//  Copyright 2026 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Submodules
pub mod swaps;
pub mod swap_onramp;
pub mod swap_offramp;
pub mod ln_channels;
pub mod lp_ckbtc;
pub mod lp_btc;
pub mod channel_funding;
pub mod htlc_ops;
pub mod htlc_signing;
pub mod bolt3_keys;
pub mod commitment_signing;
pub mod admin;
pub mod http_outcall;

// Re-export all public items so `crate::canister_state::*` still works
pub use swaps::*;
pub use swap_onramp::*;
pub use swap_offramp::*;
pub use ln_channels::*;
pub use lp_ckbtc::*;
pub use lp_btc::*;
pub use channel_funding::*;
pub use htlc_ops::*;
pub use htlc_signing::*;
pub use bolt3_keys::*;
pub use commitment_signing::*;
pub use admin::*;
pub use http_outcall::{notify_relay_webhook, transform_webhook_response};

use crate::BtcPurpose;
use crate::btc::address::get_balance;
use crate::btc::address::get_segwit_address;
use crate::btc::address::{get_p2pkh_address, get_p2tr_key_path_only_address, get_p2wpkh_address};
use crate::error::{BtcError, CklError, ResultBtc};
use crate::helpers::execute_ledger_transfer;
use crate::htlc::HtlcManager;
use crate::ic_types::PoolAsset;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::{
    Amount, BtcAddressType, ChannelFunding, ChannelId, DEVNET_CKBTC_LEDGER,
    Funding, FundingLPArgs, FundingLPQueryArgs, GetBtcBalanceArgs, GetBtcBalancesResponse,
    HoldingsResponse, NotifyArgs, PoolWithdrawal, RegisteredState, SetBtcAddressArgs,
    SetBtcAddressMsg, SetBtcAddressResponse, WithdrawalLPArgs, WithdrawalReq,
};
use crate::ic_types::{
    OnrampRequestInfo, OfframpRequestInfo,
    LnChannelInfo, LnChannelBalance,
    SwapInfo, PendingBtcDeposit,
    RateLimitInfo,
};
use crate::liquidity_pool::LiquidityPool;
use crate::receiver::ICPReceiverError;
use crate::receiver::TransactionICRCNotification;

use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

use crate::error::ResultCkl;
use crate::ic_types::{DEFAULT_CKBTC_FEE, L1Account, Params, State, Timestamp};
use crate::receiver;
use crate::require;
use candid::{CandidType, Deserialize, Nat, Principal};
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::ic_types::RelayRegistration;

/// Check that the caller is the registered relay.
/// Returns Ok(()) if authorized, Err(String) with descriptive error otherwise.
pub fn assert_relay_caller() -> Result<(), String> {
    let caller = msg_caller();
    let state = STATE.read().expect("STATE lock: assert_relay_caller");
    match &state.registered_relay {
        Some(relay) if relay.principal == caller => Ok(()),
        Some(_) => Err("Unauthorized: caller is not the registered relay".to_string()),
        None => Err("Unauthorized: no relay is registered".to_string()),
    }
}

#[cfg(not(test))]
lazy_static! {
    pub(crate) static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal")
            ),
            canister_self(),
        ));
}

#[cfg(test)]
lazy_static! {
    pub(crate) static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new_for_test(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal")
            ),
        ));
}

pub struct CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    pub(crate) principal: Principal,

    // Per-user LP BTC deposit addresses (LiquidityPoolUser derivation)
    pub(crate) btc_liquidity_addresses: HashMap<Principal, String>,

    // Personal depositor BTC addresses (LiquidityDepositor derivation)
    pub(crate) btc_depositor_addresses: HashMap<Principal, String>,

    // SINGLE global invoice deposit address
    pub(crate) btc_invoice_address: Option<String>,

    // SINGLE shared LP BTC address (for Option C)
    pub(crate) lp_btc_address: Option<String>,

    // Pending BTC deposits awaiting confirmation (txid -> PendingBtcDeposit)
    pub(crate) pending_btc_deposits: HashMap<[u8; 32], PendingBtcDeposit>,

    // Processed UTXOs to avoid double-crediting (txid:vout -> depositor)
    pub(crate) processed_utxos: HashMap<(Vec<u8>, u32), Principal>,

    pub(crate) icrc_receiver: receiver::Receiver<Q>,
    pub(crate) user_holdings: HashMap<Funding, Amount>,
    pub(crate) channels: HashMap<ChannelId, RegisteredState>,
    pub(crate) liq_pool: LiquidityPool,

    // Lightning → ckBTC swaps storage (payment_hash -> SwapInfo)
    pub(crate) swaps: HashMap<[u8; 32], SwapInfo>,

    // Lightning channel funding verification (channel_id -> LnChannelInfo)
    pub(crate) ln_channels: HashMap<[u8; 32], LnChannelInfo>,

    // Onramp invoice requests (request_id -> OnrampRequestInfo)
    pub(crate) onramp_requests: HashMap<String, OnrampRequestInfo>,

    // Offramp requests (request_id -> OfframpRequestInfo)
    pub(crate) offramp_requests: HashMap<String, OfframpRequestInfo>,

    // ==========================================================================
    // LP Liquidity Tracking (Canister-Controlled BTC for Lightning)
    // ==========================================================================

    // Channel balance tracking (channel_id -> LnChannelBalance)
    pub(crate) channel_balances: HashMap<[u8; 32], LnChannelBalance>,

    // LP BTC statistics
    pub(crate) total_btc_deposited: u64,      // Lifetime total deposited by LP providers
    pub(crate) total_btc_in_channels: u64,    // Total BTC currently locked in channels

    // UTXOs reserved for pending channel opens (txid:vout -> channel_id)
    pub(crate) reserved_utxos: HashMap<(Vec<u8>, u32), [u8; 32]>,

    // HTLC state management
    pub(crate) htlc_manager: HtlcManager,

    // ==========================================================================
    // Channel Secrets (Phase 2: Full channel control by canister)
    // ==========================================================================

    // Per-channel secrets for HTLC signing (channel_id -> secrets)
    pub(crate) channel_secrets: HashMap<[u8; 32], ChannelSecretsInternal>,

    // Counterparty funding pubkey per channel (channel_keys_id -> 33-byte pubkey)
    pub(crate) channel_counterparty_pubkeys: HashMap<[u8; 32], Vec<u8>>,

    // HTLC transaction details for signing (payment_hash -> details)
    pub(crate) htlc_tx_details: HashMap<[u8; 32], HtlcTxDetails>,

    // ==========================================================================
    // Test Configuration (for E2E testing only)
    // ==========================================================================

    // Override timeout values for testing (None = use defaults)
    pub(crate) test_onramp_timeout_ns: Option<u64>,
    pub(crate) test_offramp_timeout_ns: Option<u64>,

    // ==========================================================================
    // Relay Registration (for invoice verification)
    // ==========================================================================

    // Registered relay info (node pubkey for invoice verification)
    pub(crate) registered_relay: Option<RelayRegistration>,

    // ==========================================================================
    // Rate Limiting
    // ==========================================================================

    // Rate limit tracking for onramp requests (principal -> RateLimitInfo)
    pub(crate) onramp_rate_limits: HashMap<Principal, RateLimitInfo>,

    // Rate limit tracking for offramp requests (principal -> RateLimitInfo)
    pub(crate) offramp_rate_limits: HashMap<Principal, RateLimitInfo>,

    // ==========================================================================
    // StableSwap AMM Configuration
    // ==========================================================================

    // StableSwap config (amplification, fees)
    pub(crate) stableswap_config: crate::stableswap::StableSwapConfig,

    // Accumulated protocol fees in satoshis (ckBTC side)
    pub(crate) protocol_fees_ckbtc: u64,

    // Admin principal (can update config, withdraw protocol fees)
    pub(crate) admin: Option<Principal>,

    // Configurable ICP anti-DDoS fee (in e8s). Default: 100_000_000 (1 ICP)
    pub(crate) icp_ddos_fee_e8s: u64,

    // Funded channel addresses (idempotency guard for fund_channel)
    pub(crate) funded_channels: HashSet<String>,

    // Two-phase channel funding: reservations pending confirmation
    // Keyed by funding address. Tracks amount reserved until channel_funded or cancel.
    pub(crate) channel_funding_reservations: HashMap<String, ChannelFundingReservation>,
}

/// Tracks a pending channel funding between fund_channel (TX signed) and
/// channel_funded (TX confirmed). LP balances are only deducted on confirmation.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChannelFundingReservation {
    pub amount_sat: u64,
    pub created_at: u64,
    pub funding_address: String,
}

/// Internal representation of channel secrets (not exposed via Candid)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChannelSecretsInternal {
    pub htlc_base_secret: [u8; 32],
    pub revocation_base_secret: [u8; 32],
    pub delayed_payment_base_secret: [u8; 32],
    pub payment_secret: [u8; 32],
    pub commitment_seed: [u8; 32],
}

/// Transaction details needed to sign an HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HtlcTxDetails {
    pub channel_id: [u8; 32],
    pub htlc_outpoint_txid: [u8; 32],
    pub htlc_outpoint_vout: u32,
    pub htlc_amount_sat: u64,
    pub receiver_address: String,
    pub sender_address: String,
    pub per_commitment_point: Vec<u8>,
    pub witness_script: Vec<u8>,
}

pub async fn set_btc_liquidity_address_impl() -> Result<SetLiquidityBtcAddressResponse, BtcError> {
    let depositor = msg_caller(); // IC principal of the caller

    // First check state (personal depositor addresses)
    {
        let state = STATE.read().expect("STATE lock: set_btc_liquidity_address read");
        if let Some(addr) = state.btc_depositor_addresses.get(&depositor) {
            return Ok(SetLiquidityBtcAddressResponse {
                address: addr.clone(),
                already_existed: true,
            });
        }
    }

    // Derive new SegWit address for this depositor (personal address)
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // Store in state (personal depositor addresses)
    {
        let mut state = STATE.write().expect("STATE lock: set_btc_liquidity_address write");
        state
            .btc_depositor_addresses
            .insert(depositor, address.clone());
    }

    Ok(SetLiquidityBtcAddressResponse {
        address,
        already_existed: false,
    })
}

pub async fn set_btc_address_impl(
    set_btc_address_args: SetBtcAddressArgs,
) -> Result<SetBtcAddressResponse, BtcError> {
    let mut state = STATE.write().expect("STATE lock: set_btc_address");
    let address_type = set_btc_address_args.address_type;
    let principal = msg_caller();

    match set_btc_address_args.principal {
        Some(p) if p == principal => {}
        Some(_) => return Err(BtcError::Other("Principal mismatch: caller does not match request principal".into())),
        None => return Err(BtcError::Other("Principal is required".into())),
    }

    // Check if address for this type exists (personal depositor addresses)
    if let Some(address) = state.btc_depositor_addresses.get(&principal) {
        return Ok(SetBtcAddressResponse {
            address: address.clone(),
            msg: SetBtcAddressMsg::BtcAddressAlreadySetSingle(address_type),
        });
    }

    // If not, retrieve address for the given type by calling the matching async fn
    let address = match address_type {
        BtcAddressType::P2PKH => get_p2pkh_address().await?,
        BtcAddressType::P2WPKH => get_p2wpkh_address().await?,
        BtcAddressType::P2TR => get_p2tr_key_path_only_address().await?,
    };

    // Store in the map (personal depositor addresses)
    state
        .btc_depositor_addresses
        .insert(principal.clone(), address.clone());

    Ok(SetBtcAddressResponse {
        address,
        msg: SetBtcAddressMsg::BtcAddressSetNowSingle(address_type),
    })
}

pub async fn get_btc_balances_impl(
    confirmations: Option<u64>,
) -> Result<GetBtcBalancesResponse, BtcError> {
    let state = STATE.read().expect("STATE lock: get_btc_balances");

    let mut balances: HashMap<Principal, Option<u64>> = HashMap::new();
    let mut any_address_set = false;

    for (address_type, address) in &state.btc_depositor_addresses {
        any_address_set = true;

        // Construct GetBtcBalanceArgs with actual address string, not address_type
        let args = GetBtcBalanceArgs {
            address: address.clone(),
            confirmations, // pass on confirmation filter if any
        };

        // Query balance asynchronously, handle errors gracefully
        let balance = match get_balance(args).await {
            Ok(bal) => Some(bal),
            Err(_) => None, // optionally log or process error
        };

        balances.insert(*address_type, balance);
    }

    let msg = if any_address_set {
        SetBtcAddressMsg::BtcAddressesAvailable
    } else {
        SetBtcAddressMsg::BtcAddressNotSet
    };

    Ok(GetBtcBalancesResponse { balances, msg })
}

pub async fn get_ln_address_impl() -> Result<String, BtcError> {
    // Check global cache first
    {
        let state = STATE.read().expect("STATE lock: get_ln_address read");
        if let Some(addr) = state.btc_invoice_address.as_ref() {
            return Ok(addr.clone());
        }
    }

    // Derive SINGLE invoice deposit address
    let purpose = BtcPurpose::LnInvoiceDeposit;
    let address = get_segwit_address(purpose).await?;

    // Store globally
    {
        let mut state = STATE.write().expect("STATE lock: get_ln_address write");
        state.btc_invoice_address = Some(address.clone());
    }

    Ok(address)
}

pub async fn get_btc_liquidity_address_for_caller_impl() -> std::result::Result<String, BtcError> {
    let depositor = msg_caller();

    // 1. Fast path: return existing personal address if present
    {
        let state = STATE.read().expect("STATE lock: get_btc_liquidity_address_for_caller read");
        if let Some(addr) = state.btc_depositor_addresses.get(&depositor) {
            return Ok(addr.clone());
        }
    }

    // 2. Derive new SegWit address for this depositor (personal address)
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // 3. Store in state and return (personal depositor addresses)
    {
        let mut state = STATE.write().expect("STATE lock: get_btc_liquidity_address_for_caller write");
        state
            .btc_depositor_addresses
            .insert(depositor, address.clone());
    }

    Ok(address)
}

pub async fn transaction_notification_impl(
    notify_args: NotifyArgs,
) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
    let mut state = STATE.write().expect("STATE lock: transaction_notification");
    state
        .process_icrc_tx(
            notify_args.block_height,
            notify_args.amount,
            notify_args.funding,
        )
        .await
}

pub fn query_user_lp_holdings_impl(
    funding: FundingLPQueryArgs,
) -> std::result::Result<HoldingsResponse, CklError> {
    let state = STATE.read().expect("STATE lock: query_user_lp_holdings");
    state.query_holdings(funding)
}

pub async fn withdraw_lp_impl(
    withdrawal: WithdrawalLPArgs,
    sig_withdrawal: Vec<u8>,
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().expect("STATE lock: withdraw_lp");
    let pr_caller = msg_caller();
    let receiver = withdrawal.pool_withdrawal.depositor.0;

    // compare pr_caller and receiver, give error if unequal
    if pr_caller != receiver {
        return Err(CklError::UnauthorizedCaller);
    }

    let pool_withdrawal = withdrawal.pool_withdrawal;

    state
        .withdraw_icrc(blocktime(), receiver, pool_withdrawal, &sig_withdrawal)
        .await
}

pub async fn trigger_withdraw_impl(req: WithdrawalReq) -> std::result::Result<Nat, CklError> {
    let mut state = STATE.write().expect("STATE lock: trigger_withdraw");
    state.withdraw_from_liq_pool(req).await
}

pub fn deposit_channel_impl(
    funding: ChannelFunding,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().expect("STATE lock: deposit_channel");
    state.deposit_icrc(blocktime(), Funding::Channel(funding), signature_bytes)
}

pub fn deposit_lp_impl(
    funding: FundingLPArgs,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().expect("STATE lock: deposit_lp");

    let pool_funding = funding.pool_funding;

    state.deposit_icrc(blocktime(), Funding::Pool(pool_funding), signature_bytes)
}

pub fn query_state_impl(id: ChannelId) -> Option<RegisteredState> {
    let state = STATE.read().expect("STATE lock: query_state");
    state.state(&id)
}

impl<Q> CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    /// Test-only constructor that doesn't call canister_self() (which panics outside IC runtime).
    #[cfg(test)]
    pub fn new_for_test(q: Q) -> Self {
        let dummy_principal = Principal::anonymous();
        Self {
            principal: dummy_principal,
            btc_liquidity_addresses: HashMap::new(),
            btc_depositor_addresses: HashMap::new(),
            btc_invoice_address: None,
            lp_btc_address: None,
            pending_btc_deposits: HashMap::new(),
            processed_utxos: HashMap::new(),
            icrc_receiver: receiver::Receiver::new(q, dummy_principal),
            user_holdings: Default::default(),
            channels: Default::default(),
            liq_pool: LiquidityPool::new(),
            swaps: HashMap::new(),
            ln_channels: HashMap::new(),
            onramp_requests: HashMap::new(),
            offramp_requests: HashMap::new(),
            channel_balances: HashMap::new(),
            total_btc_deposited: 0,
            total_btc_in_channels: 0,
            reserved_utxos: HashMap::new(),
            htlc_manager: HtlcManager::new(),
            channel_secrets: HashMap::new(),
            channel_counterparty_pubkeys: HashMap::new(),
            htlc_tx_details: HashMap::new(),
            test_onramp_timeout_ns: None,
            test_offramp_timeout_ns: None,
            registered_relay: None,
            onramp_rate_limits: HashMap::new(),
            offramp_rate_limits: HashMap::new(),
            stableswap_config: crate::stableswap::StableSwapConfig {
                amplification: 200,
                fee_bps: 10,
                protocol_fee_share_bps: 5000,
                max_slippage_bps: 500,
                imbalance_fee_bps: 100,
                rebate_bps: 0,
                max_swap_pct_bps: 0,
            },
            protocol_fees_ckbtc: 0,
            admin: None,
            icp_ddos_fee_e8s: 100_000_000, // 1 ICP default
            funded_channels: HashSet::new(),
            channel_funding_reservations: HashMap::new(),
        }
    }

    pub fn new(q: Q, my_principal: Principal) -> Self {
        assert!(my_principal == canister_self());

        Self {
            principal: canister_self(),
            btc_liquidity_addresses: HashMap::new(), // per-user LP deposit addresses
            btc_depositor_addresses: HashMap::new(), // personal depositor addresses
            btc_invoice_address: None,               // single global invoice address
            lp_btc_address: None,                    // single shared LP BTC address
            pending_btc_deposits: HashMap::new(),    // pending BTC deposits
            processed_utxos: HashMap::new(),         // processed UTXOs to avoid double-crediting
            icrc_receiver: receiver::Receiver::new(q, my_principal),
            user_holdings: Default::default(),
            channels: Default::default(),
            liq_pool: LiquidityPool::new(),
            swaps: HashMap::new(),           // Lightning → ckBTC swaps
            ln_channels: HashMap::new(),     // Lightning channel funding verification
            onramp_requests: HashMap::new(), // Onramp invoice requests
            offramp_requests: HashMap::new(), // Offramp requests (ckBTC → Lightning)
            // LP Liquidity tracking
            channel_balances: HashMap::new(),
            total_btc_deposited: 0,
            total_btc_in_channels: 0,
            reserved_utxos: HashMap::new(),
            // HTLC state management
            htlc_manager: HtlcManager::new(),
            // Channel secrets (Phase 2)
            channel_secrets: HashMap::new(),
            channel_counterparty_pubkeys: HashMap::new(),
            htlc_tx_details: HashMap::new(),
            // Test configuration
            test_onramp_timeout_ns: None,
            test_offramp_timeout_ns: None,
            // Relay registration
            registered_relay: None,
            // Rate limiting
            onramp_rate_limits: HashMap::new(),
            offramp_rate_limits: HashMap::new(),
            // StableSwap AMM
            stableswap_config: crate::stableswap::StableSwapConfig {
                amplification: 200,
                fee_bps: 10,
                protocol_fee_share_bps: 5000,
                max_slippage_bps: 500,    // 5% — reject swaps with extreme price impact
                imbalance_fee_bps: 100,   // 1% at full imbalance (10x base fee)
                rebate_bps: 0,            // disabled by default
                max_swap_pct_bps: 0,      // disabled by default
            },
            protocol_fees_ckbtc: 0,
            admin: None,
            icp_ddos_fee_e8s: 100_000_000, // 1 ICP default
            funded_channels: HashSet::new(),
            channel_funding_reservations: HashMap::new(),
        }
    }

    pub fn deposit_channel(&mut self, funding: Funding, amount: Amount) -> ResultCkl<()> {
        *self
            .user_holdings
            .entry(funding)
            .or_insert(Default::default()) += amount;
        Ok(())
    }

    pub async fn withdraw_icrc(
        &mut self,
        _time: Timestamp,
        receiver: Principal,
        withdrawal: PoolWithdrawal,
        _signature_bytes: &[u8],
    ) -> ResultCkl<()> {
        let PoolWithdrawal {
            asset,
            pubkey_l1,
            depositor,
            amount,
        } = &withdrawal;

        // Extract Principal from L1Account
        let depositor_principal = depositor.0;

        // Use the simplified LP withdraw method
        self.liq_pool.withdraw(depositor_principal, asset.clone(), amount.clone())?;

        // Send funds back to L1 address
        let _ = self
            .send_funds_to_l1(receiver, &pubkey_l1, amount.clone(), &asset)
            .await;

        Ok(())
    }
    async fn get_btc_address(&self, address_type: BtcAddressType) -> ResultBtc<String> {
        let result = match address_type {
            BtcAddressType::P2PKH => get_p2pkh_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2PKH error: {}", e))),
            BtcAddressType::P2WPKH => get_p2wpkh_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2WPKH error: {}", e))),
            BtcAddressType::P2TR => get_p2tr_key_path_only_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2TR error: {}", e))),
        };

        result
    }

    async fn send_funds_to_l1(
        &self,
        receiver: Principal,
        _pubkey: &Vec<u8>,
        amount: Amount,
        _asset: &PoolAsset,
    ) -> ResultCkl<()> {
        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: receiver,
                subaccount: None,
            },
            amount: Nat(amount.clone().0),
            fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
            memo: None,
            created_at_time: Some(ic_cdk::api::time()),
        };

        let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

        let call_result: CallResult<(
            std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
        )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

        match call_result {
            Ok((inner_result,)) => match inner_result {
                Ok(_block_height) => Ok(()),
                Err(_e) => Err(CklError::LedgerError),
            },
            Err((_code, _msg)) => Err(CklError::LedgerError),
        }
    }

    // Correct usage:
    pub fn withdraw_channel(&mut self, _funding: Funding, _amount: Amount) -> ResultCkl<()> {
        // TODO: withdrawal logic as part of the L2 Lightning protocol

        return Ok(());
    }

    pub fn deposit_liq_pool(
        &mut self,
        amount: Amount,
        asset: PoolAsset,
        depositor: L1Account,
        _pubkey_bytes: Vec<u8>,
        _funding: &Funding,
        _signature_bytes: &[u8],
    ) -> ResultCkl<()> {
        // Extract Principal from L1Account and use simplified LP deposit
        let depositor_principal = depositor.0;
        self.liq_pool.deposit(depositor_principal, asset, amount);
        Ok(())
    }
    pub fn deposit_icrc(
        &mut self,
        _time: Timestamp,
        funding: Funding,
        signature_bytes: &[u8], // added signature argument
    ) -> ResultCkl<()> {
        let memo = funding.memo();
        // Drain the receiver for the amount associated with this memo.
        let amount = self.icrc_receiver.drain(memo);

        match &funding {
            Funding::Channel(_) => {
                self.deposit_channel(funding.clone(), amount)?;
            }
            Funding::Pool(_) => {
                let depositor = funding.get_depositor().unwrap().clone();
                let pool_asset = funding.get_asset().unwrap().clone();
                let pubkey = funding.get_pubkey().unwrap().clone();

                // New call, now passing funding reference and signature bytes
                self.deposit_liq_pool(
                    amount,
                    pool_asset,
                    depositor,
                    pubkey,
                    &funding,        // pass reference for verification
                    signature_bytes, // pass signature bytes for verification
                )?;
            }
        }
        Ok(())
    }

    // Optionally handle events if needed
    pub async fn process_icrc_tx(
        &mut self,
        tx: receiver::BlockHeight,
        amount: u64,
        funding: Funding,
    ) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
        self.icrc_receiver.verify_icrc(tx, amount, funding).await
    }

    pub fn query_holdings(
        &self,
        funding: FundingLPQueryArgs,
    ) -> std::result::Result<HoldingsResponse, CklError> {
        let l1_account_principal = funding.funding_query.address.clone();
        let caller_principal = msg_caller();

        // Verify caller matches the requested principal
        if l1_account_principal.0 != caller_principal {
            return Err(CklError::UnauthorizedCaller);
        }

        // Extract Principal from L1Account and look up balance
        let depositor_principal = l1_account_principal.0;
        let depositor_balance = self
            .liq_pool
            .depositors
            .get(&depositor_principal)
            .ok_or(CklError::NoHoldingsFound)?;

        Ok(HoldingsResponse {
            ckbtc_amount: depositor_balance.ckbtc_amount.clone(),
            btc_amount: depositor_balance.btc_amount.clone(),
        })
    }

    pub fn query_liq_holdings(&self, asset: PoolAsset) -> Option<Amount> {
        self.liq_pool.holdings_total.get(&asset).cloned()
    }

    /// Queries a registered state.
    pub fn state(&self, id: &ChannelId) -> Option<RegisteredState> {
        self.channels.get(&id).cloned()
    }

    /// Updates the holdings associated with a channel to the outcome of the
    /// supplied state, then registers the state. If the state is the channel's
    /// initial state, the holdings are not updated, as initial states are
    /// allowed to be under-funded and are otherwise expected to match the
    /// deposit distribution exactly if fully funded.
    fn register_channel(&mut self, params: &Params, state: RegisteredState) -> ResultCkl<()> {
        let total = &self.holdings_total(&params);
        if total < &state.state.total() {
            require!(
                state.state.may_be_underfunded(),
                CklError::InsufficientFunding
            );
        } else {
            self.update_channel_holdings(&params, &state.state);
        }

        self.channels.insert(state.state.channel.clone(), state);
        Ok(())
    }

    /// Pushes a state's funding allocation into the channel's holdings mapping
    /// in the canister.
    fn update_channel_holdings(&mut self, params: &Params, state: &State) {
        for (i, outcome) in state.allocation.iter().enumerate() {
            self.user_holdings.insert(
                Funding::new_channel(state.channel.clone(), params.participants[i].clone()),
                outcome.clone(),
            );
        }
    }

    /// Calculates the total funds held in a channel. If the channel is unknown
    /// and there are no deposited funds for the channel, returns 0.
    pub fn holdings_total(&self, params: &Params) -> Amount {
        let mut acc = Amount::default();
        for pk in params.participants.iter() {
            let funding = Funding::new_channel(params.id(), pk.clone());
            acc += self
                .user_holdings
                .get(&funding)
                .unwrap_or(&Amount::default())
                .clone();
        }
        acc
    }

    pub async fn withdraw_from_liq_pool(
        &mut self,
        req: WithdrawalReq,
    ) -> std::result::Result<Nat, CklError> {
        let amount = req.amount.clone();

        let (total_deducted, to_deduct) = match self.calculate_required_deductions(&amount) {
            Ok(res) => res,
            Err(_) => {
                return Err(CklError::InsufficientLiquidity);
            }
        };

        let transfer_result = execute_ledger_transfer(&req, total_deducted).await;

        match transfer_result {
            Ok(block_height) => {
                self.apply_deductions(to_deduct);
                Ok(block_height)
            }
            Err(error_msg) => Err(error_msg),
        }
    }

    fn calculate_required_deductions(
        &self,
        amount: &Nat,
    ) -> std::result::Result<(u64, Vec<(Funding, Nat)>), CklError> {
        let mut needed = amount.clone();
        let mut to_deduct = Vec::new();
        let zero = Nat::from(0u32);

        for (acc, available) in &self.user_holdings {
            if needed == zero {
                break;
            }

            let take = available.min(&needed);
            if *take > zero {
                to_deduct.push((acc.clone(), take.clone()));
                needed -= take.clone();
            }
        }

        if needed > zero {
            return Err(CklError::InsufficientLiquidity);
        }

        let total = amount.clone() - needed;
        let total_u64 = total.0.to_u64_digits().first().copied().unwrap_or(0);
        Ok((total_u64, to_deduct))
    }

    pub fn finalize_withdrawal(&mut self, to_deduct: Vec<(Funding, Nat)>) {
        self.apply_deductions(to_deduct);
    }

    fn apply_deductions(&mut self, to_deduct: Vec<(Funding, Nat)>) {
        let zero = Nat(0u64.into());

        for (acc, take) in to_deduct {
            if let Some(entry) = self.user_holdings.get_mut(&acc) {
                *entry -= take;
                if *entry == zero {
                    self.user_holdings.remove(&acc);
                }
            }
        }
    }

    /// Serialize all persistable state into a snapshot for stable memory.
    pub fn to_snapshot(&self) -> CanisterStateSnapshot {
        // Sort all HashMap-derived Vecs for deterministic serialization.
        // This ensures identical state produces identical snapshot bytes
        // regardless of HashMap iteration order.
        let mut btc_liquidity_addresses: Vec<_> = self.btc_liquidity_addresses.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        btc_liquidity_addresses.sort_by_key(|(k, _)| *k);

        let mut btc_depositor_addresses: Vec<_> = self.btc_depositor_addresses.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        btc_depositor_addresses.sort_by_key(|(k, _)| *k);

        let mut pending_btc_deposits: Vec<_> = self.pending_btc_deposits.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        pending_btc_deposits.sort_by_key(|(k, _)| *k);

        let mut processed_utxos: Vec<_> = self.processed_utxos.iter()
            .map(|((txid, vout), p)| (txid.clone(), *vout, *p)).collect();
        processed_utxos.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

        let mut user_holdings: Vec<_> = self.user_holdings.iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        user_holdings.sort_by(|a, b| format!("{:?}", a.0).cmp(&format!("{:?}", b.0)));

        let mut channels: Vec<_> = self.channels.iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        channels.sort_by_key(|(k, _)| k.clone());

        let mut swaps: Vec<_> = self.swaps.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        swaps.sort_by_key(|(k, _)| *k);

        let mut ln_channels: Vec<_> = self.ln_channels.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        ln_channels.sort_by_key(|(k, _)| *k);

        let mut onramp_requests: Vec<_> = self.onramp_requests.iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        onramp_requests.sort_by_key(|(k, _)| k.clone());

        let mut offramp_requests: Vec<_> = self.offramp_requests.iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        offramp_requests.sort_by_key(|(k, _)| k.clone());

        let mut channel_balances: Vec<_> = self.channel_balances.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        channel_balances.sort_by_key(|(k, _)| *k);

        let mut reserved_utxos: Vec<_> = self.reserved_utxos.iter()
            .map(|((txid, vout), ch)| (txid.clone(), *vout, *ch)).collect();
        reserved_utxos.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

        let mut channel_secrets: Vec<_> = self.channel_secrets.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        channel_secrets.sort_by_key(|(k, _)| *k);

        let mut channel_counterparty_pubkeys: Vec<_> = self.channel_counterparty_pubkeys.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        channel_counterparty_pubkeys.sort_by_key(|(k, _)| *k);

        let mut htlc_tx_details: Vec<_> = self.htlc_tx_details.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        htlc_tx_details.sort_by_key(|(k, _)| *k);

        let mut onramp_rate_limits: Vec<_> = self.onramp_rate_limits.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        onramp_rate_limits.sort_by_key(|(k, _)| *k);

        let mut offramp_rate_limits: Vec<_> = self.offramp_rate_limits.iter()
            .map(|(k, v)| (*k, v.clone())).collect();
        offramp_rate_limits.sort_by_key(|(k, _)| *k);

        let mut funded_channels: Vec<String> = self.funded_channels.iter().cloned().collect();
        funded_channels.sort();

        let mut channel_funding_reservations: Vec<_> = self.channel_funding_reservations.iter()
            .map(|(k, v)| (k.clone(), v.clone())).collect();
        channel_funding_reservations.sort_by_key(|(k, _)| k.clone());

        CanisterStateSnapshot {
            version: 1,
            principal: self.principal,
            btc_liquidity_addresses,
            btc_depositor_addresses: Some(btc_depositor_addresses),
            btc_invoice_address: self.btc_invoice_address.clone(),
            lp_btc_address: self.lp_btc_address.clone(),
            pending_btc_deposits,
            processed_utxos,
            user_holdings,
            channels,
            liq_pool: self.liq_pool.clone(),
            swaps,
            ln_channels,
            onramp_requests,
            offramp_requests,
            channel_balances,
            total_btc_deposited: self.total_btc_deposited,
            total_btc_in_channels: self.total_btc_in_channels,
            reserved_utxos,
            htlc_manager: self.htlc_manager.clone(),
            channel_secrets,
            channel_counterparty_pubkeys,
            htlc_tx_details,
            registered_relay: self.registered_relay.clone(),
            onramp_rate_limits,
            offramp_rate_limits,
            stableswap_config: self.stableswap_config.clone(),
            protocol_fees_ckbtc: self.protocol_fees_ckbtc,
            admin: self.admin,
            icp_ddos_fee_e8s: self.icp_ddos_fee_e8s,
            funded_channels,
            channel_funding_reservations,
        }
    }

    /// Restore state from a deserialized snapshot.
    ///
    /// Note: `icrc_receiver` is NOT restored (it's rebuilt from constructor).
    /// Any in-flight ICRC deposits must be re-submitted after upgrade.
    pub fn restore_from_snapshot(&mut self, snap: CanisterStateSnapshot) {
        if snap.version != 1 {
            ic_cdk::trap(&format!(
                "Unsupported snapshot version: {} (expected 1)",
                snap.version
            ));
        }
        self.principal = snap.principal;
        self.btc_liquidity_addresses = snap.btc_liquidity_addresses.into_iter().collect();
        self.btc_depositor_addresses = snap.btc_depositor_addresses.unwrap_or_default().into_iter().collect();
        self.btc_invoice_address = snap.btc_invoice_address;
        self.lp_btc_address = snap.lp_btc_address;
        self.pending_btc_deposits = snap.pending_btc_deposits.into_iter().collect();
        self.processed_utxos = snap.processed_utxos.into_iter()
            .map(|(txid, vout, p)| ((txid, vout), p)).collect();
        self.user_holdings = snap.user_holdings.into_iter().collect();
        self.channels = snap.channels.into_iter().collect();
        self.liq_pool = snap.liq_pool;
        self.swaps = snap.swaps.into_iter().collect();
        self.ln_channels = snap.ln_channels.into_iter().collect();
        self.onramp_requests = snap.onramp_requests.into_iter().collect();
        self.offramp_requests = snap.offramp_requests.into_iter().collect();
        self.channel_balances = snap.channel_balances.into_iter().collect();
        self.total_btc_deposited = snap.total_btc_deposited;
        self.total_btc_in_channels = snap.total_btc_in_channels;
        self.reserved_utxos = snap.reserved_utxos.into_iter()
            .map(|(txid, vout, ch)| ((txid, vout), ch)).collect();
        self.htlc_manager = snap.htlc_manager;
        self.channel_secrets = snap.channel_secrets.into_iter().collect();
        self.channel_counterparty_pubkeys = snap.channel_counterparty_pubkeys.into_iter().collect();
        self.htlc_tx_details = snap.htlc_tx_details.into_iter().collect();
        self.registered_relay = snap.registered_relay;
        self.onramp_rate_limits = snap.onramp_rate_limits.into_iter().collect();
        self.offramp_rate_limits = snap.offramp_rate_limits.into_iter().collect();
        self.stableswap_config = snap.stableswap_config;
        self.protocol_fees_ckbtc = snap.protocol_fees_ckbtc;
        self.admin = snap.admin;
        self.icp_ddos_fee_e8s = snap.icp_ddos_fee_e8s;
        self.funded_channels = snap.funded_channels.into_iter().collect();
        self.channel_funding_reservations = snap.channel_funding_reservations.into_iter().collect();
    }
}

// =============================================================================
// Canister State Snapshot (for stable memory persistence across upgrades)
// =============================================================================

/// Serializable snapshot of all canister state for stable memory persistence.
///
/// HashMap fields are converted to Vec<(K, V)> for Candid compatibility.
/// The `icrc_receiver` and test timeout fields are intentionally excluded:
/// - `icrc_receiver` is rebuilt from principal + ledger ID on upgrade
/// - Test timeouts are only for E2E testing, not persisted
#[derive(CandidType, Deserialize)]
pub struct CanisterStateSnapshot {
    /// Schema version for forward compatibility
    pub version: u8,
    pub principal: Principal,
    pub btc_liquidity_addresses: Vec<(Principal, String)>,
    pub btc_depositor_addresses: Option<Vec<(Principal, String)>>,
    pub btc_invoice_address: Option<String>,
    pub lp_btc_address: Option<String>,
    pub pending_btc_deposits: Vec<([u8; 32], PendingBtcDeposit)>,
    /// Flattened from HashMap<(Vec<u8>, u32), Principal>
    pub processed_utxos: Vec<(Vec<u8>, u32, Principal)>,
    pub user_holdings: Vec<(Funding, Amount)>,
    pub channels: Vec<(ChannelId, RegisteredState)>,
    pub liq_pool: LiquidityPool,
    pub swaps: Vec<([u8; 32], SwapInfo)>,
    pub ln_channels: Vec<([u8; 32], LnChannelInfo)>,
    pub onramp_requests: Vec<(String, OnrampRequestInfo)>,
    pub offramp_requests: Vec<(String, OfframpRequestInfo)>,
    pub channel_balances: Vec<([u8; 32], LnChannelBalance)>,
    pub total_btc_deposited: u64,
    pub total_btc_in_channels: u64,
    /// Flattened from HashMap<(Vec<u8>, u32), [u8; 32]>
    pub reserved_utxos: Vec<(Vec<u8>, u32, [u8; 32])>,
    pub htlc_manager: HtlcManager,
    pub channel_secrets: Vec<([u8; 32], ChannelSecretsInternal)>,
    pub channel_counterparty_pubkeys: Vec<([u8; 32], Vec<u8>)>,
    pub htlc_tx_details: Vec<([u8; 32], HtlcTxDetails)>,
    pub registered_relay: Option<RelayRegistration>,
    pub onramp_rate_limits: Vec<(Principal, RateLimitInfo)>,
    pub offramp_rate_limits: Vec<(Principal, RateLimitInfo)>,
    pub stableswap_config: crate::stableswap::StableSwapConfig,
    pub protocol_fees_ckbtc: u64,
    pub admin: Option<Principal>,
    pub icp_ddos_fee_e8s: u64,
    pub funded_channels: Vec<String>,
    #[serde(default)]
    pub channel_funding_reservations: Vec<(String, ChannelFundingReservation)>,
}

#[cfg(test)]
mod snapshot_tests {
    use super::*;
    use crate::ic_types::{
        BtcOutpoint, LnChannelStatus, SwapState, DEVNET_CKBTC_LEDGER,
    };

    /// Creates a local CanisterState for testing (avoids mutating global STATE).
    fn make_test_state() -> CanisterState<crate::receiver::CanisterTXQuerier> {
        CanisterState::new_for_test(
            crate::receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal")
            ),
        )
    }

    #[test]
    fn test_snapshot_round_trip() {
        let mut state = make_test_state();

        // Populate state with representative data
        let test_principal = Principal::from_text("aaaaa-aa").unwrap();
        let test_principal_2 = Principal::from_text("2vxsx-fae").unwrap();
        state.principal = test_principal;

        // BTC addresses
        state.btc_liquidity_addresses.insert(test_principal, "bcrt1qtest123".to_string());
        state.btc_invoice_address = Some("bcrt1qinvoice".to_string());
        state.lp_btc_address = Some("bcrt1qlpaddr".to_string());

        // Pending BTC deposit
        let txid_hash = [0xAA; 32];
        state.pending_btc_deposits.insert(txid_hash, PendingBtcDeposit {
            depositor: test_principal,
            txid: vec![0xAA; 32],
            vout: 0,
            amount_sat: 50_000,
            detected_at: 1000,
            confirmations: 3,
            credited: false,
        });

        // Processed UTXOs
        state.processed_utxos.insert((vec![0xBB; 32], 1), test_principal);

        // LP deposits
        state.liq_pool.deposit(test_principal, PoolAsset::CkBTC, Nat::from(100_000u64));
        state.liq_pool.deposit(test_principal, PoolAsset::BTC, Nat::from(50_000u64));

        // Swaps
        let swap_hash = [0xCC; 32];
        state.swaps.insert(swap_hash, SwapInfo {
            payment_hash: vec![0xCC; 32],
            amount_msat: 1_000_000,
            recipient: test_principal,
            created_at: 2000,
            expiry_timestamp: 3000,
            state: SwapState::Pending,
        });

        // Lightning channels
        let ch_id = [0xDD; 32];
        state.ln_channels.insert(ch_id, LnChannelInfo {
            channel_id: vec![0xDD; 32],
            funding_outpoint: BtcOutpoint { txid: vec![0xEE; 32], vout: 0 },
            capacity_sats: 1_000_000,
            local_node_id: vec![0x02; 33],
            remote_node_id: vec![0x03; 33],
            funding_address: "bcrt1qfunding".to_string(),
            registered_at: 4000,
            last_verified_at: None,
            status: LnChannelStatus::Pending,
        });

        // Channel balances
        state.channel_balances.insert(ch_id, LnChannelBalance {
            channel_id: vec![0xDD; 32],
            capacity_sats: 1_000_000,
            our_balance_sats: 600_000,
            their_balance_sats: 400_000,
            is_active: true,
            last_updated: 5000,
        });

        // BTC tracking
        state.total_btc_deposited = 500_000;
        state.total_btc_in_channels = 200_000;

        // Reserved UTXOs
        state.reserved_utxos.insert((vec![0xFF; 32], 0), ch_id);

        // Channel secrets
        state.channel_secrets.insert(ch_id, ChannelSecretsInternal {
            htlc_base_secret: [1; 32],
            revocation_base_secret: [2; 32],
            delayed_payment_base_secret: [3; 32],
            payment_secret: [4; 32],
            commitment_seed: [5; 32],
        });

        // Counterparty pubkeys
        state.channel_counterparty_pubkeys.insert(ch_id, vec![0x02; 33]);

        // Relay registration
        state.registered_relay = Some(RelayRegistration {
            principal: test_principal_2,
            node_pubkey: vec![0x03; 33],
            registered_at: 6000,
            is_active: true,
            relay_http_url: None,
            relay_auth_token: None,
        });

        // Rate limits
        state.onramp_rate_limits.insert(test_principal, RateLimitInfo {
            request_count: 5,
            window_start: 7000,
        });

        // StableSwap config
        state.stableswap_config = crate::stableswap::StableSwapConfig {
            amplification: 300,
            fee_bps: 15,
            protocol_fee_share_bps: 4000,
            max_slippage_bps: 600,
            imbalance_fee_bps: 150,
            rebate_bps: 5,
            max_swap_pct_bps: 500,
        };
        state.protocol_fees_ckbtc = 12345;
        state.admin = Some(test_principal_2);
        state.icp_ddos_fee_e8s = 200_000_000; // 2 ICP
        state.funded_channels.insert("bcrt1qfunding".to_string());

        // Create snapshot
        let snapshot = state.to_snapshot();

        // Candid encode
        let bytes = candid::encode_one(&snapshot).expect("Candid encode failed");

        // Candid decode
        let decoded: CanisterStateSnapshot = candid::decode_one(&bytes).expect("Candid decode failed");

        // Verify snapshot fields
        assert_eq!(decoded.version, 1);
        assert_eq!(decoded.principal, test_principal);
        assert_eq!(decoded.btc_liquidity_addresses.len(), 1);
        assert_eq!(decoded.btc_invoice_address, Some("bcrt1qinvoice".to_string()));
        assert_eq!(decoded.lp_btc_address, Some("bcrt1qlpaddr".to_string()));
        assert_eq!(decoded.pending_btc_deposits.len(), 1);
        assert_eq!(decoded.processed_utxos.len(), 1);
        assert_eq!(decoded.swaps.len(), 1);
        assert_eq!(decoded.ln_channels.len(), 1);
        assert_eq!(decoded.channel_balances.len(), 1);
        assert_eq!(decoded.total_btc_deposited, 500_000);
        assert_eq!(decoded.total_btc_in_channels, 200_000);
        assert_eq!(decoded.reserved_utxos.len(), 1);
        assert_eq!(decoded.channel_secrets.len(), 1);
        assert_eq!(decoded.channel_counterparty_pubkeys.len(), 1);
        assert!(decoded.registered_relay.is_some());
        assert_eq!(decoded.onramp_rate_limits.len(), 1);
        assert_eq!(decoded.stableswap_config.amplification, 300);
        assert_eq!(decoded.stableswap_config.max_swap_pct_bps, 500);
        assert_eq!(decoded.protocol_fees_ckbtc, 12345);
        assert_eq!(decoded.admin, Some(test_principal_2));
        assert_eq!(decoded.icp_ddos_fee_e8s, 200_000_000);
        assert_eq!(decoded.funded_channels.len(), 1);

        // Restore from decoded snapshot into a fresh state
        let mut restored = make_test_state();
        restored.restore_from_snapshot(decoded);

        // Verify restoration
        assert_eq!(restored.principal, test_principal);
        assert_eq!(restored.btc_liquidity_addresses.get(&test_principal), Some(&"bcrt1qtest123".to_string()));
        assert_eq!(restored.btc_invoice_address, Some("bcrt1qinvoice".to_string()));
        assert_eq!(restored.lp_btc_address, Some("bcrt1qlpaddr".to_string()));
        assert_eq!(restored.pending_btc_deposits.len(), 1);
        assert_eq!(restored.processed_utxos.len(), 1);
        assert_eq!(restored.swaps.len(), 1);
        assert_eq!(restored.swaps[&swap_hash].amount_msat, 1_000_000);
        assert_eq!(restored.ln_channels.len(), 1);
        assert_eq!(restored.channel_balances.len(), 1);
        assert_eq!(restored.total_btc_deposited, 500_000);
        assert_eq!(restored.total_btc_in_channels, 200_000);
        assert_eq!(restored.reserved_utxos.len(), 1);
        assert_eq!(restored.channel_secrets.len(), 1);
        assert_eq!(restored.channel_secrets[&ch_id].htlc_base_secret, [1; 32]);
        assert_eq!(restored.channel_counterparty_pubkeys.len(), 1);
        assert!(restored.registered_relay.is_some());
        assert_eq!(restored.registered_relay.as_ref().unwrap().principal, test_principal_2);
        assert_eq!(restored.onramp_rate_limits.len(), 1);
        assert_eq!(restored.stableswap_config.amplification, 300);
        assert_eq!(restored.stableswap_config.max_swap_pct_bps, 500);
        assert_eq!(restored.protocol_fees_ckbtc, 12345);
        assert_eq!(restored.admin, Some(test_principal_2));
        assert_eq!(restored.icp_ddos_fee_e8s, 200_000_000);
        assert!(restored.funded_channels.contains("bcrt1qfunding"));

        // Verify LP pool survived round-trip
        assert_eq!(restored.liq_pool.get_balance(&test_principal, &PoolAsset::CkBTC), Nat::from(100_000u64));
        assert_eq!(restored.liq_pool.get_balance(&test_principal, &PoolAsset::BTC), Nat::from(50_000u64));
    }
}
