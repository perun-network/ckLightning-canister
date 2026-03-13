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
use crate::error::{BtcError, CklError};
use crate::htlc::HtlcManager;
use crate::ic_types::PoolAsset;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::{
    Amount, BtcAddressType, CKBTC_LEDGER_PRINCIPAL, DEVNET_CKBTC_LEDGER,
    FundingLPArgs, FundingLPQueryArgs, GetBtcBalanceArgs, GetBtcBalancesResponse,
    HoldingsResponse, NotifyArgs, PoolFunding, PoolWithdrawal, SetBtcAddressArgs,
    SetBtcAddressMsg, SetBtcAddressResponse, WithdrawalLPArgs,
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

use ic_cdk::call::Call;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

use crate::error::ResultCkl;
use crate::ic_types::{DEFAULT_CKBTC_FEE, L1Account, Timestamp};
use crate::receiver;
use candid::{CandidType, Deserialize, Nat, Principal};
use lazy_static::lazy_static;
use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

use crate::ic_types::RelayRegistration;

/// Check swap amount against withdrawal caps.
/// Must be called while holding STATE write lock. Returns Ok(()) or Err with reason.
pub fn check_swap_caps(state: &mut CanisterState<impl receiver::TXQuerier>, amount_sats: u64) -> Result<(), String> {
    // Per-swap cap
    if state.max_single_swap_sats > 0 && amount_sats > state.max_single_swap_sats {
        return Err(format!(
            "Swap amount {} exceeds max single swap cap of {} sats",
            amount_sats, state.max_single_swap_sats
        ));
    }

    // Hourly aggregate cap
    if state.max_hourly_swap_sats > 0 {
        let now = ic_cdk::api::time();
        const HOUR_NS: u64 = 60 * 60 * 1_000_000_000;

        // Reset window if expired
        if now.saturating_sub(state.hourly_swap_window_start) > HOUR_NS {
            state.hourly_swap_volume_sats = 0;
            state.hourly_swap_window_start = now;
        }

        if state.hourly_swap_volume_sats.saturating_add(amount_sats) > state.max_hourly_swap_sats {
            return Err(format!(
                "Hourly swap volume would exceed cap of {} sats (current: {} + requested: {})",
                state.max_hourly_swap_sats, state.hourly_swap_volume_sats, amount_sats
            ));
        }
    }

    Ok(())
}

/// Record a completed swap's volume against the hourly cap.
pub fn record_swap_volume(state: &mut CanisterState<impl receiver::TXQuerier>, amount_sats: u64) {
    if state.max_hourly_swap_sats > 0 {
        state.hourly_swap_volume_sats = state.hourly_swap_volume_sats.saturating_add(amount_sats);
    }
}

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

    // Withdrawal / swap amount caps (admin-configurable)
    // max_single_swap_sats: 0 = disabled (default)
    pub(crate) max_single_swap_sats: u64,
    // max_hourly_swap_sats: 0 = disabled (default)
    pub(crate) max_hourly_swap_sats: u64,
    // Rolling hourly swap volume tracker
    pub(crate) hourly_swap_volume_sats: u64,
    pub(crate) hourly_swap_window_start: u64,

    // Funded channel addresses (idempotency guard for fund_channel)
    pub(crate) funded_channels: HashSet<String>,

    // Two-phase channel funding: reservations pending confirmation
    // Keyed by funding address. Tracks amount reserved until channel_funded or cancel.
    pub(crate) channel_funding_reservations: HashMap<String, ChannelFundingReservation>,

    // ==========================================================================
    // WS6 Optimizations: Active request tracking
    // ==========================================================================

    // Active (non-terminal) onramp/offramp request IDs for O(1) heartbeat filtering
    pub(crate) active_onramp_ids: HashSet<String>,
    pub(crate) active_offramp_ids: HashSet<String>,

    // Running counter of ckBTC sats reserved for pending onramp requests
    // (avoids full iteration in withdraw_ckbtc_impl)
    pub(crate) reserved_ckbtc_sats: u64,
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

#[allow(clippy::await_holding_lock)] // IC canisters are single-threaded; no deadlock risk
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
        .insert(principal, address.clone());

    Ok(SetBtcAddressResponse {
        address,
        msg: SetBtcAddressMsg::BtcAddressSetNowSingle(address_type),
    })
}

#[allow(clippy::await_holding_lock)] // IC canisters are single-threaded; no deadlock risk
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
        let balance = get_balance(args).await.ok();

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

#[allow(clippy::await_holding_lock)] // IC canisters are single-threaded; no deadlock risk
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

#[allow(clippy::await_holding_lock)] // IC canisters are single-threaded; no deadlock risk
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

pub fn deposit_lp_impl(
    funding: FundingLPArgs,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().expect("STATE lock: deposit_lp");

    let pool_funding = funding.pool_funding;

    state.deposit_icrc(blocktime(), pool_funding, signature_bytes)
}

impl<Q> CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    /// Common initializer for all fields given a principal and querier.
    fn init(q: Q, principal: Principal) -> Self {
        Self {
            principal,
            btc_liquidity_addresses: HashMap::new(),
            btc_depositor_addresses: HashMap::new(),
            btc_invoice_address: None,
            lp_btc_address: None,
            pending_btc_deposits: HashMap::new(),
            processed_utxos: HashMap::new(),
            icrc_receiver: receiver::Receiver::new(q, principal),
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
            icp_ddos_fee_e8s: 100_000_000,
            max_single_swap_sats: 0,
            max_hourly_swap_sats: 0,
            hourly_swap_volume_sats: 0,
            hourly_swap_window_start: 0,
            funded_channels: HashSet::new(),
            channel_funding_reservations: HashMap::new(),
            active_onramp_ids: HashSet::new(),
            active_offramp_ids: HashSet::new(),
            reserved_ckbtc_sats: 0,
        }
    }

    /// Test-only constructor that doesn't call canister_self() (which panics outside IC runtime).
    #[cfg(test)]
    pub fn new_for_test(q: Q) -> Self {
        Self::init(q, Principal::anonymous())
    }

    pub fn new(q: Q, my_principal: Principal) -> Self {
        assert!(my_principal == canister_self());
        Self::init(q, canister_self())
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
            .send_funds_to_l1(receiver, pubkey_l1, amount.clone(), asset)
            .await;

        Ok(())
    }
    async fn send_funds_to_l1(
        &self,
        receiver: Principal,
        _pubkey: &[u8],
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
            memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:l1_transfer".to_vec())),
            created_at_time: Some(ic_cdk::api::time()),
        };

        let ckbtc_ledger_id = *CKBTC_LEDGER_PRINCIPAL;

        match Call::unbounded_wait(ckbtc_ledger_id, "icrc1_transfer")
            .with_args(&(transfer_arg,))
            .await
            .map_err(ic_cdk::call::Error::from)
            .and_then(|r| r.candid_tuple::<(std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
        {
            Ok((inner_result,)) => match inner_result {
                Ok(_block_height) => Ok(()),
                Err(_e) => Err(CklError::LedgerError),
            },
            Err(_e) => Err(CklError::LedgerError),
        }
    }

    pub fn deposit_liq_pool(
        &mut self,
        amount: Amount,
        asset: PoolAsset,
        depositor: L1Account,
    ) -> ResultCkl<()> {
        // Extract Principal from L1Account and use simplified LP deposit
        let depositor_principal = depositor.0;
        self.liq_pool.deposit(depositor_principal, asset, amount);
        Ok(())
    }
    pub fn deposit_icrc(
        &mut self,
        _time: Timestamp,
        funding: PoolFunding,
        _signature_bytes: &[u8],
    ) -> ResultCkl<()> {
        let memo = funding.memo();
        // Drain the receiver for the amount associated with this memo.
        let amount = self.icrc_receiver.drain(memo);

        let depositor = funding.get_depositor().clone();
        let pool_asset = funding.get_asset().clone();

        self.deposit_liq_pool(amount, pool_asset, depositor)?;
        Ok(())
    }

    // Optionally handle events if needed
    pub async fn process_icrc_tx(
        &mut self,
        tx: receiver::BlockHeight,
        amount: u64,
        funding: PoolFunding,
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

    /// Serialize all persistable state into a snapshot for stable memory.
    pub fn to_snapshot(&self) -> CanisterStateSnapshot {
        // Collect HashMap entries into sorted Vecs for deterministic serialization.
        // Identical state must produce identical snapshot bytes regardless of iteration order.
        macro_rules! sorted_map {
            ($map:expr) => {{
                let mut v: Vec<_> = $map.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
                v.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                v
            }};
        }

        let btc_liquidity_addresses = sorted_map!(self.btc_liquidity_addresses);
        let btc_depositor_addresses = sorted_map!(self.btc_depositor_addresses);
        let pending_btc_deposits = sorted_map!(self.pending_btc_deposits);
        let swaps = sorted_map!(self.swaps);
        let ln_channels = sorted_map!(self.ln_channels);
        let onramp_requests = sorted_map!(self.onramp_requests);
        let offramp_requests = sorted_map!(self.offramp_requests);
        let channel_balances = sorted_map!(self.channel_balances);
        let channel_secrets = sorted_map!(self.channel_secrets);
        let channel_counterparty_pubkeys = sorted_map!(self.channel_counterparty_pubkeys);
        let htlc_tx_details = sorted_map!(self.htlc_tx_details);
        let onramp_rate_limits = sorted_map!(self.onramp_rate_limits);
        let offramp_rate_limits = sorted_map!(self.offramp_rate_limits);
        let channel_funding_reservations = sorted_map!(self.channel_funding_reservations);

        let mut processed_utxos: Vec<_> = self.processed_utxos.iter()
            .map(|((txid, vout), p)| (txid.clone(), *vout, *p)).collect();
        processed_utxos.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

        let mut reserved_utxos: Vec<_> = self.reserved_utxos.iter()
            .map(|((txid, vout), ch)| (txid.clone(), *vout, *ch)).collect();
        reserved_utxos.sort_by(|a, b| (&a.0, a.1).cmp(&(&b.0, b.1)));

        let mut funded_channels: Vec<String> = self.funded_channels.iter().cloned().collect();
        funded_channels.sort();

        // known_txs from Receiver (already sorted since BTreeSet)
        let known_txs: Vec<u64> = self.icrc_receiver.get_known_txs().into_iter().collect();

        CanisterStateSnapshot {
            version: 1,
            principal: self.principal,
            btc_liquidity_addresses,
            btc_depositor_addresses: Some(btc_depositor_addresses),
            btc_invoice_address: self.btc_invoice_address.clone(),
            lp_btc_address: self.lp_btc_address.clone(),
            pending_btc_deposits,
            processed_utxos,
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
            max_single_swap_sats: self.max_single_swap_sats,
            max_hourly_swap_sats: self.max_hourly_swap_sats,
            funded_channels,
            channel_funding_reservations,
            known_txs,
            active_onramp_ids: {
                let mut ids: Vec<String> = self.active_onramp_ids.iter().cloned().collect();
                ids.sort();
                ids
            },
            active_offramp_ids: {
                let mut ids: Vec<String> = self.active_offramp_ids.iter().cloned().collect();
                ids.sort();
                ids
            },
            reserved_ckbtc_sats: self.reserved_ckbtc_sats,
        }
    }

    /// Restore state from a deserialized snapshot.
    ///
    /// Note: `icrc_receiver` is NOT restored (it's rebuilt from constructor).
    /// Any in-flight ICRC deposits must be re-submitted after upgrade.
    pub fn restore_from_snapshot(&mut self, snap: CanisterStateSnapshot) {
        if snap.version != 1 {
            ic_cdk::trap(format!(
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
        self.max_single_swap_sats = snap.max_single_swap_sats;
        self.max_hourly_swap_sats = snap.max_hourly_swap_sats;
        self.funded_channels = snap.funded_channels.into_iter().collect();
        self.channel_funding_reservations = snap.channel_funding_reservations.into_iter().collect();
        // Restore known_txs into icrc_receiver to prevent double-crediting after upgrade
        self.icrc_receiver.set_known_txs(snap.known_txs.into_iter().collect());
        self.active_onramp_ids = snap.active_onramp_ids.into_iter().collect();
        self.active_offramp_ids = snap.active_offramp_ids.into_iter().collect();
        self.reserved_ckbtc_sats = snap.reserved_ckbtc_sats;
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
    #[serde(default)]
    pub max_single_swap_sats: u64,
    #[serde(default)]
    pub max_hourly_swap_sats: u64,
    pub funded_channels: Vec<String>,
    #[serde(default)]
    pub channel_funding_reservations: Vec<(String, ChannelFundingReservation)>,
    /// Known ICRC block heights already processed (prevents double-crediting after upgrade)
    #[serde(default)]
    pub known_txs: Vec<u64>,
    /// Active (non-terminal) onramp request IDs
    #[serde(default)]
    pub active_onramp_ids: Vec<String>,
    /// Active (non-terminal) offramp request IDs
    #[serde(default)]
    pub active_offramp_ids: Vec<String>,
    /// Running counter of ckBTC sats reserved for pending onramp requests
    #[serde(default)]
    pub reserved_ckbtc_sats: u64,
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
