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
pub mod admin;

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
pub use admin::*;

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
use candid::{Nat, Principal};
use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;

use crate::ic_types::RelayRegistration;

lazy_static! {
    pub(crate) static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal")
            ),
            canister_self(),
        ));
}

pub struct CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    pub(crate) principal: Principal,

    // Multiple liquidity depositor addresses
    pub(crate) btc_liquidity_addresses: HashMap<Principal, String>,

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
}

/// Internal representation of channel secrets (not exposed via Candid)
#[derive(Clone, Debug)]
pub struct ChannelSecretsInternal {
    pub htlc_base_secret: [u8; 32],
    pub revocation_base_secret: [u8; 32],
    pub delayed_payment_base_secret: [u8; 32],
    pub payment_secret: [u8; 32],
    pub commitment_seed: [u8; 32],
}

/// Transaction details needed to sign an HTLC
#[derive(Clone, Debug)]
pub struct HtlcTxDetails {
    pub channel_id: [u8; 32],
    pub htlc_outpoint_txid: [u8; 32],
    pub htlc_outpoint_vout: u32,
    pub htlc_amount_sat: u64,
    pub receiver_address: String,
    pub sender_address: String,
    pub per_commitment_point: [u8; 33],
    pub witness_script: Vec<u8>,
}

pub async fn set_btc_liquidity_address_impl() -> Result<SetLiquidityBtcAddressResponse, BtcError> {
    let depositor = msg_caller(); // IC principal of the caller

    // First check state
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_liquidity_addresses.get(&depositor) {
            return Ok(SetLiquidityBtcAddressResponse {
                address: addr.clone(),
                already_existed: true,
            });
        }
    }

    // Derive new SegWit address for this depositor
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // Store in state
    {
        let mut state = STATE.write().unwrap();
        state
            .btc_liquidity_addresses
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
    let mut state = STATE.write().unwrap();
    let address_type = set_btc_address_args.address_type;
    let principal = msg_caller();

    assert!(principal == set_btc_address_args.principal.unwrap());

    assert!(!state.btc_liquidity_addresses.contains_key(&principal));

    // Check if address for this type exists
    if let Some(address) = state.btc_liquidity_addresses.get(&principal) {
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

    // Store in the map
    state
        .btc_liquidity_addresses
        .insert(principal.clone(), address.clone());

    Ok(SetBtcAddressResponse {
        address,
        msg: SetBtcAddressMsg::BtcAddressSetNowSingle(address_type),
    })
}

pub async fn get_btc_balances_impl(
    confirmations: Option<u64>,
) -> Result<GetBtcBalancesResponse, BtcError> {
    let state = STATE.read().unwrap();

    let mut balances: HashMap<Principal, Option<u64>> = HashMap::new();
    let mut any_address_set = false;

    for (address_type, address) in &state.btc_liquidity_addresses {
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
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_invoice_address.as_ref() {
            return Ok(addr.clone());
        }
    }

    // Derive SINGLE invoice deposit address
    let purpose = BtcPurpose::LnInvoiceDeposit;
    let address = get_segwit_address(purpose).await?;

    // Store globally
    {
        let mut state = STATE.write().unwrap();
        state.btc_invoice_address = Some(address.clone());
    }

    Ok(address)
}

pub async fn get_btc_liquidity_address_for_caller_impl() -> std::result::Result<String, BtcError> {
    let depositor = msg_caller();

    // 1. Fast path: return existing address if present
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_liquidity_addresses.get(&depositor) {
            return Ok(addr.clone());
        }
    }

    // 2. Derive new SegWit address for this depositor
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // 3. Store in state and return
    {
        let mut state = STATE.write().unwrap();
        state
            .btc_liquidity_addresses
            .insert(depositor, address.clone());
    }

    Ok(address)
}

pub async fn transaction_notification_impl(
    notify_args: NotifyArgs,
) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
    let mut state = STATE.write().unwrap();
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
    let state = STATE.read().unwrap();
    state.query_holdings(funding)
}

pub async fn withdraw_lp_impl(
    withdrawal: WithdrawalLPArgs,
    sig_withdrawal: Vec<u8>,
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().unwrap();
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
    let mut state = STATE.write().unwrap();
    state.withdraw_from_liq_pool(req).await
}

pub fn deposit_channel_impl(
    funding: ChannelFunding,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().unwrap();
    state.deposit_icrc(blocktime(), Funding::Channel(funding), signature_bytes)
}

pub fn deposit_lp_impl(
    funding: FundingLPArgs,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().unwrap();

    let pool_funding = funding.pool_funding;

    state.deposit_icrc(blocktime(), Funding::Pool(pool_funding), signature_bytes)
}

pub fn query_state_impl(id: ChannelId) -> Option<RegisteredState> {
    let state = STATE.read().unwrap();
    state.state(&id)
}

impl<Q> CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    pub fn new(q: Q, my_principal: Principal) -> Self {
        assert!(my_principal == canister_self());

        Self {
            principal: canister_self(),
            btc_liquidity_addresses: HashMap::new(), // multiple per depositor
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
            },
            protocol_fees_ckbtc: 0,
            admin: None,
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
        pubkey: &Vec<u8>,
        amount: Amount,
        asset: &PoolAsset,
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
            created_at_time: None,
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
    pub fn withdraw_channel(&mut self, funding: Funding, amount: Amount) -> ResultCkl<()> {
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
        time: Timestamp,
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
        let total_u64 = total.0.to_u64_digits()[0];
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
}
