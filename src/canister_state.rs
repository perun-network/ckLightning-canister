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
use crate::BtcPurpose;
use crate::btc::address::get_balance;
use crate::btc::address::get_segwit_address;
use crate::btc::address::{get_p2pkh_address, get_p2tr_key_path_only_address, get_p2wpkh_address};
use crate::btc::common::get_fee_per_byte;
use crate::btc::ecdsa::{get_ecdsa_public_key, sign_with_ecdsa};
use crate::btc::p2wpkh;
use crate::error::{BtcError, CklError, ResultBtc};
use crate::helpers::{execute_ledger_transfer, send_btc_from_lp_address};
use crate::htlc::{
    HtlcManager,
    // HTLC signing functions (Phase 2)
    build_htlc_witness_script, build_htlc_success_tx, build_htlc_timeout_tx,
    sign_htlc_input, apply_htlc_success_witness, apply_htlc_timeout_witness,
    verify_preimage,
};
use crate::ic_types::PoolAsset;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::{
    Amount, BtcAddressType, ChannelFunding, ChannelId, DEVNET_CKBTC_LEDGER, Funding,
    FundingLPArgs, FundingLPQueryArgs, GetBtcBalanceArgs, GetBtcBalancesResponse, HoldingsResponse,
    NotifyArgs, PoolWithdrawal, RegisteredState, SetBtcAddressArgs, SetBtcAddressMsg,
    SetBtcAddressResponse, WithdrawalLPArgs, WithdrawalReq,
};
use crate::ic_types::{
    CompleteSwapRequest, CompleteSwapResponse, RegisterSwapRequest, RegisterSwapResponse,
    SwapInfo, SwapState, PendingBtcDeposit, LpBtcAddressResponse, LpBtcDepositRequest,
    LpBtcDepositResponse, LpBtcWithdrawRequest, LpBtcWithdrawResponse,
    // User BTC operations
    SendFromDepositorRequest, SendFromDepositorResponse, DepositorBtcBalanceResponse,
    // Onramp invoice request types
    OnrampInvoiceRequest, OnrampInvoiceResponse, OnrampRequestInfo, OnrampRequestState,
    PendingInvoiceRequest, SubmitInvoiceRequest, SubmitInvoiceResponse, GetInvoiceResponse,
    // Offramp types (ckBTC → Lightning)
    OfframpRequest, OfframpResponse, OfframpRequestInfo, OfframpRequestState,
    PendingOfframpRequest, CompleteOfframpRequest, CompleteOfframpResponse,
    FailOfframpRequest, FailOfframpResponse, GetOfframpStatusResponse,
};
use crate::ic_types::{
    BtcOutpoint, LnChannelInfo, LnChannelStatus,
    QueryLnChannelRequest, QueryLnChannelsResponse, RegisterLnChannelRequest,
    RegisterLnChannelResponse, VerifyLnChannelResponse,
    // LP Liquidity types
    LpBtcUtxo, GetFundingUtxosResponse,
    UpdateChannelBalanceRequest, UpdateChannelBalanceResponse,
    LpLiquidityStatus, LnChannelBalance,
    // Channel funding types
    FundChannelRequest, FundChannelResponse,
    // HTLC types
    CreateHtlcRequest, CreateHtlcResponse,
    FulfillHtlcRequest, FulfillHtlcResponse,
    TimeoutHtlcRequest, TimeoutHtlcResponse,
    HtlcInfo,
    // Channel secrets types (Phase 2)
    ChannelSecrets, RegisterChannelSecretsRequest, RegisterChannelSecretsResponse,
    ChannelSecretsInfo,
    // HTLC signing types (Phase 2)
    CreateHtlcWithTxDetailsRequest, CreateHtlcWithTxDetailsResponse,
    SignHtlcSuccessRequest, SignHtlcTimeoutRequest, SignHtlcResponse,
};
use crate::liquidity_pool::LiquidityPool;
use crate::receiver::ICPReceiverError;
use crate::receiver::TransactionICRCNotification;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::{Address, CompressedPublicKey};
use bitcoin::{PublicKey, consensus::serialize};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use ic_cdk::bitcoin_canister::{
    GetBalanceRequest, GetUtxosRequest, SendTransactionRequest,
    bitcoin_get_balance, bitcoin_get_utxos, bitcoin_send_transaction,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

use crate::error::ResultCkl;
use crate::ic_types::{DEFAULT_CKBTC_FEE, L1Account, Params, State, Timestamp};
use crate::receiver;
use crate::require;
use candid::{Nat, Principal};
use std::str::FromStr;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal") // //bkyz2-fmaaa-aaaaa-qaaaq-cai
            ),
            canister_self(),
        ));
}

pub struct CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    principal: Principal,

    // Multiple liquidity depositor addresses
    btc_liquidity_addresses: HashMap<Principal, String>,

    // SINGLE global invoice deposit address
    btc_invoice_address: Option<String>,

    // SINGLE shared LP BTC address (for Option C)
    lp_btc_address: Option<String>,

    // Pending BTC deposits awaiting confirmation (txid -> PendingBtcDeposit)
    pending_btc_deposits: HashMap<[u8; 32], PendingBtcDeposit>,

    // Processed UTXOs to avoid double-crediting (txid:vout -> depositor)
    processed_utxos: HashMap<(Vec<u8>, u32), Principal>,

    icrc_receiver: receiver::Receiver<Q>,
    user_holdings: HashMap<Funding, Amount>,
    channels: HashMap<ChannelId, RegisteredState>,
    liq_pool: LiquidityPool,

    // Lightning → ckBTC swaps storage (payment_hash -> SwapInfo)
    swaps: HashMap<[u8; 32], SwapInfo>,

    // Lightning channel funding verification (channel_id -> LnChannelInfo)
    ln_channels: HashMap<[u8; 32], LnChannelInfo>,

    // Onramp invoice requests (request_id -> OnrampRequestInfo)
    onramp_requests: HashMap<String, OnrampRequestInfo>,

    // Offramp requests (request_id -> OfframpRequestInfo)
    offramp_requests: HashMap<String, OfframpRequestInfo>,

    // ==========================================================================
    // LP Liquidity Tracking (Canister-Controlled BTC for Lightning)
    // ==========================================================================

    // Channel balance tracking (channel_id -> LnChannelBalance)
    channel_balances: HashMap<[u8; 32], LnChannelBalance>,

    // LP BTC statistics
    total_btc_deposited: u64,      // Lifetime total deposited by LP providers
    total_btc_in_channels: u64,    // Total BTC currently locked in channels

    // UTXOs reserved for pending channel opens (txid:vout -> channel_id)
    reserved_utxos: HashMap<(Vec<u8>, u32), [u8; 32]>,

    // HTLC state management
    htlc_manager: HtlcManager,

    // ==========================================================================
    // Channel Secrets (Phase 2: Full channel control by canister)
    // ==========================================================================

    // Per-channel secrets for HTLC signing (channel_id -> secrets)
    channel_secrets: HashMap<[u8; 32], ChannelSecretsInternal>,

    // HTLC transaction details for signing (payment_hash -> details)
    htlc_tx_details: HashMap<[u8; 32], HtlcTxDetails>,
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

// pub struct CanisterState<Q>
// where
//     Q: receiver::TXQuerier,
// {
//     principal: Principal,
//     btc_addresses_liquidity: Option<String>,
//     btc_address_lightning: Option<String>,
//     own_btc_addresses: HashMap<BtcAddressType, String>,
//     icrc_receiver: receiver::Receiver<Q>,
//     user_holdings: HashMap<Funding, Amount>,
//     channels: HashMap<ChannelId, RegisteredState>,
//     liq_pool: LiquidityPool,
// }

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

// pub async fn get_btc_liquidity_address_for_caller_impl() -> std::result::Result<String, BtcError> {
//     let depositor = msg_caller();
//     let state = STATE.read().unwrap();
//     match state.btc_liquidity_addresses.get(&depositor) {
//         Some(addr) => Ok(addr.clone()),
//         None => Err(BtcError::Other(
//             "No liquidity BTC address set for caller".to_string(),
//         )),
//     }
// }

// pub async fn query_btc_address_impl() -> Result<QueryBtcAddressResponse, BtcError> {
//     let state = STATE.read().unwrap();
//     let addresses_map = state.btc_liquidity_addresses.clone();

//     if addresses_map.is_empty() {
//         // No addresses set, respond with None
//         Ok(QueryBtcAddressResponse {
//             msg: SetBtcAddressMsg::BtcAddressNotSet,
//             addresses: None,
//         })
//     } else {
//         // Return all stored addresses in Some(HashMap)
//         Ok(QueryBtcAddressResponse {
//             msg: SetBtcAddressMsg::BtcAddressesAvailable,
//             addresses: Some(addresses_map),
//         })
//     }
// }

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
    //std::result::Result<(), CklError>
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
        }
    }

    // pub fn set_btc_address_impl(&mut self, address: String) -> () {
    //     self.btc_liquidity_addresses = Some(address);
    // }

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
        // TODO: Implement transfer logic here

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
        //     // events::STATE
        //     //     .write()
        //     //     .unwrap()
        //     //     .register_event(
        //     //         time,
        //     //         funding.channel.clone(),
        //     //         Event::Funded {
        //     //             who: funding.participant.clone(),
        //     //             total: self.user_holdings.get(&funding).cloned().unwrap(),
        //     //             timestamp: time,
        //     //         },
        //     //     )
        //     //     .await;
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
            // let amt = outcome.clone();
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

// =============================================================================
// Lightning → ckBTC Swap Implementation
// =============================================================================

/// Register a new Lightning → ckBTC swap
///
/// Called by the relay node when an invoice is created with an IC principal.
/// Stores the swap info so it can be verified and completed later.
pub fn register_swap_impl(request: RegisterSwapRequest) -> RegisterSwapResponse {
    // Validate payment_hash length
    if request.payment_hash.len() != 32 {
        return RegisterSwapResponse {
            success: false,
            error: Some("Invalid payment_hash length (must be 32 bytes)".to_string()),
        };
    }

    // Convert to fixed array
    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    // Check if swap already exists
    {
        let state = STATE.read().unwrap();
        if state.swaps.contains_key(&payment_hash_arr) {
            return RegisterSwapResponse {
                success: false,
                error: Some("Swap with this payment_hash already exists".to_string()),
            };
        }
    }

    // Create swap info
    let swap_info = SwapInfo {
        payment_hash: request.payment_hash.clone(),
        amount_msat: request.amount_msat,
        recipient: request.recipient,
        created_at: blocktime(),
        expiry_timestamp: request.expiry_timestamp,
        state: SwapState::Pending,
    };

    // Store swap
    {
        let mut state = STATE.write().unwrap();
        state.swaps.insert(payment_hash_arr, swap_info);
    }

    RegisterSwapResponse {
        success: true,
        error: None,
    }
}

/// Complete a Lightning → ckBTC swap
///
/// Called by the relay node when a Lightning payment is received.
/// Verifies the preimage, then transfers ckBTC to the recipient.
pub async fn complete_swap_impl(request: CompleteSwapRequest) -> CompleteSwapResponse {
    // Validate lengths
    if request.payment_hash.len() != 32 {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Invalid payment_hash length".to_string()),
        };
    }
    if request.preimage.len() != 32 {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Invalid preimage length".to_string()),
        };
    }

    // Verify preimage matches payment_hash
    let computed_hash = sha256::Hash::hash(&request.preimage);
    if computed_hash.as_byte_array() != request.payment_hash.as_slice() {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Preimage does not match payment_hash".to_string()),
        };
    }

    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    // Get swap info and verify state
    let swap_info = {
        let state = STATE.read().unwrap();
        match state.swaps.get(&payment_hash_arr) {
            Some(info) => info.clone(),
            None => {
                return CompleteSwapResponse {
                    success: false,
                    block_index: None,
                    error: Some("Swap not found for this payment_hash".to_string()),
                };
            }
        }
    };

    // Check swap state
    match &swap_info.state {
        SwapState::Pending => {} // OK to proceed
        SwapState::Completed { .. } => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some("Swap already completed".to_string()),
            };
        }
        SwapState::Expired => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some("Swap has expired".to_string()),
            };
        }
        SwapState::Failed { reason } => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some(format!("Swap failed: {}", reason)),
            };
        }
    }

    // Convert amount from millisatoshis to satoshis
    let amount_sat = swap_info.amount_msat / 1000;
    if amount_sat == 0 {
        // Mark as failed
        {
            let mut state = STATE.write().unwrap();
            if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                swap.state = SwapState::Failed {
                    reason: "Amount too small".to_string(),
                };
            }
        }
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Amount too small (< 1000 msat)".to_string()),
        };
    }

    // Check LP has sufficient liquidity and deduct proportionally from all depositors
    let amount_nat = Nat::from(amount_sat);
    {
        let mut state = STATE.write().unwrap();
        if let Err(_) = state.liq_pool.deduct_proportional(PoolAsset::CkBTC, amount_nat.clone()) {
            if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                swap.state = SwapState::Failed {
                    reason: "Insufficient LP liquidity".to_string(),
                };
            }
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some("Insufficient LP liquidity for swap".to_string()),
            };
        }
    }

    // Execute ckBTC transfer
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: swap_info.recipient,
            subaccount: None,
        },
        amount: Nat(amount_sat.into()),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(
            request.payment_hash.clone(),
        )),
        created_at_time: None,
    };

    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let call_result: CallResult<(
        std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                // Mark swap as completed
                {
                    let mut state = STATE.write().unwrap();
                    if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                        swap.state = SwapState::Completed {
                            block_index: block_index.clone(),
                        };
                    }
                }
                CompleteSwapResponse {
                    success: true,
                    block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Restore LP balance and mark as failed
                {
                    let mut state = STATE.write().unwrap();
                    // Restore the deducted amount back to pool
                    state.liq_pool.holdings_total
                        .get_mut(&PoolAsset::CkBTC)
                        .map(|total| *total += amount_nat.clone());
                    if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                        swap.state = SwapState::Failed {
                            reason: format!("Transfer error: {:?}", e),
                        };
                    }
                }
                CompleteSwapResponse {
                    success: false,
                    block_index: None,
                    error: Some(format!("ckBTC transfer failed: {:?}", e)),
                }
            }
        },
        Err((code, msg)) => {
            // Restore LP balance and mark as failed
            {
                let mut state = STATE.write().unwrap();
                // Restore the deducted amount back to pool
                state.liq_pool.holdings_total
                    .get_mut(&PoolAsset::CkBTC)
                    .map(|total| *total += amount_nat.clone());
                if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                    swap.state = SwapState::Failed {
                        reason: format!("Call error: {:?} - {}", code, msg),
                    };
                }
            }
            CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some(format!("Canister call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

// =============================================================================
// Onramp Invoice Request Implementation (Canister-First Flow)
// =============================================================================

/// Request a new onramp invoice
///
/// Called by clients to initiate a Lightning → ckBTC swap.
/// Creates a pending request that the relay will fulfill with an actual invoice.
pub fn request_onramp_invoice_impl(request: OnrampInvoiceRequest) -> OnrampInvoiceResponse {
    // Validate amount
    if request.amount_sats == 0 {
        return OnrampInvoiceResponse {
            request_id: String::new(),
            success: false,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Generate unique request ID (hash of recipient + amount + time)
    let now = blocktime();
    let mut hash_input = request.recipient.as_slice().to_vec();
    hash_input.extend_from_slice(&request.amount_sats.to_be_bytes());
    hash_input.extend_from_slice(&now.to_be_bytes());
    let request_id_hash = sha256::Hash::hash(&hash_input);
    // Convert first 16 bytes to hex string
    let request_id = request_id_hash.as_byte_array()[..16]
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Create the request info
    let request_info = OnrampRequestInfo {
        request_id: request_id.clone(),
        recipient: request.recipient,
        amount_sats: request.amount_sats,
        created_at: now,
        state: OnrampRequestState::Pending,
        invoice: None,
        payment_hash: None,
        expiry_timestamp: None,
    };

    // Store the request
    {
        let mut state = STATE.write().unwrap();
        state.onramp_requests.insert(request_id.clone(), request_info);
    }

    OnrampInvoiceResponse {
        request_id,
        success: true,
        error: None,
    }
}

/// Get all pending invoice requests for the relay to process
///
/// Called by the relay to find requests that need invoices created.
pub fn get_pending_invoice_requests_impl() -> Vec<PendingInvoiceRequest> {
    let state = STATE.read().unwrap();

    state.onramp_requests
        .values()
        .filter(|req| matches!(req.state, OnrampRequestState::Pending))
        .map(|req| PendingInvoiceRequest {
            request_id: req.request_id.clone(),
            recipient: req.recipient,
            amount_sats: req.amount_sats,
            amount_msat: req.amount_sats * 1000,
            created_at: req.created_at,
        })
        .collect()
}

/// Submit a created invoice for a pending request
///
/// Called by the relay after creating a BOLT11 invoice.
/// Also registers the swap so complete_swap works later.
pub fn submit_invoice_impl(request: SubmitInvoiceRequest) -> SubmitInvoiceResponse {
    // Validate payment_hash length
    if request.payment_hash.len() != 32 {
        return SubmitInvoiceResponse {
            success: false,
            error: Some("Invalid payment_hash length (must be 32 bytes)".to_string()),
        };
    }

    let mut state = STATE.write().unwrap();

    // Find the request
    let request_info = match state.onramp_requests.get_mut(&request.request_id) {
        Some(info) => info,
        None => {
            return SubmitInvoiceResponse {
                success: false,
                error: Some("Request not found".to_string()),
            };
        }
    };

    // Check state
    if !matches!(request_info.state, OnrampRequestState::Pending) {
        return SubmitInvoiceResponse {
            success: false,
            error: Some("Request is not in pending state".to_string()),
        };
    }

    // Update the request with invoice info
    request_info.invoice = Some(request.invoice);
    request_info.payment_hash = Some(request.payment_hash.clone());
    request_info.expiry_timestamp = Some(request.expiry_timestamp);
    request_info.state = OnrampRequestState::Ready;

    // Also register the swap (so complete_swap works)
    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    let swap_info = SwapInfo {
        payment_hash: request.payment_hash,
        amount_msat: request_info.amount_sats * 1000,
        recipient: request_info.recipient,
        created_at: blocktime(),
        expiry_timestamp: request.expiry_timestamp,
        state: SwapState::Pending,
    };

    state.swaps.insert(payment_hash_arr, swap_info);

    SubmitInvoiceResponse {
        success: true,
        error: None,
    }
}

/// Get the invoice for a request (client polling)
///
/// Called by clients to check if their invoice is ready.
pub fn get_invoice_by_request_impl(request_id: String) -> GetInvoiceResponse {
    let state = STATE.read().unwrap();

    match state.onramp_requests.get(&request_id) {
        Some(info) => GetInvoiceResponse {
            state: info.state.clone(),
            invoice: info.invoice.clone(),
            error: None,
        },
        None => GetInvoiceResponse {
            state: OnrampRequestState::Failed {
                reason: "Request not found".to_string(),
            },
            invoice: None,
            error: Some("Request not found".to_string()),
        },
    }
}

/// Mark an onramp request as completed (called after complete_swap)
///
/// Internal function to update onramp request state when swap completes.
pub fn mark_onramp_completed_impl(payment_hash: &[u8], block_index: Nat) {
    let mut state = STATE.write().unwrap();

    // Find the request by payment_hash
    for request in state.onramp_requests.values_mut() {
        if let Some(ref ph) = request.payment_hash {
            if ph.as_slice() == payment_hash {
                request.state = OnrampRequestState::Completed { block_index };
                break;
            }
        }
    }
}

// =============================================================================
// Offramp Implementation (ckBTC → Lightning)
// =============================================================================

/// Request an offramp (ckBTC → Lightning)
///
/// Called by a user who wants to pay a Lightning invoice using their ckBTC.
/// The canister takes custody of the ckBTC via ICRC-2 transfer_from.
/// The relay then pays the invoice and reports success/failure.
pub async fn request_offramp_impl(request: OfframpRequest) -> OfframpResponse {
    let caller = msg_caller();

    // Parse the invoice to extract amount and payment_hash
    let invoice = match lightning_invoice::Bolt11Invoice::from_str(&request.invoice) {
        Ok(inv) => inv,
        Err(e) => {
            return OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: None,
                error: Some(format!("Invalid invoice: {}", e)),
            };
        }
    };

    // Get amount in millisatoshis
    let amount_msat = match invoice.amount_milli_satoshis() {
        Some(amt) => amt,
        None => {
            return OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: None,
                error: Some("Invoice has no amount specified".to_string()),
            };
        }
    };

    let amount_sats = amount_msat / 1000;

    // Extract payment hash
    let payment_hash_slice: &[u8] = invoice.payment_hash().as_ref();
    let payment_hash = payment_hash_slice.to_vec();

    // Get invoice expiry
    let invoice_expiry = invoice.expires_at()
        .map(|d| d.as_secs())
        .unwrap_or(ic_cdk::api::time() / 1_000_000_000 + 3600); // Default 1 hour

    // Generate request_id from payment_hash
    let request_id = payment_hash.iter()
        .take(16)
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Take custody of user's ckBTC via ICRC-2 transfer_from
    // User must have called icrc2_approve(ckLightning canister, amount + fee) first
    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap();
    let canister_principal = canister_self();

    // Transfer ckBTC from user to canister
    let transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc_ledger_types::icrc1::account::Account {
            owner: caller,
            subaccount: None,
        },
        to: icrc_ledger_types::icrc1::account::Account {
            owner: canister_principal,
            subaccount: None,
        },
        amount: candid::Nat::from(amount_sats),
        fee: None,
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc2_transfer_from", (transfer_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(_block_index) => {
                // Success - store the offramp request
                let now = ic_cdk::api::time();

                let request_info = OfframpRequestInfo {
                    request_id: request_id.clone(),
                    user: caller,
                    invoice: request.invoice.clone(),
                    amount_sats,
                    amount_msat,
                    payment_hash: payment_hash.clone(),
                    invoice_expiry,
                    fallback_btc_address: request.fallback_btc_address,
                    created_at: now,
                    state: OfframpRequestState::Pending,
                    preimage: None,
                };

                {
                    let mut state = STATE.write().unwrap();
                    state.offramp_requests.insert(request_id.clone(), request_info);
                }

                OfframpResponse {
                    request_id,
                    success: true,
                    amount_sats: Some(amount_sats),
                    error: None,
                }
            }
            Err(err) => {
                OfframpResponse {
                    request_id: String::new(),
                    success: false,
                    amount_sats: Some(amount_sats),
                    error: Some(format!("Failed to take custody of ckBTC: {:?}", err)),
                }
            }
        },
        Err((code, msg)) => {
            OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: Some(amount_sats),
                error: Some(format!("ICRC-2 transfer_from failed: {:?} - {}", code, msg)),
            }
        }
    }
}

/// Get all pending offramp requests for the relay to process
///
/// Called by the relay to find requests that need invoices paid.
pub fn get_pending_offramp_requests_impl() -> Vec<PendingOfframpRequest> {
    let state = STATE.read().unwrap();

    state.offramp_requests
        .values()
        .filter(|req| matches!(req.state, OfframpRequestState::Pending))
        .map(|req| PendingOfframpRequest {
            request_id: req.request_id.clone(),
            invoice: req.invoice.clone(),
            amount_msat: req.amount_msat,
            payment_hash: req.payment_hash.clone(),
            created_at: req.created_at,
            invoice_expiry: req.invoice_expiry,
        })
        .collect()
}

/// Mark an offramp request as payment in progress
///
/// Called by the relay when it starts attempting to pay the invoice.
pub fn mark_offramp_in_progress_impl(request_id: &str) -> bool {
    let mut state = STATE.write().unwrap();

    if let Some(request) = state.offramp_requests.get_mut(request_id) {
        if matches!(request.state, OfframpRequestState::Pending) {
            request.state = OfframpRequestState::PaymentInProgress;
            return true;
        }
    }
    false
}

/// Complete an offramp request after successful payment
///
/// Called by the relay after successfully paying the Lightning invoice.
pub fn complete_offramp_impl(request: CompleteOfframpRequest) -> CompleteOfframpResponse {
    // Validate preimage length
    if request.preimage.len() != 32 {
        return CompleteOfframpResponse {
            success: false,
            error: Some("Preimage must be 32 bytes".to_string()),
        };
    }

    // Verify preimage matches payment_hash
    let computed_hash = bitcoin::hashes::sha256::Hash::hash(&request.preimage);
    let computed_hash_bytes = computed_hash.as_byte_array();

    let mut state = STATE.write().unwrap();

    let request_info = match state.offramp_requests.get_mut(&request.request_id) {
        Some(info) => info,
        None => {
            return CompleteOfframpResponse {
                success: false,
                error: Some("Request not found".to_string()),
            };
        }
    };

    // Verify payment_hash matches
    if request_info.payment_hash.as_slice() != computed_hash_bytes {
        return CompleteOfframpResponse {
            success: false,
            error: Some("Preimage does not match payment_hash".to_string()),
        };
    }

    // Check state
    if !matches!(request_info.state, OfframpRequestState::Pending | OfframpRequestState::PaymentInProgress) {
        return CompleteOfframpResponse {
            success: false,
            error: Some(format!("Invalid state for completion: {:?}", request_info.state)),
        };
    }

    // Mark as completed
    request_info.state = OfframpRequestState::Completed {
        preimage: request.preimage.clone(),
    };
    request_info.preimage = Some(request.preimage);

    CompleteOfframpResponse {
        success: true,
        error: None,
    }
}

/// Fail an offramp request and initiate refund
///
/// Called by the relay when it fails to pay the Lightning invoice.
/// The ckBTC is refunded to the user.
pub async fn fail_offramp_impl(request: FailOfframpRequest) -> FailOfframpResponse {
    let (user, amount_sats) = {
        let mut state = STATE.write().unwrap();

        let request_info = match state.offramp_requests.get_mut(&request.request_id) {
            Some(info) => info,
            None => {
                return FailOfframpResponse {
                    success: false,
                    refund_block_index: None,
                    error: Some("Request not found".to_string()),
                };
            }
        };

        // Check state
        if !matches!(request_info.state, OfframpRequestState::Pending | OfframpRequestState::PaymentInProgress) {
            return FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Invalid state for failure: {:?}", request_info.state)),
            };
        }

        // Mark as failed first
        request_info.state = OfframpRequestState::Failed {
            reason: request.reason.clone(),
        };

        (request_info.user, request_info.amount_sats)
    };

    // Refund ckBTC to user
    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap();

    let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
        from_subaccount: None,
        to: icrc_ledger_types::icrc1::account::Account {
            owner: user,
            subaccount: None,
        },
        amount: candid::Nat::from(amount_sats),
        fee: None,
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc1_transfer", (transfer_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                // Update state to refunded
                let mut state = STATE.write().unwrap();
                if let Some(request_info) = state.offramp_requests.get_mut(&request.request_id) {
                    request_info.state = OfframpRequestState::Refunded {
                        block_index: block_index.clone(),
                    };
                }

                FailOfframpResponse {
                    success: true,
                    refund_block_index: Some(block_index),
                    error: None,
                }
            }
            Err(err) => {
                FailOfframpResponse {
                    success: false,
                    refund_block_index: None,
                    error: Some(format!("Refund transfer failed: {:?}", err)),
                }
            }
        },
        Err((code, msg)) => {
            FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Refund call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

/// Get the status of an offramp request
///
/// Called by users to check the status of their offramp.
pub fn get_offramp_status_impl(request_id: String) -> GetOfframpStatusResponse {
    let state = STATE.read().unwrap();

    match state.offramp_requests.get(&request_id) {
        Some(info) => GetOfframpStatusResponse {
            state: info.state.clone(),
            amount_sats: info.amount_sats,
            error: None,
        },
        None => GetOfframpStatusResponse {
            state: OfframpRequestState::Failed {
                reason: "Request not found".to_string(),
            },
            amount_sats: 0,
            error: Some("Request not found".to_string()),
        },
    }
}

// =============================================================================
// Lightning Channel Funding Verification Implementation
// =============================================================================

/// Register a new Lightning channel for funding verification
///
/// Called by the relay node when a channel is opened.
/// Stores the channel info so the funding UTXO can be verified on-chain.
pub fn register_ln_channel_impl(request: RegisterLnChannelRequest) -> RegisterLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    // Validate funding_txid length
    if request.funding_txid.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid funding_txid length (must be 32 bytes)".to_string()),
        };
    }

    // Validate node IDs (33 bytes compressed pubkey)
    if request.local_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid local_node_id length (must be 33 bytes)".to_string()),
        };
    }
    if request.remote_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid remote_node_id length (must be 33 bytes)".to_string()),
        };
    }

    // Convert to fixed array
    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Check if channel already exists
    {
        let state = STATE.read().unwrap();
        if state.ln_channels.contains_key(&channel_id_arr) {
            return RegisterLnChannelResponse {
                success: false,
                error: Some("Channel with this channel_id already registered".to_string()),
            };
        }
    }

    // Create channel info
    let channel_info = LnChannelInfo {
        channel_id: request.channel_id.clone(),
        funding_outpoint: BtcOutpoint {
            txid: request.funding_txid.clone(),
            vout: request.funding_vout,
        },
        capacity_sats: request.capacity_sats,
        local_node_id: request.local_node_id.clone(),
        remote_node_id: request.remote_node_id.clone(),
        funding_address: request.funding_address.clone(),
        registered_at: blocktime(),
        last_verified_at: None,
        status: LnChannelStatus::Pending,
    };

    // Store channel
    {
        let mut state = STATE.write().unwrap();
        state.ln_channels.insert(channel_id_arr, channel_info);
    }

    RegisterLnChannelResponse {
        success: true,
        error: None,
    }
}

/// Verify a Lightning channel's funding UTXO on-chain
///
/// Queries the Bitcoin canister to check if the funding UTXO exists
/// and has sufficient confirmations.
pub async fn verify_ln_channel_impl(
    request: QueryLnChannelRequest,
) -> VerifyLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return VerifyLnChannelResponse {
            verified: false,
            confirmations: None,
            utxo_value_sats: None,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Get channel info
    let channel_info = {
        let state = STATE.read().unwrap();
        match state.ln_channels.get(&channel_id_arr) {
            Some(info) => info.clone(),
            None => {
                return VerifyLnChannelResponse {
                    verified: false,
                    confirmations: None,
                    utxo_value_sats: None,
                    error: Some("Channel not found".to_string()),
                };
            }
        }
    };

    // Get Bitcoin context
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Use the stored funding address (provided by relay when registering)
    let funding_address = &channel_info.funding_address;

    // Query UTXOs for the funding address
    let utxos_result = bitcoin_get_utxos(&GetUtxosRequest {
        address: funding_address.clone(),
        network: ctx.network,
        filter: None, // Get all UTXOs including unconfirmed
    })
    .await;

    let utxos_response = match utxos_result {
        Ok(response) => response,
        Err(e) => {
            return VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!("Failed to query UTXOs: {:?}", e)),
            };
        }
    };

    // Get current tip height to calculate confirmations
    let tip_height = utxos_response.tip_height;

    // Look for the specific funding UTXO by matching txid and vout
    // Note: The txid in the UTXO response is in internal byte order (little-endian)
    // while Lightning typically uses big-endian (display order)
    let funding_txid = &channel_info.funding_outpoint.txid;
    let funding_vout = channel_info.funding_outpoint.vout;

    let mut found_utxo: Option<(u64, u32)> = None; // (value, confirmations)

    for utxo in &utxos_response.utxos {
        // Compare txid (both should be in the same byte order from the canister)
        if utxo.outpoint.txid.as_slice() == funding_txid.as_slice()
            && utxo.outpoint.vout == funding_vout
        {
            // Found the funding UTXO
            let confirmations = if utxo.height > 0 {
                tip_height.saturating_sub(utxo.height) + 1
            } else {
                0 // Unconfirmed
            };
            found_utxo = Some((utxo.value, confirmations));
            break;
        }
    }

    match found_utxo {
        Some((value, confirmations)) => {
            // Verify the value matches the claimed capacity
            let value_matches = value == channel_info.capacity_sats;

            // Update channel status
            let current_time = blocktime();
            {
                let mut state = STATE.write().unwrap();
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    if value_matches && confirmations >= 3 {
                        channel.status = LnChannelStatus::Verified {
                            confirmations: confirmations as u32,
                        };
                    } else if !value_matches {
                        channel.status = LnChannelStatus::Failed {
                            reason: format!(
                                "Value mismatch: expected {} sats, found {} sats",
                                channel_info.capacity_sats, value
                            ),
                        };
                    } else {
                        // Not enough confirmations yet, keep as pending
                        channel.status = LnChannelStatus::Pending;
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: value_matches && confirmations >= 3,
                confirmations: Some(confirmations as u32),
                utxo_value_sats: Some(value),
                error: if !value_matches {
                    Some(format!(
                        "Value mismatch: expected {} sats, found {} sats",
                        channel_info.capacity_sats, value
                    ))
                } else if confirmations < 3 {
                    Some(format!(
                        "Insufficient confirmations: {} (need at least 3)",
                        confirmations
                    ))
                } else {
                    None
                },
            }
        }
        None => {
            // UTXO not found - channel might be closed or funding tx not yet confirmed
            let current_time = blocktime();
            {
                let mut state = STATE.write().unwrap();
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    // Check if channel was previously verified - if so, it's now closed
                    match &channel.status {
                        LnChannelStatus::Verified { .. } => {
                            channel.status = LnChannelStatus::Closed;
                        }
                        _ => {
                            // Keep current status, UTXO might not be confirmed yet
                        }
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!(
                    "Funding UTXO not found at address {}. Channel may be closed or funding tx not yet confirmed.",
                    funding_address
                )),
            }
        }
    }
}

/// Query a specific Lightning channel
pub fn query_ln_channel_impl(request: QueryLnChannelRequest) -> Option<LnChannelInfo> {
    if request.channel_id.len() != 32 {
        return None;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    let state = STATE.read().unwrap();
    state.ln_channels.get(&channel_id_arr).cloned()
}

/// Query all registered Lightning channels
pub fn query_ln_channels_impl() -> QueryLnChannelsResponse {
    let state = STATE.read().unwrap();
    let channels: Vec<LnChannelInfo> = state.ln_channels.values().cloned().collect();
    QueryLnChannelsResponse { channels }
}

/// Update a Lightning channel's status (e.g., when closed)
pub fn update_ln_channel_status_impl(channel_id: Vec<u8>, status: LnChannelStatus) -> bool {
    if channel_id.len() != 32 {
        return false;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&channel_id);

    let mut state = STATE.write().unwrap();
    if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
        channel.status = status;
        true
    } else {
        false
    }
}

// =============================================================================
// Simplified Liquidity Pool Implementation
// =============================================================================

use crate::ic_types::{LpBalanceResponse, LpDepositResponse, LpWithdrawResponse, TotalLpBalanceResponse};

/// Deposit ckBTC into the liquidity pool
///
/// The caller must have approved the canister to spend their ckBTC first via ICRC-2.
/// This function pulls ckBTC from the caller and credits their LP balance.
pub async fn deposit_ckbtc_impl(amount: Nat) -> LpDepositResponse {
    let caller = msg_caller();
    let canister_id = ic_cdk::api::canister_self();

    if amount == Nat::from(0u64) {
        return LpDepositResponse {
            success: false,
            new_balance: Nat::from(0u64),
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Pull ckBTC from caller using ICRC-2 transfer_from
    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let transfer_from_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: Account {
            owner: caller,
            subaccount: None,
        },
        to: Account {
            owner: canister_id,
            subaccount: None,
        },
        amount: amount.clone(),
        fee: None, // Use default fee
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc2_transfer_from", (transfer_from_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(_block_index) => {
                // Credit the caller's LP balance
                let mut state = STATE.write().unwrap();
                state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());

                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpDepositResponse {
                    success: true,
                    new_balance,
                    error: None,
                }
            }
            Err(e) => LpDepositResponse {
                success: false,
                new_balance: Nat::from(0u64),
                error: Some(format!("ICRC-2 transfer_from failed: {:?}", e)),
            },
        },
        Err((code, msg)) => LpDepositResponse {
            success: false,
            new_balance: Nat::from(0u64),
            error: Some(format!("Canister call failed: {:?} - {}", code, msg)),
        },
    }
}

/// Withdraw ckBTC from the liquidity pool
///
/// Checks the caller's LP balance and transfers ckBTC back to them.
pub async fn withdraw_ckbtc_impl(amount: Nat) -> LpWithdrawResponse {
    let caller = msg_caller();

    if amount == Nat::from(0u64) {
        return LpWithdrawResponse {
            success: false,
            amount_withdrawn: Nat::from(0u64),
            new_balance: Nat::from(0u64),
            block_index: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Check and deduct from LP balance
    {
        let mut state = STATE.write().unwrap();
        if let Err(e) = state.liq_pool.withdraw(caller, PoolAsset::CkBTC, amount.clone()) {
            let current_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);
            return LpWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_balance: current_balance,
                block_index: None,
                error: Some(format!("Insufficient balance: {:?}", e)),
            };
        }
    }

    // Transfer ckBTC to caller
    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: caller,
            subaccount: None,
        },
        amount: amount.clone(),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                let state = STATE.read().unwrap();
                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpWithdrawResponse {
                    success: true,
                    amount_withdrawn: amount,
                    new_balance,
                    block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Transfer failed - restore the LP balance
                let mut state = STATE.write().unwrap();
                state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());
                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpWithdrawResponse {
                    success: false,
                    amount_withdrawn: Nat::from(0u64),
                    new_balance,
                    block_index: None,
                    error: Some(format!("ckBTC transfer failed: {:?}", e)),
                }
            }
        },
        Err((code, msg)) => {
            // Call failed - restore the LP balance
            let mut state = STATE.write().unwrap();
            state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());
            let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

            LpWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_balance,
                block_index: None,
                error: Some(format!("Canister call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

/// Get the caller's LP balance
pub fn get_my_lp_balance_impl() -> LpBalanceResponse {
    let caller = msg_caller();
    let state = STATE.read().unwrap();

    LpBalanceResponse {
        ckbtc_balance: state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC),
        btc_balance: state.liq_pool.get_balance(&caller, &PoolAsset::BTC),
    }
}

/// Get the total LP balance across all depositors
pub fn get_total_lp_balance_impl() -> TotalLpBalanceResponse {
    let state = STATE.read().unwrap();

    TotalLpBalanceResponse {
        total_ckbtc: state.liq_pool.get_total(&PoolAsset::CkBTC),
        total_btc: state.liq_pool.get_total(&PoolAsset::BTC),
        num_depositors: state.liq_pool.depositors.len() as u64,
    }
}

// =============================================================================
// BTC Liquidity Pool Implementation (Shared LP Address - Option C)
// =============================================================================

const REQUIRED_BTC_CONFIRMATIONS: u32 = 6;

/// Get the shared LP BTC address
///
/// Returns a single shared SegWit (P2WPKH) address for all LP BTC deposits.
/// This is derived using chainkey ECDSA with a fixed derivation path.
pub async fn get_lp_btc_address_impl() -> Result<LpBtcAddressResponse, BtcError> {
    // Check cache first
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.lp_btc_address.as_ref() {
            return Ok(LpBtcAddressResponse {
                address: addr.clone(),
            });
        }
    }

    // Derive the shared LP BTC address
    let purpose = BtcPurpose::LiquidityPoolShared;
    let address = get_segwit_address(purpose).await?;

    // Cache it
    {
        let mut state = STATE.write().unwrap();
        state.lp_btc_address = Some(address.clone());
    }

    Ok(LpBtcAddressResponse { address })
}

/// Deposit BTC to the liquidity pool
///
/// This function scans the shared LP address for UTXOs that haven't been credited yet.
/// When called by a user, it will credit any new deposits with 6+ confirmations.
///
/// Flow:
/// 1. User sends BTC to the shared LP address (off-chain)
/// 2. User calls this function to claim their deposit
/// 3. Canister scans UTXOs and credits new deposits to the caller's LP balance
///
/// Note: Since we use a shared address, we rely on the caller being honest about which
/// deposits are theirs. For production, consider using per-user addresses or signatures.
pub async fn deposit_btc_impl(request: LpBtcDepositRequest) -> LpBtcDepositResponse {
    let caller = msg_caller();

    // Get the shared LP BTC address
    let lp_address = {
        let state = STATE.read().unwrap();
        match state.lp_btc_address.as_ref() {
            Some(addr) => addr.clone(),
            None => {
                // Address not initialized, derive it
                drop(state);
                match get_lp_btc_address_impl().await {
                    Ok(resp) => resp.address,
                    Err(e) => {
                        return LpBtcDepositResponse {
                            success: false,
                            credited_amount: Nat::from(0u64),
                            new_btc_balance: Nat::from(0u64),
                            error: Some(format!("Failed to get LP address: {:?}", e)),
                        };
                    }
                }
            }
        }
    };

    // Get Bitcoin context and query UTXOs
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    let utxos_result = bitcoin_get_utxos(&GetUtxosRequest {
        address: lp_address.clone(),
        network: ctx.network,
        filter: None,
    })
    .await;

    let utxos_response = match utxos_result {
        Ok(response) => response,
        Err(e) => {
            return LpBtcDepositResponse {
                success: false,
                credited_amount: Nat::from(0u64),
                new_btc_balance: Nat::from(0u64),
                error: Some(format!("Failed to query UTXOs: {:?}", e)),
            };
        }
    };

    let tip_height = utxos_response.tip_height;
    let mut total_credited: u64 = 0;

    // Process each UTXO
    for utxo in &utxos_response.utxos {
        // Calculate confirmations
        let confirmations = if utxo.height > 0 {
            tip_height.saturating_sub(utxo.height) + 1
        } else {
            0
        };

        // Skip if not enough confirmations
        if confirmations < REQUIRED_BTC_CONFIRMATIONS as u32 {
            continue;
        }

        // Check if this UTXO was already processed
        let utxo_key = (utxo.outpoint.txid.clone(), utxo.outpoint.vout);
        {
            let state = STATE.read().unwrap();
            if state.processed_utxos.contains_key(&utxo_key) {
                continue;
            }
        }

        // If a specific txid was provided, only process matching UTXOs
        if let Some(ref expected_txid) = request.txid {
            if utxo.outpoint.txid.as_slice() != expected_txid.as_slice() {
                continue;
            }
        }

        // Credit this UTXO to the caller
        let amount = utxo.value;
        {
            let mut state = STATE.write().unwrap();
            state.liq_pool.deposit(caller, PoolAsset::BTC, Nat::from(amount));
            state.processed_utxos.insert(utxo_key, caller);
        }

        total_credited += amount;
    }

    // Get updated balance
    let new_btc_balance = {
        let state = STATE.read().unwrap();
        state.liq_pool.get_balance(&caller, &PoolAsset::BTC)
    };

    if total_credited > 0 {
        LpBtcDepositResponse {
            success: true,
            credited_amount: Nat::from(total_credited),
            new_btc_balance,
            error: None,
        }
    } else {
        LpBtcDepositResponse {
            success: false,
            credited_amount: Nat::from(0u64),
            new_btc_balance,
            error: Some(format!(
                "No new deposits found with {} confirmations. Send BTC to {} first.",
                REQUIRED_BTC_CONFIRMATIONS, lp_address
            )),
        }
    }
}

/// Withdraw BTC from the liquidity pool
///
/// Sends BTC from the shared LP address to the user's destination address.
/// The caller's LP BTC balance must be sufficient for the withdrawal.
pub async fn withdraw_btc_impl(request: LpBtcWithdrawRequest) -> LpBtcWithdrawResponse {
    let caller = msg_caller();

    if request.amount_sat == 0 {
        return LpBtcWithdrawResponse {
            success: false,
            amount_withdrawn: Nat::from(0u64),
            new_btc_balance: Nat::from(0u64),
            txid: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    let amount_nat = Nat::from(request.amount_sat);

    // Check and deduct from LP balance
    {
        let mut state = STATE.write().unwrap();
        if let Err(e) = state.liq_pool.withdraw(caller, PoolAsset::BTC, amount_nat.clone()) {
            let current_balance = state.liq_pool.get_balance(&caller, &PoolAsset::BTC);
            return LpBtcWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_btc_balance: current_balance,
                txid: None,
                error: Some(format!("Insufficient BTC balance: {:?}", e)),
            };
        }
    }

    // Send BTC to the destination address
    // We use P2WPKH for the shared LP address
    let send_result = send_btc_from_lp_address(
        request.destination_address.clone(),
        request.amount_sat,
    )
    .await;

    match send_result {
        Ok(txid) => {
            let new_btc_balance = {
                let state = STATE.read().unwrap();
                state.liq_pool.get_balance(&caller, &PoolAsset::BTC)
            };

            LpBtcWithdrawResponse {
                success: true,
                amount_withdrawn: amount_nat,
                new_btc_balance,
                txid: Some(txid),
                error: None,
            }
        }
        Err(e) => {
            // Restore the LP balance on failure
            {
                let mut state = STATE.write().unwrap();
                state.liq_pool.deposit(caller, PoolAsset::BTC, amount_nat.clone());
            }

            let new_btc_balance = {
                let state = STATE.read().unwrap();
                state.liq_pool.get_balance(&caller, &PoolAsset::BTC)
            };

            LpBtcWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_btc_balance,
                txid: None,
                error: Some(format!("BTC send failed: {:?}", e)),
            }
        }
    }
}

// =============================================================================
// User BTC Operations (from depositor address)
// =============================================================================

/// Get the caller's BTC balance at their depositor address
pub async fn get_depositor_btc_balance_impl() -> DepositorBtcBalanceResponse {
    let caller = msg_caller();

    // Get or derive the caller's depositor address
    let address = {
        let state = STATE.read().unwrap();
        state.btc_liquidity_addresses.get(&caller).cloned()
    };

    let address = match address {
        Some(addr) => addr,
        None => {
            // Derive the address if not yet stored
            let purpose = BtcPurpose::LiquidityDepositor(caller);
            match get_segwit_address(purpose).await {
                Ok(addr) => {
                    // Store it for future use
                    let mut state = STATE.write().unwrap();
                    state.btc_liquidity_addresses.insert(caller, addr.clone());
                    addr
                }
                Err(e) => {
                    return DepositorBtcBalanceResponse {
                        address: String::new(),
                        balance_sat: 0,
                        error: Some(format!("Failed to derive address: {:?}", e)),
                    };
                }
            }
        }
    };

    // Get balance from Bitcoin canister
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());
    let balance = match bitcoin_get_balance(&GetBalanceRequest {
        address: address.clone(),
        network: ctx.network,
        min_confirmations: Some(1),
    })
    .await
    {
        Ok(bal) => bal,
        Err(e) => {
            return DepositorBtcBalanceResponse {
                address,
                balance_sat: 0,
                error: Some(format!("Failed to get balance: {:?}", e)),
            };
        }
    };

    DepositorBtcBalanceResponse {
        address,
        balance_sat: balance,
        error: None,
    }
}

/// Send BTC from the caller's depositor address to a destination
pub async fn send_btc_from_depositor_address_impl(
    request: SendFromDepositorRequest,
) -> SendFromDepositorResponse {
    let caller = msg_caller();
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    if request.amount_sat == 0 {
        return SendFromDepositorResponse {
            success: false,
            txid: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Parse and validate destination address
    let dst_address = match Address::from_str(&request.destination_address) {
        Ok(addr) => match addr.require_network(ctx.bitcoin_network) {
            Ok(a) => a,
            Err(e) => {
                return SendFromDepositorResponse {
                    success: false,
                    txid: None,
                    error: Some(format!("Address network mismatch: {:?}", e)),
                };
            }
        },
        Err(e) => {
            return SendFromDepositorResponse {
                success: false,
                txid: None,
                error: Some(format!("Invalid destination address: {}", e)),
            };
        }
    };

    // Get derivation path for caller's depositor address
    let purpose = BtcPurpose::LiquidityDepositor(caller);
    let derivation_path = purpose.derivation_path();

    // Get our public key
    let public_key_bytes = get_ecdsa_public_key(&ctx, derivation_path.clone()).await;
    let compressed_key = match CompressedPublicKey::from_slice(&public_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return SendFromDepositorResponse {
                success: false,
                txid: None,
                error: Some(format!("Failed to parse public key: {}", e)),
            };
        }
    };
    let public_key = match PublicKey::from_slice(&public_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return SendFromDepositorResponse {
                success: false,
                txid: None,
                error: Some(format!("Failed to parse public key: {}", e)),
            };
        }
    };

    // Generate our address (P2WPKH)
    let own_address = Address::p2wpkh(&compressed_key, ctx.bitcoin_network);

    // Fetch UTXOs
    let own_utxos = match bitcoin_get_utxos(&GetUtxosRequest {
        address: own_address.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    {
        Ok(resp) => resp.utxos,
        Err(e) => {
            return SendFromDepositorResponse {
                success: false,
                txid: None,
                error: Some(format!("Failed to fetch UTXOs: {:?}", e)),
            };
        }
    };

    // Check we have enough funds
    let total_available: u64 = own_utxos.iter().map(|u| u.value).sum();
    if total_available < request.amount_sat {
        return SendFromDepositorResponse {
            success: false,
            txid: None,
            error: Some(format!(
                "Insufficient BTC: available {} sats, requested {} sats",
                total_available, request.amount_sat
            )),
        };
    }

    // Get fee rate
    let fee_per_byte = get_fee_per_byte(&ctx).await;

    // Build transaction with prevouts (for P2WPKH)
    let (transaction, prevouts) = p2wpkh::build_transaction(
        &ctx,
        &public_key,
        &own_address,
        &own_utxos,
        &dst_address,
        request.amount_sat,
        fee_per_byte,
    )
    .await;

    // Sign transaction
    let signed_tx = p2wpkh::sign_transaction(
        &ctx,
        &public_key,
        &own_address,
        transaction,
        &prevouts,
        derivation_path,
        sign_with_ecdsa,
    )
    .await;

    // Send transaction
    match bitcoin_send_transaction(&SendTransactionRequest {
        network: ctx.network,
        transaction: serialize(&signed_tx),
    })
    .await
    {
        Ok(_) => SendFromDepositorResponse {
            success: true,
            txid: Some(signed_tx.compute_txid().to_string()),
            error: None,
        },
        Err(e) => SendFromDepositorResponse {
            success: false,
            txid: None,
            error: Some(format!("Failed to send transaction: {:?}", e)),
        },
    }
}

/// Fund a Lightning channel from LP BTC
/// Builds and signs a transaction but does NOT broadcast it
/// The relay passes this to LDK which handles the broadcast timing
pub async fn fund_channel_impl(request: FundChannelRequest) -> FundChannelResponse {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    if request.amount_sat == 0 {
        return FundChannelResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Parse and validate funding address
    let funding_address = match Address::from_str(&request.funding_address) {
        Ok(addr) => match addr.require_network(ctx.bitcoin_network) {
            Ok(a) => a,
            Err(e) => {
                return FundChannelResponse {
                    success: false,
                    signed_tx: None,
                    txid: None,
                    error: Some(format!("Funding address network mismatch: {:?}", e)),
                };
            }
        },
        Err(e) => {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Invalid funding address: {}", e)),
            };
        }
    };

    // Get the derivation path for the shared LP address
    let purpose = BtcPurpose::LiquidityPoolShared;
    let derivation_path = purpose.derivation_path();

    // Get our public key
    let public_key_bytes = get_ecdsa_public_key(&ctx, derivation_path.clone()).await;
    let compressed_key = match CompressedPublicKey::from_slice(&public_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to parse public key: {}", e)),
            };
        }
    };
    let public_key = match PublicKey::from_slice(&public_key_bytes) {
        Ok(k) => k,
        Err(e) => {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to parse public key: {}", e)),
            };
        }
    };

    // Generate our address (P2WPKH)
    let own_address = Address::p2wpkh(&compressed_key, ctx.bitcoin_network);

    // Fetch UTXOs
    let own_utxos = match bitcoin_get_utxos(&GetUtxosRequest {
        address: own_address.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    {
        Ok(response) => response.utxos,
        Err(e) => {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to fetch UTXOs: {:?}", e)),
            };
        }
    };

    // Check we have enough funds (with some margin for fees)
    let total_available: u64 = own_utxos.iter().map(|u| u.value).sum();
    let fee_margin = 5000u64; // 5000 sats buffer for fees
    if total_available < request.amount_sat + fee_margin {
        return FundChannelResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some(format!(
                "Insufficient BTC in LP: available {} sats, requested {} sats (+ ~{} fees)",
                total_available, request.amount_sat, fee_margin
            )),
        };
    }

    // Get fee rate
    let fee_per_byte = get_fee_per_byte(&ctx).await;

    // Build transaction with prevouts (for P2WPKH)
    let (transaction, prevouts) = p2wpkh::build_transaction(
        &ctx,
        &public_key,
        &own_address,
        &own_utxos,
        &funding_address,
        request.amount_sat,
        fee_per_byte,
    )
    .await;

    // Sign transaction
    let signed_tx = p2wpkh::sign_transaction(
        &ctx,
        &public_key,
        &own_address,
        transaction,
        &prevouts,
        derivation_path,
        sign_with_ecdsa,
    )
    .await;

    // Serialize the transaction for return
    let tx_bytes = serialize(&signed_tx);
    let txid = signed_tx.compute_txid().to_string();

    // Track the funding in canister state
    {
        let mut state = STATE.write().unwrap();
        // Deduct from total LP BTC (it will go into channel)
        state.total_btc_in_channels = state.total_btc_in_channels.saturating_add(request.amount_sat);
    }

    FundChannelResponse {
        success: true,
        signed_tx: Some(tx_bytes),
        txid: Some(txid),
        error: None,
    }
}

// =============================================================================
// LP Liquidity Management (Canister-Controlled BTC for Lightning)
// =============================================================================

/// Get available UTXOs from the LP's BTC address for channel funding
pub async fn get_funding_utxos_impl(min_amount_sats: u64) -> Result<GetFundingUtxosResponse, BtcError> {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Get the LP BTC address
    let lp_address = {
        let state = STATE.read().unwrap();
        state.lp_btc_address.clone()
    };

    let lp_address = match lp_address {
        Some(addr) => addr,
        None => {
            return Ok(GetFundingUtxosResponse {
                utxos: vec![],
                total_sats: 0,
                lp_address: None,
            });
        }
    };

    // Parse address
    let address = Address::from_str(&lp_address)
        .map_err(|e| BtcError::Other(format!("Invalid LP address: {}", e)))?
        .require_network(ctx.bitcoin_network)
        .map_err(|e| BtcError::Other(format!("LP address network mismatch: {:?}", e)))?;

    // Fetch UTXOs from Bitcoin canister
    let utxo_response = bitcoin_get_utxos(&GetUtxosRequest {
        address: lp_address.clone(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to get UTXOs: {:?}", e)))?;

    // Get reserved UTXOs to exclude
    let reserved = {
        let state = STATE.read().unwrap();
        state.reserved_utxos.clone()
    };

    // Filter out reserved UTXOs and convert to our type
    let mut available_utxos = Vec::new();
    let mut total_sats = 0u64;

    for utxo in utxo_response.utxos {
        let key = (utxo.outpoint.txid.clone(), utxo.outpoint.vout);
        if !reserved.contains_key(&key) {
            total_sats += utxo.value;
            available_utxos.push(LpBtcUtxo {
                txid: utxo.outpoint.txid,
                vout: utxo.outpoint.vout,
                value_sats: utxo.value,
                height: utxo.height,
            });
        }
    }

    // Sort by value descending (prefer larger UTXOs)
    available_utxos.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));

    Ok(GetFundingUtxosResponse {
        utxos: available_utxos,
        total_sats,
        lp_address: Some(lp_address),
    })
}

/// Update channel balance after payment activity
pub fn update_channel_balance_impl(request: UpdateChannelBalanceRequest) -> UpdateChannelBalanceResponse {
    let channel_id: [u8; 32] = match request.channel_id.try_into() {
        Ok(id) => id,
        Err(_) => {
            return UpdateChannelBalanceResponse {
                success: false,
                error: Some("Invalid channel_id length".to_string()),
            };
        }
    };

    let mut state = STATE.write().unwrap();

    // Check if channel exists and get capacity for potential new entry
    let channel_capacity = match state.ln_channels.get(&channel_id) {
        Some(info) => info.capacity_sats,
        None => {
            return UpdateChannelBalanceResponse {
                success: false,
                error: Some("Channel not registered".to_string()),
            };
        }
    };

    // Update or insert channel balance
    let balance = state.channel_balances.entry(channel_id).or_insert_with(|| {
        LnChannelBalance {
            channel_id: channel_id.to_vec(),
            capacity_sats: channel_capacity,
            our_balance_sats: channel_capacity, // Initially we funded it
            their_balance_sats: 0,
            is_active: true,
            last_updated: blocktime(),
        }
    });

    balance.our_balance_sats = request.our_balance_sats;
    balance.their_balance_sats = request.their_balance_sats;
    balance.last_updated = blocktime();

    UpdateChannelBalanceResponse {
        success: true,
        error: None,
    }
}

/// Get overall LP liquidity status
pub async fn get_lp_liquidity_status_impl() -> Result<LpLiquidityStatus, BtcError> {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Get on-chain BTC balance
    let (lp_address, channel_balances, total_btc_deposited, total_btc_in_channels) = {
        let state = STATE.read().unwrap();
        (
            state.lp_btc_address.clone(),
            state.channel_balances.clone(),
            state.total_btc_deposited,
            state.total_btc_in_channels,
        )
    };

    // Get on-chain UTXOs
    let (btc_onchain_sats, btc_utxo_count) = if let Some(addr) = &lp_address {
        let utxo_response = bitcoin_get_utxos(&GetUtxosRequest {
            address: addr.clone(),
            network: ctx.network,
            filter: None,
        })
        .await
        .map_err(|e| BtcError::Other(format!("Failed to get UTXOs: {:?}", e)))?;

        let total: u64 = utxo_response.utxos.iter().map(|u| u.value).sum();
        (total, utxo_response.utxos.len() as u32)
    } else {
        (0, 0)
    };

    // Calculate channel liquidity
    let mut channel_total_capacity_sats = 0u64;
    let mut channel_outbound_sats = 0u64;
    let mut channel_inbound_sats = 0u64;
    let mut channel_count = 0u32;

    for balance in channel_balances.values() {
        if balance.is_active {
            channel_total_capacity_sats += balance.capacity_sats;
            channel_outbound_sats += balance.our_balance_sats;
            channel_inbound_sats += balance.their_balance_sats;
            channel_count += 1;
        }
    }

    // Get ckBTC pool balance from liquidity pool
    let ckbtc_pool_sats = {
        let state = STATE.read().unwrap();
        state.liq_pool.get_total(&PoolAsset::CkBTC).0.try_into().unwrap_or(0)
    };

    Ok(LpLiquidityStatus {
        ckbtc_pool_sats,
        btc_onchain_sats,
        btc_utxo_count,
        channel_total_capacity_sats,
        channel_outbound_sats,
        channel_inbound_sats,
        channel_count,
        total_btc_deposited,
        total_btc_in_channels,
    })
}

/// Reserve UTXOs for a pending channel open
pub fn reserve_utxos_for_channel_impl(utxos: &[LpBtcUtxo], channel_id: [u8; 32]) {
    let mut state = STATE.write().unwrap();
    for utxo in utxos {
        let key = (utxo.txid.clone(), utxo.vout);
        state.reserved_utxos.insert(key, channel_id);
    }
}

/// Release reserved UTXOs (on channel open failure)
pub fn release_reserved_utxos_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().unwrap();
    state.reserved_utxos.retain(|_, v| *v != channel_id);
}

/// Called when a channel is successfully funded - update tracking
pub fn channel_funded_impl(channel_id: [u8; 32], capacity_sats: u64) {
    let mut state = STATE.write().unwrap();

    // Remove from reserved UTXOs
    state.reserved_utxos.retain(|_, v| *v != channel_id);

    // Update total BTC in channels
    state.total_btc_in_channels += capacity_sats;

    // Initialize channel balance
    state.channel_balances.insert(channel_id, LnChannelBalance {
        channel_id: channel_id.to_vec(),
        capacity_sats,
        our_balance_sats: capacity_sats, // We funded it, so initially all ours
        their_balance_sats: 0,
        is_active: true,
        last_updated: blocktime(),
    });
}

/// Called when a channel is closed - update tracking
pub fn channel_closed_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().unwrap();

    if let Some(balance) = state.channel_balances.get_mut(&channel_id) {
        balance.is_active = false;
        // Note: total_btc_in_channels should be reduced when we receive the closing tx funds
    }
}

// =============================================================================
// HTLC State Management
// =============================================================================

/// Create a new HTLC
///
/// Called by the relay when an HTLC is added to a commitment transaction.
/// The canister tracks the HTLC state for later fulfillment or timeout.
pub fn create_htlc_impl(request: CreateHtlcRequest) -> CreateHtlcResponse {
    let payment_hash: [u8; 32] = match request.payment_hash.try_into() {
        Ok(h) => h,
        Err(_) => {
            return CreateHtlcResponse {
                success: false,
                error: Some("Invalid payment_hash length (expected 32 bytes)".to_string()),
            }
        }
    };

    if request.sender_pubkey.len() != 33 {
        return CreateHtlcResponse {
            success: false,
            error: Some("Invalid sender_pubkey length (expected 33 bytes)".to_string()),
        };
    }

    if request.receiver_pubkey.len() != 33 {
        return CreateHtlcResponse {
            success: false,
            error: Some("Invalid receiver_pubkey length (expected 33 bytes)".to_string()),
        };
    }

    let mut state = STATE.write().unwrap();
    match state.htlc_manager.add_htlc(
        payment_hash,
        request.amount_msat,
        request.cltv_expiry,
        request.sender_pubkey,
        request.receiver_pubkey,
    ) {
        Ok(()) => CreateHtlcResponse {
            success: true,
            error: None,
        },
        Err(e) => CreateHtlcResponse {
            success: false,
            error: Some(e),
        },
    }
}

/// Fulfill an HTLC by revealing the preimage
///
/// Called by the relay when a preimage is received (payment successful).
/// Returns the payment_hash and amount for confirmation.
pub fn fulfill_htlc_impl(request: FulfillHtlcRequest) -> FulfillHtlcResponse {
    let mut state = STATE.write().unwrap();
    match state.htlc_manager.fulfill_htlc(request.preimage) {
        Ok((payment_hash, amount_msat)) => FulfillHtlcResponse {
            success: true,
            payment_hash: Some(payment_hash.to_vec()),
            amount_msat: Some(amount_msat),
            error: None,
        },
        Err(e) => FulfillHtlcResponse {
            success: false,
            payment_hash: None,
            amount_msat: None,
            error: Some(e),
        },
    }
}

/// Timeout an HTLC after CLTV expiry
///
/// Called by the relay when an HTLC has expired without being fulfilled.
/// The sender can reclaim the funds.
pub fn timeout_htlc_impl(request: TimeoutHtlcRequest) -> TimeoutHtlcResponse {
    let payment_hash: [u8; 32] = match request.payment_hash.try_into() {
        Ok(h) => h,
        Err(_) => {
            return TimeoutHtlcResponse {
                success: false,
                amount_msat: None,
                error: Some("Invalid payment_hash length (expected 32 bytes)".to_string()),
            }
        }
    };

    let mut state = STATE.write().unwrap();
    match state.htlc_manager.timeout_htlc(&payment_hash) {
        Ok(amount_msat) => TimeoutHtlcResponse {
            success: true,
            amount_msat: Some(amount_msat),
            error: None,
        },
        Err(e) => TimeoutHtlcResponse {
            success: false,
            amount_msat: None,
            error: Some(e),
        },
    }
}

/// Get an HTLC by payment hash
pub fn get_htlc_impl(payment_hash: Vec<u8>) -> Option<HtlcInfo> {
    let payment_hash: [u8; 32] = payment_hash.try_into().ok()?;
    let state = STATE.read().unwrap();
    state.htlc_manager.get_htlc(&payment_hash).map(|htlc| HtlcInfo {
        payment_hash: htlc.payment_hash.to_vec(),
        amount_msat: htlc.amount_msat,
        cltv_expiry: htlc.cltv_expiry,
        state: format!("{:?}", htlc.state),
        sender_pubkey: htlc.sender_pubkey.clone(),
        receiver_pubkey: htlc.receiver_pubkey.clone(),
    })
}

/// Get all pending HTLCs
pub fn get_pending_htlcs_impl() -> Vec<HtlcInfo> {
    let state = STATE.read().unwrap();
    state
        .htlc_manager
        .pending_htlcs()
        .iter()
        .map(|htlc| HtlcInfo {
            payment_hash: htlc.payment_hash.to_vec(),
            amount_msat: htlc.amount_msat,
            cltv_expiry: htlc.cltv_expiry,
            state: format!("{:?}", htlc.state),
            sender_pubkey: htlc.sender_pubkey.clone(),
            receiver_pubkey: htlc.receiver_pubkey.clone(),
        })
        .collect()
}

// =============================================================================
// Channel Secrets Management (Phase 2)
// =============================================================================

/// Register channel secrets for a Lightning channel.
///
/// Called by the relay when a channel is opened. Stores the secrets in canister
/// state for later use in HTLC signing operations.
///
/// Security note: These secrets are stored in canister memory, which is readable
/// by subnet nodes. This is an accepted tradeoff per HTLC_SECRET_IMPL.md.
pub fn register_channel_secrets_impl(
    request: RegisterChannelSecretsRequest,
) -> RegisterChannelSecretsResponse {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secrets = &request.secrets;

    // Validate lengths
    if secrets.channel_id.len() != 32 {
        return RegisterChannelSecretsResponse {
            success: false,
            htlc_basepoint: None,
            revocation_basepoint: None,
            delayed_payment_basepoint: None,
            payment_point: None,
            error: Some("channel_id must be 32 bytes".to_string()),
        };
    }
    if secrets.htlc_base_secret.len() != 32
        || secrets.revocation_base_secret.len() != 32
        || secrets.delayed_payment_base_secret.len() != 32
        || secrets.payment_secret.len() != 32
        || secrets.commitment_seed.len() != 32
    {
        return RegisterChannelSecretsResponse {
            success: false,
            htlc_basepoint: None,
            revocation_basepoint: None,
            delayed_payment_basepoint: None,
            payment_point: None,
            error: Some("All secrets must be 32 bytes".to_string()),
        };
    }

    // Convert to fixed arrays
    let channel_id: [u8; 32] = secrets.channel_id.clone().try_into().unwrap();
    let htlc_base_secret: [u8; 32] = secrets.htlc_base_secret.clone().try_into().unwrap();
    let revocation_base_secret: [u8; 32] = secrets.revocation_base_secret.clone().try_into().unwrap();
    let delayed_payment_base_secret: [u8; 32] = secrets.delayed_payment_base_secret.clone().try_into().unwrap();
    let payment_secret: [u8; 32] = secrets.payment_secret.clone().try_into().unwrap();
    let commitment_seed: [u8; 32] = secrets.commitment_seed.clone().try_into().unwrap();

    // Derive public keys from secrets
    let secp = Secp256k1::new();

    let htlc_basepoint = match SecretKey::from_slice(&htlc_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid htlc_base_secret".to_string()),
            };
        }
    };

    let revocation_basepoint = match SecretKey::from_slice(&revocation_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid revocation_base_secret".to_string()),
            };
        }
    };

    let delayed_payment_basepoint = match SecretKey::from_slice(&delayed_payment_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid delayed_payment_base_secret".to_string()),
            };
        }
    };

    let payment_point = match SecretKey::from_slice(&payment_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid payment_secret".to_string()),
            };
        }
    };

    // Store in canister state
    let internal_secrets = ChannelSecretsInternal {
        htlc_base_secret,
        revocation_base_secret,
        delayed_payment_base_secret,
        payment_secret,
        commitment_seed,
    };

    let mut state = STATE.write().unwrap();
    state.channel_secrets.insert(channel_id, internal_secrets);

    RegisterChannelSecretsResponse {
        success: true,
        htlc_basepoint: Some(htlc_basepoint),
        revocation_basepoint: Some(revocation_basepoint),
        delayed_payment_basepoint: Some(delayed_payment_basepoint),
        payment_point: Some(payment_point),
        error: None,
    }
}

/// Query channel secrets info (public keys only, secrets are never exposed).
pub fn get_channel_secrets_info_impl(channel_id: Vec<u8>) -> Option<ChannelSecretsInfo> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let channel_id: [u8; 32] = channel_id.try_into().ok()?;
    let state = STATE.read().unwrap();
    let secrets = state.channel_secrets.get(&channel_id)?;

    let secp = Secp256k1::new();

    let htlc_basepoint = SecretKey::from_slice(&secrets.htlc_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let revocation_basepoint = SecretKey::from_slice(&secrets.revocation_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let delayed_payment_basepoint = SecretKey::from_slice(&secrets.delayed_payment_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let payment_point = SecretKey::from_slice(&secrets.payment_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    Some(ChannelSecretsInfo {
        channel_id: channel_id.to_vec(),
        has_secrets: true,
        htlc_basepoint,
        revocation_basepoint,
        delayed_payment_basepoint,
        payment_point,
    })
}

// =============================================================================
// HTLC with Transaction Details (Phase 2)
// =============================================================================

/// Create an HTLC with full transaction details for later signing.
///
/// This stores all information needed to construct and sign HTLC-Success
/// and HTLC-Timeout transactions without requiring the relay to provide
/// details again at signing time.
pub fn create_htlc_with_tx_details_impl(
    request: CreateHtlcWithTxDetailsRequest,
) -> CreateHtlcWithTxDetailsResponse {
    use bitcoin::secp256k1::PublicKey;

    // Validate payment_hash
    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    // Validate channel_id
    let channel_id: [u8; 32] = match request.channel_id.clone().try_into() {
        Ok(c) => c,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("channel_id must be 32 bytes".to_string()),
            };
        }
    };

    // Validate outpoint txid
    let htlc_outpoint_txid: [u8; 32] = match request.htlc_outpoint_txid.clone().try_into() {
        Ok(t) => t,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("htlc_outpoint_txid must be 32 bytes".to_string()),
            };
        }
    };

    // Validate per_commitment_point
    let per_commitment_point: [u8; 33] = match request.per_commitment_point.clone().try_into() {
        Ok(p) => p,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("per_commitment_point must be 33 bytes".to_string()),
            };
        }
    };

    // Parse public keys
    let sender_pubkey = match PublicKey::from_slice(&request.sender_pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("Invalid sender_pubkey".to_string()),
            };
        }
    };

    let receiver_pubkey = match PublicKey::from_slice(&request.receiver_pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("Invalid receiver_pubkey".to_string()),
            };
        }
    };

    // Build the witness script
    let witness_script = build_htlc_witness_script(
        &payment_hash,
        &receiver_pubkey,
        &sender_pubkey,
        request.cltv_expiry,
    );

    // Store HTLC in HtlcManager
    let mut state = STATE.write().unwrap();

    if let Err(e) = state.htlc_manager.add_htlc(
        payment_hash,
        request.amount_msat,
        request.cltv_expiry,
        request.sender_pubkey.clone(),
        request.receiver_pubkey.clone(),
    ) {
        return CreateHtlcWithTxDetailsResponse {
            success: false,
            witness_script: None,
            error: Some(e),
        };
    }

    // Store transaction details for signing
    let tx_details = HtlcTxDetails {
        channel_id,
        htlc_outpoint_txid,
        htlc_outpoint_vout: request.htlc_outpoint_vout,
        htlc_amount_sat: request.htlc_amount_sat,
        receiver_address: request.receiver_address,
        sender_address: request.sender_address,
        per_commitment_point,
        witness_script: witness_script.as_bytes().to_vec(),
    };

    state.htlc_tx_details.insert(payment_hash, tx_details);

    CreateHtlcWithTxDetailsResponse {
        success: true,
        witness_script: Some(witness_script.as_bytes().to_vec()),
        error: None,
    }
}

// =============================================================================
// HTLC Signing (Phase 2)
// =============================================================================

/// Sign an HTLC-Success transaction (receiver claims with preimage).
///
/// This builds the HTLC-Success transaction, signs it with the HTLC key,
/// and returns the fully signed transaction ready for broadcast.
pub fn sign_htlc_success_impl(request: SignHtlcSuccessRequest) -> SignHtlcResponse {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{OutPoint, ScriptBuf, Txid};

    // Validate preimage and compute payment hash
    if request.preimage.len() != 32 {
        return SignHtlcResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some("preimage must be 32 bytes".to_string()),
        };
    }

    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    // Verify preimage matches payment hash
    if !verify_preimage(&request.preimage, &payment_hash) {
        return SignHtlcResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some("preimage does not match payment_hash".to_string()),
        };
    }

    let state = STATE.read().unwrap();

    // Get HTLC transaction details
    let tx_details = match state.htlc_tx_details.get(&payment_hash) {
        Some(d) => d.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC transaction details not found".to_string()),
            };
        }
    };

    // Get HTLC info
    let htlc = match state.htlc_manager.get_htlc(&payment_hash) {
        Some(h) => h.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC not found".to_string()),
            };
        }
    };

    // Get channel secrets
    let secrets = match state.channel_secrets.get(&tx_details.channel_id) {
        Some(s) => s.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    drop(state); // Release lock

    // Parse receiver address
    let receiver_address: Address<bitcoin::address::NetworkUnchecked> =
        match tx_details.receiver_address.parse() {
            Ok(a) => a,
            Err(_) => {
                return SignHtlcResponse {
                    success: false,
                    signed_tx: None,
                    txid: None,
                    error: Some("Invalid receiver address".to_string()),
                };
            }
        };
    let receiver_address = receiver_address.assume_checked();

    // Build HTLC outpoint
    let txid_bytes: [u8; 32] = tx_details.htlc_outpoint_txid;
    let txid = Txid::from_byte_array(txid_bytes);
    let htlc_outpoint = OutPoint {
        txid,
        vout: tx_details.htlc_outpoint_vout,
    };

    // Build HTLC-Success transaction
    let mut tx = build_htlc_success_tx(
        htlc_outpoint,
        tx_details.htlc_amount_sat,
        &receiver_address,
        request.fee_sat,
    );

    // Get the witness script
    let witness_script = ScriptBuf::from_bytes(tx_details.witness_script.clone());

    // Sign the transaction
    // Note: For BOLT-3 we would derive: htlc_key = htlc_base_secret + SHA256(per_commitment_point || htlc_basepoint)
    // For simplicity, we use htlc_base_secret directly here. Full BOLT-3 derivation would require
    // implementing the key derivation formula.
    let htlc_secret_key = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Invalid HTLC secret key".to_string()),
            };
        }
    };

    let signature = match sign_htlc_input(
        &tx,
        0, // input index
        &witness_script,
        tx_details.htlc_amount_sat,
        &htlc_secret_key,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to sign: {}", e)),
            };
        }
    };

    // Apply the success witness
    apply_htlc_success_witness(&mut tx, 0, signature, request.preimage, &witness_script);

    // Serialize the signed transaction
    let signed_tx = serialize(&tx);
    let result_txid = tx.compute_txid().to_byte_array().to_vec();

    SignHtlcResponse {
        success: true,
        signed_tx: Some(signed_tx),
        txid: Some(result_txid),
        error: None,
    }
}

/// Sign an HTLC-Timeout transaction (sender reclaims after expiry).
///
/// This builds the HTLC-Timeout transaction, signs it with the HTLC key,
/// and returns the fully signed transaction ready for broadcast.
pub fn sign_htlc_timeout_impl(request: SignHtlcTimeoutRequest) -> SignHtlcResponse {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{OutPoint, ScriptBuf, Txid};

    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    let state = STATE.read().unwrap();

    // Get HTLC transaction details
    let tx_details = match state.htlc_tx_details.get(&payment_hash) {
        Some(d) => d.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC transaction details not found".to_string()),
            };
        }
    };

    // Get HTLC info
    let htlc = match state.htlc_manager.get_htlc(&payment_hash) {
        Some(h) => h.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC not found".to_string()),
            };
        }
    };

    // Get channel secrets
    let secrets = match state.channel_secrets.get(&tx_details.channel_id) {
        Some(s) => s.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    drop(state); // Release lock

    // Parse sender address
    let sender_address: Address<bitcoin::address::NetworkUnchecked> =
        match tx_details.sender_address.parse() {
            Ok(a) => a,
            Err(_) => {
                return SignHtlcResponse {
                    success: false,
                    signed_tx: None,
                    txid: None,
                    error: Some("Invalid sender address".to_string()),
                };
            }
        };
    let sender_address = sender_address.assume_checked();

    // Build HTLC outpoint
    let txid_bytes: [u8; 32] = tx_details.htlc_outpoint_txid;
    let txid = Txid::from_byte_array(txid_bytes);
    let htlc_outpoint = OutPoint {
        txid,
        vout: tx_details.htlc_outpoint_vout,
    };

    // Build HTLC-Timeout transaction
    let mut tx = build_htlc_timeout_tx(
        htlc_outpoint,
        tx_details.htlc_amount_sat,
        &sender_address,
        htlc.cltv_expiry,
        request.fee_sat,
    );

    // Get the witness script
    let witness_script = ScriptBuf::from_bytes(tx_details.witness_script.clone());

    // Sign the transaction
    let htlc_secret_key = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Invalid HTLC secret key".to_string()),
            };
        }
    };

    let signature = match sign_htlc_input(
        &tx,
        0, // input index
        &witness_script,
        tx_details.htlc_amount_sat,
        &htlc_secret_key,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to sign: {}", e)),
            };
        }
    };

    // Apply the timeout witness
    apply_htlc_timeout_witness(&mut tx, 0, signature, &witness_script);

    // Serialize the signed transaction
    let signed_tx = serialize(&tx);
    let result_txid = tx.compute_txid().to_byte_array().to_vec();

    SignHtlcResponse {
        success: true,
        signed_tx: Some(signed_tx),
        txid: Some(result_txid),
        error: None,
    }
}
