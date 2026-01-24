//  Copyright 2025 PolyCrypt GmbH
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
use crate::canister_state::set_btc_liquidity_address_impl;
use crate::canister_state::{
    complete_swap_impl, deposit_channel_impl, deposit_lp_impl, get_btc_balances_impl,
    get_btc_liquidity_address_for_caller_impl, get_ln_address_impl, get_ln_funding_pubkey_impl,
    get_ln_invoice_impl, query_ln_channel_impl, query_ln_channels_impl, query_state_impl,
    query_user_lp_holdings_impl, register_ln_channel_impl, register_swap_impl, send_btc_tx_impl,
    set_btc_address_impl, sign_ln_message_impl, transaction_notification_impl,
    trigger_withdraw_impl, verify_ln_channel_impl, withdraw_lp_impl,
    // New simplified LP functions
    deposit_ckbtc_impl, withdraw_ckbtc_impl, get_my_lp_balance_impl, get_total_lp_balance_impl,
};
use crate::ic_types::{LpBalanceResponse, LpDepositResponse, LpWithdrawResponse, TotalLpBalanceResponse};
use crate::error::{BtcError, CklError};
use crate::ic_types::LnInvoiceRequest;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::SignedCandidInvoice;
use crate::ic_types::{
    BtcPurpose, ChannelFunding, ChannelId, CompleteSwapRequest, CompleteSwapResponse,
    DEVNET_CKBTC_LEDGER, FundingLPArgs, FundingLPQueryArgs, GetBtcBalancesResponse,
    HoldingsResponse, LnChannelInfo, LnFundingPubkeyResponse, LnSignRequest, LnSignResponse,
    NotifyArgs, QueryBtcAddressResponse, QueryLnChannelRequest, QueryLnChannelsResponse,
    RegisterLnChannelRequest, RegisterLnChannelResponse, RegisterSwapRequest, RegisterSwapResponse,
    RegisteredState, SendBtcTxArgs, SendBtcTxMsg, SetBtcAddressArgs, SetBtcAddressResponse,
    VerifyLnChannelResponse, WithdrawalLPArgs, WithdrawalReq,
};
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use candid::{Nat, Principal, candid_method};
use ic_cdk::api::call::CallResult;
use ic_cdk::query;
use ic_cdk::update;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

#[update]
#[candid_method(update)]
async fn send_btc_tx(args: SendBtcTxArgs) -> std::result::Result<SendBtcTxMsg, BtcError> {
    let recipient = args.recipient;
    let from_address_type = args.from_address_type;
    let amount = args.amount;

    send_btc_tx_impl(recipient, from_address_type, amount).await
}

#[update]
#[candid_method(update)]
async fn get_ln_address() -> std::result::Result<String, BtcError> {
    get_ln_address_impl().await
}

#[update]
#[candid_method(update)]
async fn query_ln_invoice(
    invoice_req: LnInvoiceRequest,
) -> std::result::Result<SignedCandidInvoice, BtcError> {
    get_ln_invoice_impl(invoice_req).await
}

#[update]
#[candid_method(update)]
async fn get_btc_liquidity_address_for_caller() -> std::result::Result<String, BtcError> {
    get_btc_liquidity_address_for_caller_impl().await
}

#[update]
#[candid_method(update)]
async fn set_btc_liquidity_address() -> Result<SetLiquidityBtcAddressResponse, BtcError> {
    set_btc_liquidity_address_impl().await
}

#[update]
#[candid_method(update)]
async fn get_btc_balance(
    confirmations: Option<u64>,
) -> std::result::Result<GetBtcBalancesResponse, BtcError> {
    get_btc_balances_impl(confirmations).await
}

#[update]
#[candid_method(update)]
async fn set_btc_address(
    set_btc_address_args: SetBtcAddressArgs,
) -> std::result::Result<SetBtcAddressResponse, BtcError> {
    set_btc_address_impl(set_btc_address_args).await
}

#[update]
#[candid_method(update)]
async fn transaction_notification(
    notify_args: NotifyArgs,
) -> Result<TransactionICRCNotification, ICPReceiverError> {
    transaction_notification_impl(notify_args).await
}

#[query]
#[candid_method(query)]
/// Returns the funds deposited for a channel's specified participant, if any.
/// this function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_user_lp_holdings(
    funding: FundingLPQueryArgs,
) -> std::result::Result<HoldingsResponse, CklError> {
    query_user_lp_holdings_impl(funding)
}

#[update]
#[candid_method(update)]
fn deposit_channel(funding: ChannelFunding, signature_bytes: Vec<u8>) -> Result<(), CklError> {
    deposit_channel_impl(funding, &signature_bytes)
}

#[update]
#[candid_method(update)]
async fn withdraw_lp(withdrawal: WithdrawalLPArgs) -> Result<(), CklError> {
    let sig_withdrawal = withdrawal.signature.clone();

    withdraw_lp_impl(withdrawal, sig_withdrawal).await
}

#[update]
#[candid_method(update)]
fn deposit_lp(funding: FundingLPArgs) -> Result<(), CklError> {
    let signature_bytes = funding.signature.clone();

    deposit_lp_impl(funding, &signature_bytes)
}

#[query]
#[candid_method(query)]
fn query_state(id: ChannelId) -> Option<RegisteredState> {
    query_state_impl(id)
}

#[update]
#[candid::candid_method]
async fn simple_withdraw(req: WithdrawalReq) -> Nat {
    let receiver = req.receiver;
    let amount_nat = req.amount;

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: receiver,
            subaccount: None,
        },
        amount: amount_nat.clone(),
        fee: Some(Nat(1000u64.into())), // ckBTC fee
        memo: None,
        created_at_time: None,
    };

    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let call_result: CallResult<(
        std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_height) => Nat::from(block_height),
            Err(e) => match e {
                icrc_ledger_types::icrc1::transfer::TransferError::BadFee { expected_fee } => {
                    ic_cdk::println!("BadFee: expected_fee = {:?}", expected_fee);
                    Nat::from(111u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::BadBurn { min_burn_amount } => {
                    ic_cdk::println!("BadBurn: min_burn_amount = {:?}", min_burn_amount);
                    Nat::from(112u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::InsufficientFunds {
                    balance,
                } => {
                    ic_cdk::println!("InsufficientFunds: balance = {:?}", balance);
                    Nat::from(222u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::TooOld => Nat::from(333u32),
                icrc_ledger_types::icrc1::transfer::TransferError::CreatedInFuture {
                    ledger_time,
                } => {
                    ic_cdk::println!("CreatedInFuture: ledger_time = {:?}", ledger_time);
                    Nat::from(444u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::TemporarilyUnavailable => {
                    ic_cdk::println!("TemporarilyUnavailable");
                    Nat::from(666u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::Duplicate { duplicate_of } => {
                    ic_cdk::println!("Duplicate: duplicate_of = {:?}", duplicate_of);
                    Nat::from(555u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::GenericError {
                    error_code,
                    message,
                } => {
                    ic_cdk::println!(
                        "GenericError: code = {:?}, message = {}",
                        error_code,
                        message
                    );
                    Nat::from(777u32)
                }
            },
        },
        Err(e) => {
            ic_cdk::println!("CallResult error: {:?}", e);
            Nat::from(999u32) // Generic call error
        }
    }
}

#[update]
#[candid::candid_method]
async fn trigger_withdraw(req: WithdrawalReq) -> Result<Nat, CklError> {
    trigger_withdraw_impl(req).await
}

// =============================================================================
// Lightning → ckBTC Swap Endpoints
// =============================================================================

/// Register a new Lightning → ckBTC swap
///
/// Called by the relay node when an invoice is created with an IC principal.
/// The relay stores the mapping: payment_hash → (amount, recipient)
#[update]
#[candid_method(update)]
fn register_swap(request: RegisterSwapRequest) -> RegisterSwapResponse {
    register_swap_impl(request)
}

/// Complete a Lightning → ckBTC swap after payment received
///
/// Called by the relay node when a Lightning payment is received and claimed.
/// Verifies the preimage matches the payment_hash, then transfers ckBTC.
#[update]
#[candid_method(update)]
async fn complete_swap(request: CompleteSwapRequest) -> CompleteSwapResponse {
    complete_swap_impl(request).await
}

// =============================================================================
// Lightning Channel Funding Verification Endpoints
// =============================================================================

/// Register a new Lightning channel for funding verification
///
/// Called by the relay node when a channel is opened.
/// Stores channel info (funding txid, vout, capacity) so it can be verified on-chain.
#[update]
#[candid_method(update)]
fn register_ln_channel(request: RegisterLnChannelRequest) -> RegisterLnChannelResponse {
    register_ln_channel_impl(request)
}

/// Verify a Lightning channel's funding UTXO on-chain
///
/// Queries the Bitcoin canister to check if the funding UTXO exists
/// with sufficient confirmations.
#[update]
#[candid_method(update)]
async fn verify_ln_channel(request: QueryLnChannelRequest) -> VerifyLnChannelResponse {
    verify_ln_channel_impl(request).await
}

/// Debug: Get raw UTXOs for an address from the Bitcoin canister
#[update]
#[candid_method(update)]
async fn get_utxos_for_address(address: String) -> Result<ic_cdk::bitcoin_canister::GetUtxosResponse, String> {
    use ic_cdk::bitcoin_canister::{GetUtxosRequest, bitcoin_get_utxos};
    use crate::BTC_CONTEXT;

    let network = BTC_CONTEXT.with(|ctx| ctx.get().network);

    bitcoin_get_utxos(&GetUtxosRequest {
        address,
        network,
        filter: None,
    })
    .await
    .map_err(|e| format!("Failed to get UTXOs: {:?}", e))
}

/// Query a specific Lightning channel by ID
#[query]
#[candid_method(query)]
fn query_ln_channel(request: QueryLnChannelRequest) -> Option<LnChannelInfo> {
    query_ln_channel_impl(request)
}

/// Query all registered Lightning channels
#[query]
#[candid_method(query)]
fn query_ln_channels() -> QueryLnChannelsResponse {
    query_ln_channels_impl()
}

// =============================================================================
// Lightning Chainkey Signing Endpoints
// =============================================================================

/// Get the canister's Lightning funding public key
///
/// Returns the compressed SEC1 public key (33 bytes) derived via chainkey ECDSA.
/// This key is used as one half of the 2-of-2 multisig for channel funding.
#[update]
#[candid_method(update)]
async fn get_ln_funding_pubkey() -> LnFundingPubkeyResponse {
    get_ln_funding_pubkey_impl().await
}

/// Sign a message hash for Lightning channel operations
///
/// Called by the relay when it needs a signature for commitment transactions,
/// HTLC transactions, or closing transactions. The canister signs using its
/// Lightning funding key derived via chainkey ECDSA.
#[update]
#[candid_method(update)]
async fn sign_ln_message(request: LnSignRequest) -> LnSignResponse {
    sign_ln_message_impl(request).await
}

// =============================================================================
// Simplified Liquidity Pool Endpoints
// =============================================================================

/// Deposit ckBTC into the liquidity pool
///
/// The caller must first approve the canister to spend their ckBTC using ICRC-2:
/// 1. Call btcledger.icrc2_approve(canister_id, amount)
/// 2. Call this function with the amount to deposit
///
/// The canister will pull ckBTC from the caller and credit their LP balance.
#[update]
#[candid_method(update)]
async fn deposit_ckbtc(amount: Nat) -> LpDepositResponse {
    deposit_ckbtc_impl(amount).await
}

/// Withdraw ckBTC from the liquidity pool
///
/// Withdraws the specified amount of ckBTC from the caller's LP balance.
/// The ckBTC is transferred directly to the caller's principal.
#[update]
#[candid_method(update)]
async fn withdraw_ckbtc(amount: Nat) -> LpWithdrawResponse {
    withdraw_ckbtc_impl(amount).await
}

/// Get the caller's LP balance
///
/// Returns the caller's deposited ckBTC and BTC balances in the liquidity pool.
#[query]
#[candid_method(query)]
fn get_my_lp_balance() -> LpBalanceResponse {
    get_my_lp_balance_impl()
}

/// Get the total LP balance across all depositors
///
/// Returns the total ckBTC and BTC in the liquidity pool, plus the number of depositors.
#[query]
#[candid_method(query)]
fn get_total_lp_balance() -> TotalLpBalanceResponse {
    get_total_lp_balance_impl()
}
