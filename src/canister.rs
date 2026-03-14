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
use crate::canister_state::assert_relay_caller;
use crate::canister_state::set_btc_liquidity_address_impl;
use crate::canister_state::{
    complete_swap_impl, deposit_lp_impl, get_btc_balances_impl,
    get_btc_liquidity_address_for_caller_impl, get_ln_address_impl,
    query_ln_channel_impl, query_ln_channels_impl,
    query_user_lp_holdings_impl, register_ln_channel_impl, register_swap_impl,
    set_btc_address_impl, transaction_notification_impl,
    verify_ln_channel_impl, withdraw_lp_impl,
    // Simplified LP functions
    deposit_ckbtc_impl, withdraw_ckbtc_impl, get_my_lp_balance_impl, get_total_lp_balance_impl,
    // BTC LP functions
    withdraw_btc_impl,
    get_lp_btc_user_address_impl, deposit_btc_user_impl,
    // User BTC operations (from depositor address)
    get_depositor_btc_balance_impl, send_btc_from_depositor_address_impl,
    // Onramp invoice request functions
    request_onramp_invoice_impl, get_pending_invoice_requests_impl, submit_invoice_impl,
    get_invoice_by_request_impl,
    // Offramp functions (ckBTC → Lightning)
    request_offramp_impl, get_pending_offramp_requests_impl, mark_offramp_in_progress_impl,
    complete_offramp_impl, fail_offramp_impl, retry_offramp_refund_impl, get_offramp_status_impl,
    // LP Liquidity management functions
    get_funding_utxos_impl, update_channel_balance_impl, get_lp_liquidity_status_impl,
    channel_funded_impl, channel_closed_impl, cancel_channel_funding_impl,
    expire_channel_funding_reservations,
    // Channel funding from LP BTC
    fund_channel_impl,
    // HTLC functions
    create_htlc_impl, fulfill_htlc_impl, timeout_htlc_impl,
    get_htlc_impl, get_pending_htlcs_impl,
    // Channel secrets functions
    get_channel_secrets_info_impl,
    // HTLC signing functions (Phase 2)
    create_htlc_with_tx_details_impl, sign_htlc_success_impl, sign_htlc_timeout_impl,
    // Channel secret generation (Phase 3: canister generates secrets)
    generate_channel_secrets_impl, get_per_commitment_point_impl,
    release_commitment_secret_impl, register_channel_info_impl,
    // Commitment/justice/HTLC signing (Phase 3 + 4)
    sign_counterparty_commitment_impl, sign_holder_commitment_impl,
    sign_closing_tx_impl, sign_justice_tx_impl, sign_htlc_tx_impl,
    // Swap timeout handling
    check_expired_swaps_impl, get_expired_swap_counts,
    set_test_timeouts_impl, get_timeout_values_impl,
    // Relay registration
    register_relay_impl, get_relay_info_impl,
    // Rate limiting
    get_rate_limit_status_impl,
    // StableSwap functions
    get_swap_quote_impl, get_stableswap_config_impl,
    update_stableswap_config_impl, withdraw_protocol_fees_impl,
    set_icp_ddos_fee_impl, get_icp_ddos_fee_impl, withdraw_icp_fees_impl, redistribute_fees_impl,
    set_admin_impl, set_swap_caps_impl,
    // State pruning & monitoring
    prune_state_impl, get_state_stats_impl,
    // HTTPS outcall helpers
    transform_webhook_response,
};
use crate::helpers::{
    get_ln_funding_pubkey_impl, get_ln_invoice_impl, send_btc_tx_impl, sign_ln_message_impl,
};
use crate::ic_types::{
    LpBalanceResponse, LpDepositResponse, LpWithdrawResponse, TotalLpBalanceResponse,
    LpBtcAddressResponse, LpBtcDepositRequest, LpBtcDepositResponse,
    LpBtcWithdrawRequest, LpBtcWithdrawResponse,
    FundChannelRequest, FundChannelResponse,
    // User BTC operations
    SendFromDepositorRequest, SendFromDepositorResponse, DepositorBtcBalanceResponse,
    // HTLC types
    CreateHtlcRequest, CreateHtlcResponse,
    FulfillHtlcRequest, FulfillHtlcResponse,
    TimeoutHtlcRequest, TimeoutHtlcResponse,
    HtlcInfo,
    // Channel secrets types
    ChannelSecretsInfo,
    // HTLC signing types (Phase 2)
    CreateHtlcWithTxDetailsRequest, CreateHtlcWithTxDetailsResponse,
    SignHtlcSuccessRequest, SignHtlcTimeoutRequest, SignHtlcResponse,
    // Channel secret generation types (Phase 3)
    GenerateChannelSecretsRequest, GenerateChannelSecretsResponse,
    GetPerCommitmentPointRequest, GetPerCommitmentPointResponse,
    ReleaseCommitmentSecretRequest, ReleaseCommitmentSecretResponse,
    RegisterChannelInfoRequest,
    // Commitment/justice/HTLC signing types (Phase 3 + 4)
    SignCounterpartyCommitmentRequest, SignCounterpartyCommitmentResponse,
    SignHolderCommitmentRequest, SignHolderCommitmentResponse,
    SignClosingTxRequest,
    SignJusticeTxRequest, SignHtlcTxRequest,
};
use crate::error::{BtcError, CklError};
use crate::ic_types::LnInvoiceRequest;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::SignedCandidInvoice;
use crate::ic_types::{
    CompleteSwapRequest, CompleteSwapResponse,
    FundingLPArgs, FundingLPQueryArgs, GetBtcBalancesResponse,
    HoldingsResponse, LnChannelInfo, LnFundingPubkeyResponse, LnSignRequest, LnSignResponse,
    NotifyArgs, QueryLnChannelRequest, QueryLnChannelsResponse,
    RegisterLnChannelRequest, RegisterLnChannelResponse, RegisterSwapRequest, RegisterSwapResponse,
    SendBtcTxArgs, SendBtcTxMsg, SetBtcAddressArgs, SetBtcAddressResponse,
    VerifyLnChannelResponse, WithdrawalLPArgs,
    // Onramp invoice request types
    OnrampInvoiceRequest, OnrampInvoiceResponse, PendingInvoiceRequest,
    SubmitInvoiceRequest, SubmitInvoiceResponse, GetInvoiceResponse,
    // Offramp types (ckBTC → Lightning)
    OfframpRequest, OfframpResponse, PendingOfframpRequest,
    CompleteOfframpRequest, CompleteOfframpResponse,
    FailOfframpRequest, FailOfframpResponse, GetOfframpStatusResponse,
    // LP Liquidity types
    GetFundingUtxosResponse, UpdateChannelBalanceRequest, UpdateChannelBalanceResponse,
    LpLiquidityStatus,
    // Relay registration types
    RegisterRelayRequest, RegisterRelayResponse, GetRelayInfoResponse,
    // Rate limiting types
    RateLimitStatus,
    // StableSwap types
    StableSwapConfig, SwapQuoteRequest, SwapQuoteResponse,
    UpdateStableSwapConfigRequest, UpdateStableSwapConfigResponse,
    WithdrawProtocolFeesResponse,
    SetIcpDdosFeeResponse, WithdrawIcpFeesResponse, RedistributeFeesResponse,
    PruneResult, StateStats,
};
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use candid::{Nat, Principal, candid_method};
use ic_cdk::query;
use ic_cdk::update;
use ic_cdk::heartbeat;

#[update]
#[candid_method(update)]
async fn send_btc_tx(args: SendBtcTxArgs) -> std::result::Result<SendBtcTxMsg, BtcError> {
    assert_relay_caller().map_err(BtcError::Other)?;
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
/// This function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_user_lp_holdings(
    funding: FundingLPQueryArgs,
) -> std::result::Result<HoldingsResponse, CklError> {
    query_user_lp_holdings_impl(funding)
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
    if let Err(e) = assert_relay_caller() {
        return RegisterSwapResponse { success: false, error: Some(e) };
    }
    register_swap_impl(request)
}

/// Complete a Lightning → ckBTC swap after payment received
///
/// Called by the relay node when a Lightning payment is received and claimed.
/// Verifies the preimage matches the payment_hash, then transfers ckBTC.
#[update]
#[candid_method(update)]
async fn complete_swap(request: CompleteSwapRequest) -> CompleteSwapResponse {
    if let Err(e) = assert_relay_caller() {
        return CompleteSwapResponse { success: false, block_index: None, error: Some(e) };
    }
    complete_swap_impl(request).await
}

// =============================================================================
// Onramp Invoice Request Endpoints (Canister-First Flow)
// =============================================================================

/// Request a new onramp invoice for Lightning → ckBTC swap
///
/// Called by clients to initiate a swap. Returns a request_id that can be
/// used to poll for the invoice once the relay creates it.
/// Requires prior ICRC-2 approval for the configured ICP anti-DDoS fee.
///
/// Flow:
/// 1. Client approves ICP for canister via ICP ledger icrc2_approve
/// 2. Client calls this endpoint with (recipient, amount)
/// 3. Canister takes ICP fee, creates pending request, returns request_id
/// 4. Relay polls get_pending_invoice_requests, creates BOLT11 invoice
/// 5. Relay calls submit_invoice with the invoice
/// 6. Client polls get_invoice_by_request until invoice is ready
/// 7. Client pays the invoice
/// 8. Relay receives payment, calls complete_swap
/// 9. Canister transfers ckBTC AND refunds ICP to user
#[update]
#[candid_method(update)]
async fn request_onramp_invoice(request: OnrampInvoiceRequest) -> OnrampInvoiceResponse {
    request_onramp_invoice_impl(request).await
}

/// Get all pending invoice requests for the relay to process
///
/// Called by the relay to find requests that need invoices created.
/// The relay should poll this periodically and create invoices for pending requests.
#[query]
#[candid_method(query)]
fn get_pending_invoice_requests() -> Vec<PendingInvoiceRequest> {
    if assert_relay_caller().is_err() { return vec![]; }
    get_pending_invoice_requests_impl()
}

/// Submit a created invoice for a pending request
///
/// Called by the relay after creating a BOLT11 invoice for a pending request.
/// This also registers the swap internally so complete_swap will work.
#[update]
#[candid_method(update)]
fn submit_invoice(request: SubmitInvoiceRequest) -> SubmitInvoiceResponse {
    if let Err(e) = assert_relay_caller() {
        return SubmitInvoiceResponse { success: false, error: Some(e) };
    }
    submit_invoice_impl(request)
}

/// Get the invoice for a request (client polling)
///
/// Called by clients to check if their invoice is ready.
/// Returns the current state and the invoice if available.
#[query]
#[candid_method(query)]
fn get_invoice_by_request(request_id: String) -> GetInvoiceResponse {
    get_invoice_by_request_impl(request_id)
}

// =============================================================================
// Offramp Endpoints (ckBTC → Lightning)
// =============================================================================

/// Request an offramp (ckBTC → Lightning)
///
/// Called by a user who wants to pay a Lightning invoice using their ckBTC.
/// User must first call icrc2_approve on ckBTC ledger for the canister.
/// The canister takes custody of the ckBTC and the relay pays the invoice.
#[update]
#[candid_method(update)]
async fn request_offramp(request: OfframpRequest) -> OfframpResponse {
    request_offramp_impl(request).await
}

/// Get all pending offramp requests for the relay to process
///
/// Called by the relay to find offramp requests that need invoices paid.
#[query]
#[candid_method(query)]
fn get_pending_offramp_requests() -> Vec<PendingOfframpRequest> {
    if assert_relay_caller().is_err() { return vec![]; }
    get_pending_offramp_requests_impl()
}

/// Mark an offramp request as payment in progress
///
/// Called by the relay when it starts attempting to pay the invoice.
#[update]
#[candid_method(update)]
fn mark_offramp_in_progress(request_id: String) -> bool {
    if assert_relay_caller().is_err() { return false; }
    mark_offramp_in_progress_impl(&request_id)
}

/// Complete an offramp request after successful payment
///
/// Called by the relay after successfully paying the Lightning invoice.
/// Requires the payment preimage as proof of payment.
/// Refunds the ICP anti-DDoS fee to the user on success.
#[update]
#[candid_method(update)]
async fn complete_offramp(request: CompleteOfframpRequest) -> CompleteOfframpResponse {
    if let Err(e) = assert_relay_caller() {
        return CompleteOfframpResponse { success: false, error: Some(e) };
    }
    complete_offramp_impl(request).await
}

/// Fail an offramp request and initiate refund
///
/// Called by the relay when it fails to pay the Lightning invoice.
/// The ckBTC is refunded to the user.
#[update]
#[candid_method(update)]
async fn fail_offramp(request: FailOfframpRequest) -> FailOfframpResponse {
    if let Err(e) = assert_relay_caller() {
        return FailOfframpResponse { success: false, refund_block_index: None, error: Some(e) };
    }
    fail_offramp_impl(request).await
}

/// Retry a failed offramp ckBTC refund
///
/// Called by admin/relay to retry refund for requests stuck in FailedPendingRefund.
#[update]
#[candid_method(update)]
async fn retry_offramp_refund(request_id: String) -> FailOfframpResponse {
    // Allow both relay and admin to retry
    let caller = ic_cdk::api::msg_caller();
    let relay_ok = assert_relay_caller().is_ok();
    let admin_ok = {
        let state = crate::canister_state::STATE.read().expect("STATE lock: mark_offramp_in_progress");
        state.admin == Some(caller)
    };
    if !relay_ok && !admin_ok {
        return FailOfframpResponse {
            success: false,
            refund_block_index: None,
            error: Some("Only relay or admin can retry refunds".to_string()),
        };
    }
    retry_offramp_refund_impl(request_id).await
}

/// Get the status of an offramp request
///
/// Called by users to check the status of their offramp.
#[query]
#[candid_method(query)]
fn get_offramp_status(request_id: String) -> GetOfframpStatusResponse {
    get_offramp_status_impl(request_id)
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
    if let Err(e) = assert_relay_caller() {
        return RegisterLnChannelResponse { success: false, error: Some(e) };
    }
    register_ln_channel_impl(request)
}

/// Verify a Lightning channel's funding UTXO on-chain
///
/// Queries the Bitcoin canister to check if the funding UTXO exists
/// with sufficient confirmations.
#[update]
#[candid_method(update)]
async fn verify_ln_channel(request: QueryLnChannelRequest) -> VerifyLnChannelResponse {
    if let Err(e) = assert_relay_caller() {
        return VerifyLnChannelResponse { verified: false, confirmations: None, utxo_value_sats: None, error: Some(e) };
    }
    verify_ln_channel_impl(request).await
}

/// Debug: Get raw UTXOs for an address from the Bitcoin canister
#[update]
#[candid_method(update)]
async fn get_utxos_for_address(address: String) -> Result<ic_cdk::bitcoin_canister::GetUtxosResponse, String> {
    assert_relay_caller()?;
    use ic_cdk::bitcoin_canister::{GetUtxosRequest, bitcoin_get_utxos};
    use crate::BTC_CONTEXT;

    let network = BTC_CONTEXT.with(|ctx| ctx.get().network);

    bitcoin_get_utxos(&GetUtxosRequest {
        address,
        network,
        filter: None,
    })
    .await
    .map_err(|e| format!("Failed to get UTXOs: {e:?}"))
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
    if let Err(e) = assert_relay_caller() {
        return LnSignResponse { success: false, signature: None, error: Some(e) };
    }
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

// =============================================================================
// BTC Liquidity Pool Endpoints (Shared LP Address)
// =============================================================================

/// Get the caller's per-user LP BTC deposit address
///
/// Each LP depositor gets a unique address derived from their principal.
/// This prevents the first-claimer-wins issue of the shared address.
#[update]
#[candid_method(update)]
async fn get_lp_btc_user_address() -> Result<LpBtcAddressResponse, BtcError> {
    get_lp_btc_user_address_impl().await
}

/// Deposit BTC to the liquidity pool using per-user address
///
/// Flow:
/// 1. Call get_lp_btc_user_address() to get your unique deposit address
/// 2. Send BTC to that address (off-chain, via wallet)
/// 3. Wait for 6 confirmations
/// 4. Call this function to claim your deposit
///
/// Only UTXOs at the caller's own address are credited.
#[update]
#[candid_method(update)]
async fn deposit_btc_user(request: LpBtcDepositRequest) -> LpBtcDepositResponse {
    deposit_btc_user_impl(request).await
}

/// Withdraw BTC from the liquidity pool
///
/// Sends BTC from the LP to your specified destination address.
/// Your LP BTC balance must be sufficient for the withdrawal amount.
#[update]
#[candid_method(update)]
async fn withdraw_btc(request: LpBtcWithdrawRequest) -> LpBtcWithdrawResponse {
    withdraw_btc_impl(request).await
}

// =============================================================================
// User BTC Operations (from depositor address)
// =============================================================================

/// Get the caller's BTC balance at their depositor address
///
/// Returns the caller's BTC address (derived via threshold ECDSA) and its balance.
/// The address is derived from the caller's principal using BtcPurpose::LiquidityDepositor.
#[update]
#[candid_method(update)]
async fn get_depositor_btc_balance() -> DepositorBtcBalanceResponse {
    get_depositor_btc_balance_impl().await
}

/// Send BTC from the caller's depositor address to a destination
///
/// The caller must have BTC at their depositor address (derived from their principal).
/// The canister signs the transaction using threshold ECDSA.
///
/// Use this to send BTC to the LP address for depositing to the liquidity pool.
#[update]
#[candid_method(update)]
async fn send_btc_from_depositor_address(request: SendFromDepositorRequest) -> SendFromDepositorResponse {
    send_btc_from_depositor_address_impl(request).await
}

/// Fund a Lightning channel from LP BTC
///
/// Builds and signs a transaction from LP UTXOs to the channel funding address.
/// The transaction is NOT broadcast - it's returned to the relay which passes
/// it to LDK for proper broadcast timing and channel setup.
#[update]
#[candid_method(update)]
async fn fund_channel(request: FundChannelRequest) -> FundChannelResponse {
    if let Err(e) = assert_relay_caller() {
        return FundChannelResponse { success: false, signed_tx: None, txid: None, error: Some(e) };
    }
    fund_channel_impl(request).await
}

// =============================================================================
// LP Liquidity Management (Canister-Controlled BTC for Lightning)
// =============================================================================

/// Get available UTXOs from the LP's BTC address for channel funding
///
/// The relay calls this to get UTXOs it can use to fund Lightning channels.
/// Only returns UTXOs that are not reserved for pending channel opens.
#[update]
#[candid_method(update)]
async fn get_funding_utxos(min_amount_sats: u64) -> Result<GetFundingUtxosResponse, BtcError> {
    assert_relay_caller().map_err(BtcError::Other)?;
    get_funding_utxos_impl(min_amount_sats).await
}

/// Update channel balance after Lightning payment activity
///
/// The relay calls this to report updated channel balances after payments.
/// This allows the canister to track available outbound/inbound capacity.
#[update]
#[candid_method(update)]
fn update_channel_balance(request: UpdateChannelBalanceRequest) -> UpdateChannelBalanceResponse {
    if let Err(e) = assert_relay_caller() {
        return UpdateChannelBalanceResponse { success: false, error: Some(e) };
    }
    update_channel_balance_impl(request)
}

/// Get overall LP liquidity status
///
/// Returns the current state of both ckBTC pool and BTC/Lightning liquidity.
/// Useful for monitoring available capacity for onramp/offramp operations.
#[update]
#[candid_method(update)]
async fn get_lp_liquidity_status() -> Result<LpLiquidityStatus, BtcError> {
    assert_relay_caller().map_err(BtcError::Other)?;
    get_lp_liquidity_status_impl().await
}

/// Called when a channel is successfully funded
///
/// The relay calls this after a channel funding transaction is confirmed.
/// Updates LP accounting to track BTC locked in channels.
#[update]
#[candid_method(update)]
fn channel_funded(channel_id: Vec<u8>, capacity_sats: u64) -> Result<(), String> {
    assert_relay_caller()?;
    let channel_id: [u8; 32] = channel_id
        .try_into()
        .map_err(|_| "Invalid channel_id length")?;
    channel_funded_impl(channel_id, capacity_sats);
    Ok(())
}

/// Called when a channel is closed
///
/// The relay calls this when a channel is closed (cooperative or force).
/// Updates LP accounting to mark the channel as inactive.
#[update]
#[candid_method(update)]
fn channel_closed(channel_id: Vec<u8>) -> Result<(), String> {
    assert_relay_caller()?;
    let channel_id: [u8; 32] = channel_id
        .try_into()
        .map_err(|_| "Invalid channel_id length")?;
    channel_closed_impl(channel_id);
    Ok(())
}

/// Cancel a pending channel funding (TX never broadcast or relay aborted).
///
/// Releases the idempotency guard and reservation so funding can be re-attempted.
/// No LP balance changes occur since deduction hasn't happened yet (two-phase model).
#[update]
#[candid_method(update)]
fn cancel_channel_funding(funding_address: String) -> Result<(), String> {
    assert_relay_caller()?;
    cancel_channel_funding_impl(funding_address)
}

// =============================================================================
// HTLC Endpoints (Hash Time-Locked Contracts)
// =============================================================================

/// Create a new HTLC
///
/// Called by the relay when an HTLC is added to a commitment transaction.
/// The canister tracks the HTLC state for later fulfillment or timeout.
#[update]
#[candid_method(update)]
fn create_htlc(request: CreateHtlcRequest) -> CreateHtlcResponse {
    if let Err(e) = assert_relay_caller() {
        return CreateHtlcResponse { success: false, error: Some(e) };
    }
    create_htlc_impl(request)
}

/// Fulfill an HTLC by revealing the preimage
///
/// Called by the relay when a preimage is received (payment successful).
/// Returns the payment_hash and amount for confirmation.
#[update]
#[candid_method(update)]
fn fulfill_htlc(request: FulfillHtlcRequest) -> FulfillHtlcResponse {
    if let Err(e) = assert_relay_caller() {
        return FulfillHtlcResponse { success: false, payment_hash: None, amount_msat: None, error: Some(e) };
    }
    fulfill_htlc_impl(request)
}

/// Timeout an HTLC after CLTV expiry
///
/// Called by the relay when an HTLC has expired without being fulfilled.
/// The sender can reclaim the funds.
#[update]
#[candid_method(update)]
fn timeout_htlc(request: TimeoutHtlcRequest) -> TimeoutHtlcResponse {
    if let Err(e) = assert_relay_caller() {
        return TimeoutHtlcResponse { success: false, amount_msat: None, error: Some(e) };
    }
    timeout_htlc_impl(request)
}

/// Get an HTLC by payment hash
#[query]
#[candid_method(query)]
fn get_htlc(payment_hash: Vec<u8>) -> Option<HtlcInfo> {
    if assert_relay_caller().is_err() { return None; }
    get_htlc_impl(payment_hash)
}

/// Get all pending HTLCs
#[query]
#[candid_method(query)]
fn get_pending_htlcs() -> Vec<HtlcInfo> {
    if assert_relay_caller().is_err() { return vec![]; }
    get_pending_htlcs_impl()
}

// =============================================================================
// Channel Secrets Endpoints
// =============================================================================

/// Query channel secrets info (public keys only, secrets are never exposed).
#[query]
#[candid_method(query)]
fn get_channel_secrets_info(channel_id: Vec<u8>) -> Option<ChannelSecretsInfo> {
    if assert_relay_caller().is_err() { return None; }
    get_channel_secrets_info_impl(channel_id)
}

// =============================================================================
// HTLC with Transaction Details Endpoints (Phase 2)
// =============================================================================

/// Create an HTLC with full transaction details for later signing.
///
/// This is an extended version of create_htlc that stores all information
/// needed to construct and sign HTLC-Success and HTLC-Timeout transactions.
#[update]
#[candid_method(update)]
fn create_htlc_with_tx_details(
    request: CreateHtlcWithTxDetailsRequest,
) -> CreateHtlcWithTxDetailsResponse {
    if let Err(e) = assert_relay_caller() {
        return CreateHtlcWithTxDetailsResponse { success: false, witness_script: None, error: Some(e) };
    }
    create_htlc_with_tx_details_impl(request)
}

// =============================================================================
// HTLC Signing Endpoints (Phase 2)
// =============================================================================

/// Sign an HTLC-Success transaction (receiver claims with preimage).
///
/// Builds the HTLC-Success transaction using stored HTLC details,
/// signs it with the channel's HTLC key, and returns the fully signed
/// transaction ready for broadcast.
///
/// Requirements:
/// - Channel secrets must be registered via register_channel_secrets()
/// - HTLC must be created via create_htlc_with_tx_details()
/// - Preimage must match the payment hash
#[update]
#[candid_method(update)]
fn sign_htlc_success(request: SignHtlcSuccessRequest) -> SignHtlcResponse {
    if let Err(e) = assert_relay_caller() {
        return SignHtlcResponse { success: false, signed_tx: None, txid: None, error: Some(e) };
    }
    sign_htlc_success_impl(request)
}

/// Sign an HTLC-Timeout transaction (sender reclaims after CLTV expiry).
///
/// Builds the HTLC-Timeout transaction using stored HTLC details,
/// signs it with the channel's HTLC key, and returns the fully signed
/// transaction ready for broadcast.
///
/// Requirements:
/// - Channel secrets must be registered via register_channel_secrets()
/// - HTLC must be created via create_htlc_with_tx_details()
/// - Current block height must be >= HTLC's cltv_expiry (enforced by Bitcoin, not here)
#[update]
#[candid_method(update)]
fn sign_htlc_timeout(request: SignHtlcTimeoutRequest) -> SignHtlcResponse {
    if let Err(e) = assert_relay_caller() {
        return SignHtlcResponse { success: false, signed_tx: None, txid: None, error: Some(e) };
    }
    sign_htlc_timeout_impl(request)
}

// =============================================================================
// Swap Timeout Handling
// =============================================================================

/// Heartbeat function that periodically checks for expired swaps.
///
/// - Onramp: Marks expired requests, ICP fee NOT refunded (anti-DDoS)
/// - Offramp: Marks expired requests, refunds ckBTC to user (not LP)
///
// =============================================================================
// Ingress Message Filtering
// =============================================================================
/// Pre-execution filter for update calls.
///
/// Rejects unauthorized callers BEFORE decoding arguments, saving cycles.
/// Queries are not subject to inspect_message (they go through query handlers).
#[ic_cdk::inspect_message]
fn inspect_message() {
    use crate::canister_state::STATE;

    let method = ic_cdk::api::msg_method_name();
    let caller = ic_cdk::api::msg_caller();

    let allowed = match method.as_str() {
        // Controller-only
        "set_admin" => ic_cdk::api::is_controller(&caller),

        // Admin-only
        "update_stableswap_config" | "withdraw_protocol_fees" | "set_icp_ddos_fee"
        | "withdraw_icp_fees" | "redistribute_fees" | "prune_state"
        | "set_test_timeouts" | "set_swap_caps" => {
            let state = STATE.read().expect("STATE lock: inspect_message");
            state.admin == Some(caller)
        }

        // Relay or admin
        "retry_offramp_refund" => {
            let state = STATE.read().expect("STATE lock: inspect_message");
            let is_admin = state.admin == Some(caller);
            let is_relay = match &state.registered_relay {
                Some(relay) => relay.principal == caller,
                None => false,
            };
            is_admin || is_relay
        }

        // Relay registration — admin, controller, or existing relay (endpoint does its own auth)
        "register_relay" => {
            let state = STATE.read().expect("STATE lock: inspect_message");
            let is_admin = state.admin == Some(caller);
            let is_relay = matches!(&state.registered_relay, Some(r) if r.principal == caller);
            is_admin || is_relay || ic_cdk::api::is_controller(&caller)
        }

        // Public canister key — needed by relay at startup before registration
        "get_ln_funding_pubkey" => true,

        // Relay-only
        "send_btc_tx" | "register_swap" | "complete_swap" | "submit_invoice"
        | "mark_offramp_in_progress" | "complete_offramp" | "fail_offramp"
        | "register_ln_channel" | "verify_ln_channel" | "get_utxos_for_address"
        | "sign_ln_message"
        | "fund_channel" | "get_funding_utxos" | "update_channel_balance"
        | "get_lp_liquidity_status" | "channel_funded" | "channel_closed" | "cancel_channel_funding"
        | "create_htlc" | "fulfill_htlc" | "timeout_htlc"
        | "create_htlc_with_tx_details" | "sign_htlc_success" | "sign_htlc_timeout"
        | "generate_channel_secrets" | "sign_counterparty_commitment"
        | "sign_holder_commitment_v2" | "sign_closing_tx"
        | "sign_justice_tx" | "sign_htlc_tx" | "register_channel_info"
        | "check_expired_swaps" => {
            let state = STATE.read().expect("STATE lock: inspect_message");
            match &state.registered_relay {
                Some(relay) => relay.principal == caller,
                None => false,
            }
        }

        // User methods — anyone can call (they are self-scoped by msg_caller)
        "get_ln_address" | "query_ln_invoice" | "get_btc_liquidity_address_for_caller"
        | "set_btc_liquidity_address" | "get_btc_balance" | "set_btc_address"
        | "transaction_notification" | "withdraw_lp" | "deposit_lp"
        | "request_onramp_invoice" | "request_offramp"
        | "deposit_ckbtc" | "withdraw_ckbtc"
        | "withdraw_btc" | "get_depositor_btc_balance"
        | "send_btc_from_depositor_address"
        | "get_lp_btc_user_address" | "deposit_btc_user" => true,

        // Unknown method — reject
        _ => false,
    };

    if allowed {
        ic_cdk::api::accept_message();
    }
    // Otherwise: message silently rejected, no cycles spent on arg decoding
}

///
/// Timeout periods:
/// - Onramp: 30 minutes
/// - Offramp: 10 minutes
#[heartbeat]
async fn heartbeat() {
    check_expired_swaps_impl().await;
    expire_channel_funding_reservations();
}

/// Get count of expired swaps for monitoring
///
/// Returns (expired_onramp_count, expired_offramp_count)
#[query]
#[candid_method(query)]
fn get_expired_swap_counts_query() -> (u64, u64) {
    get_expired_swap_counts()
}

/// Manually trigger expired swap checking (for testing)
///
/// This allows E2E tests to trigger the expiry check without waiting for heartbeat.
/// In production, the heartbeat handles this automatically.
#[update]
#[candid_method(update)]
#[allow(clippy::await_holding_lock)] // lock is dropped before await
async fn check_expired_swaps() {
    // Admin or relay only for manual trigger
    let caller = ic_cdk::api::msg_caller();
    let state = crate::canister_state::STATE.read().expect("STATE lock: get_expired_swap_counts_query");
    let is_admin = matches!(state.admin, Some(admin) if admin == caller);
    let is_relay = matches!(&state.registered_relay, Some(r) if r.principal == caller);
    drop(state);
    if !is_admin && !is_relay {
        return; // silently ignore unauthorized callers
    }
    check_expired_swaps_impl().await;
}

/// Set test timeout values (for E2E testing only)
///
/// Pass 0 to reset to default values.
/// Default: onramp=30min, offramp=10min
/// For testing, use small values like 5_000_000_000 (5 seconds)
#[update]
#[candid_method(update)]
fn set_test_timeouts(onramp_timeout_ns: u64, offramp_timeout_ns: u64) {
    // Admin-only: test timeouts should not be callable by anyone
    let caller = ic_cdk::api::msg_caller();
    let state = crate::canister_state::STATE.read().expect("STATE lock: set_test_timeouts");
    match state.admin {
        Some(admin) if admin == caller => {},
        _ => { ic_cdk::trap("Unauthorized: only admin can set test timeouts"); }
    }
    drop(state);
    set_test_timeouts_impl(onramp_timeout_ns, offramp_timeout_ns);
}

/// Get current timeout values (for testing/debugging)
///
/// Returns (onramp_timeout_ns, offramp_timeout_ns)
#[query]
#[candid_method(query)]
fn get_timeout_values() -> (u64, u64) {
    get_timeout_values_impl()
}

// =============================================================================
// Relay Registration Endpoints
// =============================================================================

/// Register a relay with its Lightning node pubkey.
///
/// The relay must call this before it can submit invoices for onramp requests.
/// This prevents invoice substitution attacks where a malicious relay could
/// redirect payments to a different node.
///
/// # Arguments
/// * `request` - Contains the 33-byte compressed secp256k1 node pubkey
///
/// # Security
/// - Only one relay can be registered at a time
/// - The same principal can update its pubkey by calling again
/// - Invoice submission will fail if the invoice's destination node doesn't match
#[update]
#[candid_method(update)]
fn register_relay(request: RegisterRelayRequest) -> RegisterRelayResponse {
    // Admin or controller only (first relay registration requires controller)
    let caller = ic_cdk::api::msg_caller();
    let state = crate::canister_state::STATE.read().expect("STATE lock: register_relay");
    let is_admin = matches!(state.admin, Some(admin) if admin == caller);
    let is_existing_relay = matches!(&state.registered_relay, Some(r) if r.principal == caller);
    drop(state);
    if !is_admin && !is_existing_relay && !ic_cdk::api::is_controller(&caller) {
        return RegisterRelayResponse {
            success: false,
            error: Some("Unauthorized: only admin, controller, or existing relay can register".to_string()),
        };
    }
    register_relay_impl(request)
}

/// Get information about the registered relay.
///
/// Returns whether a relay is registered, and if so, its principal and node pubkey.
#[query]
#[candid_method(query)]
fn get_relay_info() -> GetRelayInfoResponse {
    get_relay_info_impl()
}

// =============================================================================
// HTTPS Outcall Transform Endpoint
// =============================================================================

/// Transform function for HTTPS outcalls (required by IC consensus).
///
/// Ensures deterministic response across replicas by stripping response body.
/// Name must match the string in `TransformContext::from_name()` in http_outcall.rs.
#[query(name = "transform_webhook_response")]
#[candid_method(query, rename = "transform_webhook_response")]
fn transform_webhook_response_query(
    args: ic_cdk::management_canister::TransformArgs,
) -> ic_cdk::management_canister::HttpRequestResult {
    transform_webhook_response(args)
}

// =============================================================================
// Rate Limiting Endpoints
// =============================================================================

/// Get the caller's rate limit status.
///
/// Returns how many onramp/offramp requests the caller has made in the current
/// window, and when the window resets.
#[query]
#[candid_method(query)]
fn get_rate_limit_status() -> RateLimitStatus {
    get_rate_limit_status_impl(ic_cdk::api::msg_caller())
}

// =============================================================================
// StableSwap AMM Endpoints
// =============================================================================

/// Preview a swap output without executing.
///
/// Returns the expected output, fees, and price impact for a given input
/// amount and direction. Does not modify any state.
#[query]
#[candid_method(query)]
fn get_swap_quote(request: SwapQuoteRequest) -> SwapQuoteResponse {
    get_swap_quote_impl(request)
}

/// Get the current StableSwap configuration.
///
/// Returns the amplification coefficient, fee basis points, and protocol fee share.
#[query]
#[candid_method(query)]
fn get_stableswap_config() -> StableSwapConfig {
    get_stableswap_config_impl()
}

/// Update the StableSwap configuration (admin-only).
///
/// Allows the admin to change the amplification coefficient, swap fee,
/// and protocol fee share. Pass None for fields that should not change.
#[update]
#[candid_method(update)]
fn update_stableswap_config(request: UpdateStableSwapConfigRequest) -> UpdateStableSwapConfigResponse {
    update_stableswap_config_impl(request)
}

/// Withdraw accumulated protocol fees (admin-only).
///
/// Transfers all accumulated ckBTC protocol fees to the specified recipient
/// via ICRC-1 transfer, then resets the counter.
#[update]
#[candid_method(update)]
async fn withdraw_protocol_fees(recipient: Principal) -> WithdrawProtocolFeesResponse {
    withdraw_protocol_fees_impl(recipient).await
}

/// Set the ICP anti-DDoS fee amount (admin-only).
///
/// Controls how much ICP is collected as a security deposit for swap requests.
/// The fee is refunded on successful swap completion.
#[update]
#[candid_method(update)]
fn set_icp_ddos_fee(fee_e8s: u64) -> SetIcpDdosFeeResponse {
    set_icp_ddos_fee_impl(fee_e8s)
}

/// Get the current ICP anti-DDoS fee amount.
#[query]
#[candid_method(query)]
fn get_icp_ddos_fee() -> u64 {
    get_icp_ddos_fee_impl()
}

/// Set withdrawal / swap amount caps (admin-only).
///
/// max_single_swap_sats: max satoshis per individual swap (0 = disabled).
/// max_hourly_swap_sats: max aggregate satoshis per rolling hour (0 = disabled).
#[update]
#[candid_method(update)]
fn set_swap_caps(max_single_swap_sats: u64, max_hourly_swap_sats: u64) -> Result<(), String> {
    set_swap_caps_impl(max_single_swap_sats, max_hourly_swap_sats)
}

/// Withdraw accumulated ICP fees from the canister (admin-only).
///
/// Transfers the canister's ICP balance (minus transfer fee) to the recipient.
#[update]
#[candid_method(update)]
async fn withdraw_icp_fees(recipient: Principal) -> WithdrawIcpFeesResponse {
    withdraw_icp_fees_impl(recipient).await
}

/// Redistribute accumulated ckBTC protocol fees to LPs (admin-only).
///
/// Credits each LP's ckBTC balance proportionally based on their pool share,
/// then resets the protocol fee counter.
#[update]
#[candid_method(update)]
fn redistribute_fees() -> RedistributeFeesResponse {
    redistribute_fees_impl()
}

// =============================================================================
// Channel Secret Generation Endpoints (Phase 3: Canister generates secrets)
// =============================================================================

/// Generate channel secrets on the canister.
///
/// The canister uses `raw_rand()` to generate a cryptographic master seed,
/// then derives all 5 channel secrets via HMAC-SHA256. Secrets never leave
/// the canister — only public keys are returned.
///
/// This replaces `register_channel_secrets` where the relay sent secrets
/// to the canister.
#[update]
#[candid_method(update)]
async fn generate_channel_secrets(
    request: GenerateChannelSecretsRequest,
) -> GenerateChannelSecretsResponse {
    if let Err(e) = assert_relay_caller() {
        return GenerateChannelSecretsResponse {
            success: false, htlc_basepoint: None, revocation_basepoint: None,
            delayed_payment_basepoint: None, payment_point: None, error: Some(e),
        };
    }
    generate_channel_secrets_impl(request).await
}

/// Get the per-commitment point for a specific commitment index.
///
/// Pure computation from stored commitment_seed — safe as query.
#[query]
#[candid_method(query)]
fn get_per_commitment_point(request: GetPerCommitmentPointRequest) -> GetPerCommitmentPointResponse {
    if let Err(e) = assert_relay_caller() {
        return GetPerCommitmentPointResponse { success: false, point: None, error: Some(e) };
    }
    get_per_commitment_point_impl(request)
}

/// Release (reveal) a per-commitment secret.
///
/// Returns the raw 32-byte secret for a given commitment index.
/// Pure computation from stored commitment_seed — safe as query.
#[query]
#[candid_method(query)]
fn release_commitment_secret(
    request: ReleaseCommitmentSecretRequest,
) -> ReleaseCommitmentSecretResponse {
    if let Err(e) = assert_relay_caller() {
        return ReleaseCommitmentSecretResponse { success: false, secret: None, error: Some(e) };
    }
    release_commitment_secret_impl(request)
}

/// Register counterparty channel info for a channel.
///
/// Stores the counterparty's funding pubkey so the canister can reconstruct
/// the funding redeemscript for sighash computation during signing.
#[update]
#[candid_method(update)]
fn register_channel_info(request: RegisterChannelInfoRequest) -> bool {
    if assert_relay_caller().is_err() { return false; }
    register_channel_info_impl(request)
}

// =============================================================================
// Commitment Signing Endpoints (Phase 3)
// =============================================================================

/// Sign a counterparty commitment transaction.
///
/// Returns commitment signature (chainkey ECDSA) and HTLC signatures
/// (local ECDSA using derived HTLC key). The canister computes all
/// sighashes itself from full transaction bytes.
#[update]
#[candid_method(update)]
async fn sign_counterparty_commitment(
    request: SignCounterpartyCommitmentRequest,
) -> SignCounterpartyCommitmentResponse {
    if let Err(e) = assert_relay_caller() {
        return SignCounterpartyCommitmentResponse { success: false, commitment_sig: None, htlc_sigs: None, error: Some(e) };
    }
    sign_counterparty_commitment_impl(request).await
}

/// Sign a holder commitment transaction.
///
/// Returns only the commitment signature (chainkey ECDSA).
#[update]
#[candid_method(update)]
async fn sign_holder_commitment_v2(
    request: SignHolderCommitmentRequest,
) -> SignHolderCommitmentResponse {
    if let Err(e) = assert_relay_caller() {
        return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) };
    }
    sign_holder_commitment_impl(request).await
}

/// Sign a cooperative closing transaction.
#[update]
#[candid_method(update)]
async fn sign_closing_tx(request: SignClosingTxRequest) -> SignHolderCommitmentResponse {
    if let Err(e) = assert_relay_caller() {
        return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) };
    }
    sign_closing_tx_impl(request).await
}

// =============================================================================
// Justice + HTLC Transaction Signing Endpoints (Phase 4)
// =============================================================================

/// Sign a justice (penalty) transaction.
///
/// Uses the derived revocation key to sign. Certified by subnet consensus
/// via `#[update]` even though no chainkey is needed.
#[update]
#[candid_method(update)]
fn sign_justice_tx(request: SignJusticeTxRequest) -> LnSignResponse {
    if let Err(e) = assert_relay_caller() {
        return LnSignResponse { success: false, signature: None, error: Some(e) };
    }
    sign_justice_tx_impl(request)
}

/// Sign an HTLC transaction (holder or counterparty second-level).
///
/// Uses the derived HTLC key to sign. Certified by subnet consensus
/// via `#[update]` even though no chainkey is needed.
#[update]
#[candid_method(update)]
fn sign_htlc_tx(request: SignHtlcTxRequest) -> LnSignResponse {
    if let Err(e) = assert_relay_caller() {
        return LnSignResponse { success: false, signature: None, error: Some(e) };
    }
    sign_htlc_tx_impl(request)
}

// =============================================================================
// Admin Endpoints
// =============================================================================

/// Set the admin principal (controller-only).
///
/// Only canister controllers can call this. The admin can then update
/// StableSwap config and withdraw protocol fees.
#[update]
#[candid_method(update)]
fn set_admin(principal: Principal) {
    set_admin_impl(principal)
}

/// Prune terminal-state entries older than cutoff (admin-only).
///
/// Pass a nanosecond timestamp; entries with `created_at < older_than_ns` in
/// terminal states (Completed, Expired, Failed, Refunded) will be removed.
#[update]
#[candid_method(update)]
fn prune_state(older_than_ns: u64) -> PruneResult {
    prune_state_impl(older_than_ns)
}

/// Get statistics about canister state collection sizes.
#[query]
#[candid_method(query)]
fn get_state_stats() -> StateStats {
    get_state_stats_impl()
}

