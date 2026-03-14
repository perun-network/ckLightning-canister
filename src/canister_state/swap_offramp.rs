// =============================================================================
// Offramp Implementation (ckBTC → Lightning)
// =============================================================================

use super::STATE;
use super::admin::check_offramp_rate_limit;
use super::http_outcall::notify_relay_webhook;
use super::swaps::refund_icp_fee;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    CKBTC_LEDGER_PRINCIPAL, ICP_LEDGER_PRINCIPAL,
    OfframpRequest, OfframpResponse, OfframpRequestInfo, OfframpRequestState,
    PendingOfframpRequest, CompleteOfframpRequest, CompleteOfframpResponse,
    FailOfframpRequest, FailOfframpResponse, GetOfframpStatusResponse,
};

use bitcoin::hashes::Hash;
use candid::{Nat, Principal};
use ic_cdk::call::Call;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use std::str::FromStr;

/// Parsed BOLT11 invoice data needed for offramp processing.
struct ParsedInvoice {
    amount_msat: u64,
    amount_sats: u64,
    payment_hash: Vec<u8>,
    invoice_expiry: u64,
    request_id: String,
}

/// Parse a BOLT11 invoice and extract the fields needed for offramp.
fn parse_offramp_invoice(invoice_str: &str) -> Result<ParsedInvoice, OfframpResponse> {
    let invoice = lightning_invoice::Bolt11Invoice::from_str(invoice_str)
        .map_err(|e| offramp_err(format!("Invalid invoice: {e}")))?;

    let amount_msat = invoice.amount_milli_satoshis()
        .ok_or_else(|| offramp_err("Invoice has no amount specified".to_string()))?;

    let payment_hash_slice: &[u8] = invoice.payment_hash().as_ref();
    let payment_hash = payment_hash_slice.to_vec();
    let invoice_expiry = invoice.expires_at()
        .map(|d| d.as_secs())
        .unwrap_or(ic_cdk::api::time() / 1_000_000_000 + 3600);
    let request_id = hex::encode(&payment_hash);

    Ok(ParsedInvoice {
        amount_msat,
        amount_sats: amount_msat / 1000,
        payment_hash,
        invoice_expiry,
        request_id,
    })
}

/// Compute StableSwap pricing for an offramp (how much ckBTC for the desired BTC output).
fn compute_offramp_pricing(btc_out: u64) -> Result<(u64, u64), OfframpResponse> {
    let state = STATE.read().expect("STATE lock: compute_offramp_pricing");

    let btc_balance: u64 = state.liq_pool.get_total(&PoolAsset::BTC).0.clone().try_into().unwrap_or(0);
    let btc_balance = btc_balance.saturating_add(state.total_btc_in_channels);
    let ckbtc_balance: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC).0.clone().try_into().unwrap_or(0);

    let swap_result = crate::stableswap::get_swap_input(
        &state.stableswap_config,
        btc_balance,
        ckbtc_balance,
        btc_out,
        &crate::stableswap::SwapDirection::CkbtcToBtc,
    ).map_err(|e| offramp_err_with_amount(
        format!("StableSwap pricing error: {e}"), btc_out,
    ))?;

    // output_amount in get_swap_input is the required ckBTC input
    Ok((swap_result.output_amount, swap_result.protocol_fee))
}

/// Collect ICP anti-DDoS fee from the caller via ICRC-2 transfer_from.
async fn collect_icp_fee(
    caller: Principal,
    amount_sats: u64,
) -> Result<Nat, OfframpResponse> {
    let icp_ddos_fee = {
        let state = STATE.read().expect("STATE lock: collect_icp_fee");
        state.icp_ddos_fee_e8s
    };

    let transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc_ledger_types::icrc1::account::Account { owner: caller, subaccount: None },
        to: icrc_ledger_types::icrc1::account::Account { owner: canister_self(), subaccount: None },
        amount: candid::Nat::from(icp_ddos_fee),
        fee: None,
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:offramp_icp_fee".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(*ICP_LEDGER_PRINCIPAL, "icrc2_transfer_from")
        .with_args(&(transfer_args,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,)>().map_err(Into::into))
    {
        Ok((Ok(block_index),)) => Ok(block_index),
        Ok((Err(err),)) => {
            let fee_icp = icp_ddos_fee as f64 / 1e8;
            Err(offramp_err_with_amount(
                format!("Failed to collect ICP anti-DDoS fee: {err:?}. Did you approve {fee_icp} ICP?"),
                amount_sats,
            ))
        }
        Err(e) => Err(offramp_err_with_amount(
            format!("ICP ledger call failed: {e}"),
            amount_sats,
        )),
    }
}

/// Take custody of the user's ckBTC via ICRC-2 transfer_from.
async fn collect_offramp_ckbtc(
    caller: Principal,
    ckbtc_required: u64,
    amount_sats: u64,
    icp_fee_block_index: &Nat,
) -> Result<(), OfframpResponse> {
    let transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc_ledger_types::icrc1::account::Account { owner: caller, subaccount: None },
        to: icrc_ledger_types::icrc1::account::Account { owner: canister_self(), subaccount: None },
        amount: candid::Nat::from(ckbtc_required),
        fee: None,
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:offramp_ckbtc".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(*CKBTC_LEDGER_PRINCIPAL, "icrc2_transfer_from")
        .with_args(&(transfer_args,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,)>().map_err(Into::into))
    {
        Ok((Ok(_),)) => Ok(()),
        Ok((Err(err),)) => {
            ic_cdk::println!("ckBTC collection failed, ICP fee (block {}) not refunded", icp_fee_block_index);
            Err(offramp_err_with_amount(
                format!("Failed to take custody of ckBTC: {err:?}. ICP fee was collected and is NOT refunded."),
                amount_sats,
            ))
        }
        Err(e) => {
            ic_cdk::println!("ckBTC ledger call failed, ICP fee (block {}) not refunded", icp_fee_block_index);
            Err(offramp_err_with_amount(
                format!("ckBTC ICRC-2 transfer_from failed: {e}. ICP fee was collected and is NOT refunded."),
                amount_sats,
            ))
        }
    }
}

/// Construct a failed OfframpResponse with no amount.
fn offramp_err(error: String) -> OfframpResponse {
    OfframpResponse { request_id: String::new(), success: false, amount_sats: None, error: Some(error) }
}

/// Construct a failed OfframpResponse with an amount.
fn offramp_err_with_amount(error: String, amount_sats: u64) -> OfframpResponse {
    OfframpResponse { request_id: String::new(), success: false, amount_sats: Some(amount_sats), error: Some(error) }
}

/// Request an offramp (ckBTC → Lightning)
///
/// Called by a user who wants to pay a Lightning invoice using their ckBTC.
/// Requires prior ICRC-2 approval for the configured ICP anti-DDoS fee + ckBTC amount.
/// The canister takes custody of ICP fee first, then ckBTC.
/// If ckBTC collection fails, ICP fee is NOT refunded (this is the DDoS protection).
/// ICP fee is only refunded on successful Lightning payment completion.
pub async fn request_offramp_impl(request: OfframpRequest) -> OfframpResponse {
    let caller = msg_caller();

    if let Err(e) = check_offramp_rate_limit(caller) {
        return offramp_err(e);
    }

    let inv = match parse_offramp_invoice(&request.invoice) {
        Ok(inv) => inv,
        Err(resp) => return resp,
    };

    // Reject duplicate offramp requests (prevents ckBTC loss via overwrite)
    {
        let state = STATE.read().expect("STATE lock: request_offramp read");
        if state.offramp_requests.contains_key(&inv.request_id) {
            return offramp_err_with_amount(
                "Duplicate offramp request: this invoice has already been submitted".to_string(),
                inv.amount_sats,
            );
        }
    }

    // Check withdrawal caps before proceeding (early rejection)
    {
        let mut state = STATE.write().expect("STATE lock: request_offramp cap check");
        if let Err(cap_err) = super::check_swap_caps(&mut state, inv.amount_sats) {
            return offramp_err_with_amount(cap_err, inv.amount_sats);
        }
    }

    let (ckbtc_required, protocol_fee) = match compute_offramp_pricing(inv.amount_sats) {
        Ok(v) => v,
        Err(resp) => return resp,
    };

    // STEP 1: Collect ICP anti-DDoS fee
    let icp_fee_block_index = match collect_icp_fee(caller, inv.amount_sats).await {
        Ok(idx) => idx,
        Err(resp) => return resp,
    };

    // STEP 2: Take custody of user's ckBTC via ICRC-2
    if let Err(resp) = collect_offramp_ckbtc(caller, ckbtc_required, inv.amount_sats, &icp_fee_block_index).await {
        return resp;
    }

    // Both collections succeeded — store the offramp request
    let request_info = OfframpRequestInfo {
        request_id: inv.request_id.clone(),
        user: caller,
        invoice: request.invoice.clone(),
        amount_sats: inv.amount_sats,
        amount_msat: inv.amount_msat,
        payment_hash: inv.payment_hash,
        invoice_expiry: inv.invoice_expiry,
        fallback_btc_address: request.fallback_btc_address,
        created_at: ic_cdk::api::time(),
        state: OfframpRequestState::Pending,
        preimage: None,
        icp_fee_block_index: Some(icp_fee_block_index),
        icp_fee_refunded: false,
        ckbtc_collected: ckbtc_required,
    };

    {
        let mut state = STATE.write().expect("STATE lock: request_offramp write");
        state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(protocol_fee);
        state.active_offramp_ids.insert(inv.request_id.clone());
        state.offramp_requests.insert(inv.request_id.clone(), request_info);
    }

    notify_relay_webhook("/webhook/offramp");

    OfframpResponse {
        request_id: inv.request_id,
        success: true,
        amount_sats: Some(inv.amount_sats),
        error: None,
    }
}

/// Get all pending offramp requests for the relay to process
///
/// Called by the relay to find requests that need invoices paid.
pub fn get_pending_offramp_requests_impl() -> Vec<PendingOfframpRequest> {
    let state = STATE.read().expect("STATE lock: get_pending_offramp_requests");

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
    let mut state = STATE.write().expect("STATE lock: mark_offramp_in_progress");

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
/// Refunds the ICP anti-DDoS fee to the user on success.
pub async fn complete_offramp_impl(request: CompleteOfframpRequest) -> CompleteOfframpResponse {
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

    // Get the user and verify state, mark as completed, credit LPs with ckBTC
    let user = {
        let mut state = STATE.write().expect("STATE lock: complete_offramp write");

        // Extract data we need before mutating (avoids borrow conflicts)
        let (user, ckbtc_collected, amount_sats) = {
            let request_info = match state.offramp_requests.get(&request.request_id) {
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

            (request_info.user, request_info.ckbtc_collected, request_info.amount_sats)
        };

        // Now mutate
        if let Some(request_info) = state.offramp_requests.get_mut(&request.request_id) {
            request_info.state = OfframpRequestState::Completed {
                preimage: request.preimage.clone(),
            };
            request_info.preimage = Some(request.preimage);
        }
        state.active_offramp_ids.remove(&request.request_id);

        super::record_swap_volume(&mut state, amount_sats);

        // Credit LPs proportionally with the ckBTC collected from the user.
        // LPs are "selling" BTC (via Lightning channel) in exchange for ckBTC.
        if ckbtc_collected > 0 {
            let amount_nat = Nat::from(ckbtc_collected);
            state.liq_pool.credit_proportional(PoolAsset::CkBTC, amount_nat);
        }

        // Update BTC side: Lightning payment sent, so channel BTC decreased
        state.total_btc_in_channels = state.total_btc_in_channels.saturating_sub(amount_sats);

        user
    };

    // Refund ICP fee to the user (on success)
    // Mark as refunded BEFORE the call to prevent double-refund race
    {
        let mut state = STATE.write().expect("STATE lock: complete_offramp write 2");
        if let Some(request_info) = state.offramp_requests.get_mut(&request.request_id) {
            request_info.icp_fee_refunded = true;
        }
    }
    let refund_result = refund_icp_fee(user).await;
    if let Err(e) = refund_result {
        ic_cdk::println!("Warning: Failed to refund ICP fee for offramp: {}", e);
        // Roll back the flag so a retry can attempt the refund
        let mut state = STATE.write().expect("STATE lock: complete_offramp write 3");
        if let Some(request_info) = state.offramp_requests.get_mut(&request.request_id) {
            request_info.icp_fee_refunded = false;
        }
    }

    CompleteOfframpResponse {
        success: true,
        error: None,
    }
}

/// Transfer ckBTC back to a user and update offramp request state.
/// Shared by fail_offramp_impl and retry_offramp_refund_impl.
async fn refund_ckbtc_to_user(
    request_id: &str,
    user: Principal,
    ckbtc_collected: u64,
    memo: &[u8],
) -> FailOfframpResponse {
    let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
        from_subaccount: None,
        to: icrc_ledger_types::icrc1::account::Account { owner: user, subaccount: None },
        amount: candid::Nat::from(ckbtc_collected),
        fee: None,
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(memo.to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(*CKBTC_LEDGER_PRINCIPAL, "icrc1_transfer")
        .with_args(&(transfer_args,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
        Ok((Ok(block_index),)) => {
            let mut state = STATE.write().expect("STATE lock: refund_ckbtc write");
            if let Some(info) = state.offramp_requests.get_mut(request_id) {
                info.state = OfframpRequestState::Refunded { block_index: block_index.clone() };
            }
            state.active_offramp_ids.remove(request_id);
            FailOfframpResponse { success: true, refund_block_index: Some(block_index), error: None }
        }
        Ok((Err(err),)) => FailOfframpResponse {
            success: false, refund_block_index: None,
            error: Some(format!("Refund transfer failed (retryable): {err:?}")),
        },
        Err(e) => FailOfframpResponse {
            success: false, refund_block_index: None,
            error: Some(format!("Refund call failed (retryable): {e}")),
        },
    }
}

/// Fail an offramp request and initiate refund
///
/// Called by the relay when it fails to pay the Lightning invoice.
/// The ckBTC is refunded to the user.
pub async fn fail_offramp_impl(request: FailOfframpRequest) -> FailOfframpResponse {
    let (user, ckbtc_collected) = {
        let mut state = STATE.write().expect("STATE lock: fail_offramp write");

        let request_info = match state.offramp_requests.get_mut(&request.request_id) {
            Some(info) => info,
            None => {
                return FailOfframpResponse {
                    success: false, refund_block_index: None,
                    error: Some("Request not found".to_string()),
                };
            }
        };

        if !matches!(request_info.state,
            OfframpRequestState::Pending
            | OfframpRequestState::PaymentInProgress
            | OfframpRequestState::FailedPendingRefund { .. }
        ) {
            return FailOfframpResponse {
                success: false, refund_block_index: None,
                error: Some(format!("Invalid state for failure: {:?}", request_info.state)),
            };
        }

        request_info.state = OfframpRequestState::FailedPendingRefund {
            reason: request.reason.clone(),
        };

        (request_info.user, request_info.ckbtc_collected)
    };

    refund_ckbtc_to_user(&request.request_id, user, ckbtc_collected, b"ckl:offramp_fail_refund").await
}

/// Retry a failed offramp refund
///
/// Called by admin/relay to retry ckBTC refund for requests stuck in FailedPendingRefund.
pub async fn retry_offramp_refund_impl(request_id: String) -> FailOfframpResponse {
    let (user, ckbtc_collected) = {
        let state = STATE.read().expect("STATE lock: retry_offramp_refund read");

        let request_info = match state.offramp_requests.get(&request_id) {
            Some(info) => info,
            None => {
                return FailOfframpResponse {
                    success: false, refund_block_index: None,
                    error: Some("Request not found".to_string()),
                };
            }
        };

        if !matches!(request_info.state, OfframpRequestState::FailedPendingRefund { .. }) {
            return FailOfframpResponse {
                success: false, refund_block_index: None,
                error: Some(format!("Request not in FailedPendingRefund state: {:?}", request_info.state)),
            };
        }

        (request_info.user, request_info.ckbtc_collected)
    };

    refund_ckbtc_to_user(&request_id, user, ckbtc_collected, b"ckl:offramp_retry_refund").await
}

/// Get the status of an offramp request
///
/// Called by users to check the status of their offramp.
/// Only the requesting user or the registered relay can query a given request.
pub fn get_offramp_status_impl(request_id: String) -> GetOfframpStatusResponse {
    let caller = ic_cdk::api::msg_caller();
    let state = STATE.read().expect("STATE lock: get_offramp_status");

    match state.offramp_requests.get(&request_id) {
        Some(info) => {
            let is_owner = info.user == caller;
            let is_relay = matches!(&state.registered_relay, Some(r) if r.principal == caller);
            if !is_owner && !is_relay {
                return GetOfframpStatusResponse {
                    state: OfframpRequestState::Failed {
                        reason: "Request not found".to_string(),
                    },
                    amount_sats: 0,
                    error: Some("Request not found".to_string()),
                };
            }
            GetOfframpStatusResponse {
                state: info.state.clone(),
                amount_sats: info.amount_sats,
                error: None,
            }
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
