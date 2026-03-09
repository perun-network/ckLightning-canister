// =============================================================================
// Onramp Invoice Request Implementation (Canister-First Flow)
// =============================================================================

use super::STATE;
use super::admin::{check_onramp_rate_limit, verify_invoice_node_pubkey};
use super::http_outcall::notify_relay_webhook;
use crate::ic_types::{
    DEVNET_ICP_LEDGER,
    OnrampInvoiceRequest, OnrampInvoiceResponse, OnrampRequestInfo, OnrampRequestState,
    PendingInvoiceRequest, SubmitInvoiceRequest, SubmitInvoiceResponse, GetInvoiceResponse,
    SwapInfo, SwapState,
};

use bitcoin::hashes::{Hash, sha256};
use candid::{Nat, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use std::str::FromStr;

/// Request a new onramp invoice
///
/// Called by clients to initiate a Lightning → ckBTC swap.
/// Creates a pending request that the relay will fulfill with an actual invoice.
/// Requires prior ICRC-2 approval for the configured ICP anti-DDoS fee.
pub async fn request_onramp_invoice_impl(request: OnrampInvoiceRequest) -> OnrampInvoiceResponse {
    let caller = msg_caller();

    // Check rate limit FIRST (before collecting fee)
    if let Err(e) = check_onramp_rate_limit(caller) {
        return OnrampInvoiceResponse {
            request_id: String::new(),
            success: false,
            error: Some(e),
        };
    }

    // Validate amount
    if request.amount_sats == 0 {
        return OnrampInvoiceResponse {
            request_id: String::new(),
            success: false,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Read configured ICP anti-DDoS fee from state
    let icp_ddos_fee = {
        let state = STATE.read().expect("STATE lock: request_onramp_invoice read");
        state.icp_ddos_fee_e8s
    };

    // Collect ICP anti-DDoS fee upfront via ICRC-2 transfer_from
    let icp_ledger = Principal::from_text(DEVNET_ICP_LEDGER).unwrap();
    let canister_principal = canister_self();

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
        amount: candid::Nat::from(icp_ddos_fee),
        fee: None,
        memo: None,
        created_at_time: Some(ic_cdk::api::time()),
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,
    )> = ic_cdk::call(icp_ledger, "icrc2_transfer_from", (transfer_args,)).await;

    let icp_fee_block_index = match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => block_index,
            Err(err) => {
                let fee_icp = icp_ddos_fee as f64 / 1e8;
                return OnrampInvoiceResponse {
                    request_id: String::new(),
                    success: false,
                    error: Some(format!("Failed to collect ICP anti-DDoS fee: {:?}. Did you approve {} ICP?", err, fee_icp)),
                };
            }
        },
        Err((code, msg)) => {
            return OnrampInvoiceResponse {
                request_id: String::new(),
                success: false,
                error: Some(format!("ICP ledger call failed: {:?} - {}", code, msg)),
            };
        }
    };

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

    // Create the request info with ICP fee tracking
    let request_info = OnrampRequestInfo {
        request_id: request_id.clone(),
        recipient: request.recipient,
        amount_sats: request.amount_sats,
        created_at: now,
        state: OnrampRequestState::Pending,
        invoice: None,
        payment_hash: None,
        expiry_timestamp: None,
        icp_fee_payer: Some(caller),
        icp_fee_block_index: Some(icp_fee_block_index),
        icp_fee_refunded: false,
    };

    // Store the request
    {
        let mut state = STATE.write().expect("STATE lock: request_onramp_invoice write");
        state.onramp_requests.insert(request_id.clone(), request_info);
    }

    // Notify relay via webhook outcall (fire-and-forget)
    notify_relay_webhook("/webhook/onramp");

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
    let state = STATE.read().expect("STATE lock: get_pending_invoice_requests");

    state.onramp_requests
        .values()
        .filter(|req| matches!(req.state, OnrampRequestState::Pending))
        .map(|req| PendingInvoiceRequest {
            request_id: req.request_id.clone(),
            recipient: req.recipient,
            amount_sats: req.amount_sats,
            amount_msat: req.amount_sats.saturating_mul(1000),
            created_at: req.created_at,
        })
        .collect()
}

/// Submit a created invoice for a pending request
///
/// Called by the relay after creating a BOLT11 invoice.
/// Also registers the swap so complete_swap works later.
///
/// **Security:** Verifies that the invoice was created by the registered relay node.
/// This prevents invoice substitution attacks where a malicious relay could redirect
/// payments to a different node.
pub fn submit_invoice_impl(request: SubmitInvoiceRequest) -> SubmitInvoiceResponse {
    // Validate payment_hash length
    if request.payment_hash.len() != 32 {
        return SubmitInvoiceResponse {
            success: false,
            error: Some("Invalid payment_hash length (must be 32 bytes)".to_string()),
        };
    }

    // SECURITY: Verify the invoice was created by the registered relay node
    // This prevents invoice substitution attacks
    if let Err(e) = verify_invoice_node_pubkey(&request.invoice) {
        ic_cdk::println!("Invoice verification FAILED: {}", e);
        return SubmitInvoiceResponse {
            success: false,
            error: Some(format!("Invoice verification failed: {}", e)),
        };
    }

    // SECURITY: Parse BOLT11 and verify payment_hash and amount match the submitted values.
    // This prevents a compromised relay from submitting mismatched invoices.
    let parsed_invoice = match lightning_invoice::Bolt11Invoice::from_str(&request.invoice) {
        Ok(inv) => inv,
        Err(e) => {
            return SubmitInvoiceResponse {
                success: false,
                error: Some(format!("Invalid BOLT11 invoice: {}", e)),
            };
        }
    };

    // Verify payment_hash matches
    let invoice_payment_hash: &[u8] = parsed_invoice.payment_hash().as_ref();
    if invoice_payment_hash != request.payment_hash.as_slice() {
        return SubmitInvoiceResponse {
            success: false,
            error: Some("Invoice payment_hash does not match submitted payment_hash".to_string()),
        };
    }

    // Verify amount matches the request
    if let Some(invoice_msat) = parsed_invoice.amount_milli_satoshis() {
        // Look up the request to get expected amount
        let expected_msat = {
            let state = STATE.read().expect("STATE lock: submit_invoice read");
            state.onramp_requests.get(&request.request_id)
                .map(|req| req.amount_sats.saturating_mul(1000))
        };
        if let Some(expected) = expected_msat {
            if invoice_msat != expected {
                return SubmitInvoiceResponse {
                    success: false,
                    error: Some(format!(
                        "Invoice amount {}msat does not match request amount {}msat",
                        invoice_msat, expected
                    )),
                };
            }
        }
    }

    let mut state = STATE.write().expect("STATE lock: submit_invoice write");

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

    // Update the request with invoice info (verified)
    request_info.invoice = Some(request.invoice);
    request_info.payment_hash = Some(request.payment_hash.clone());
    request_info.expiry_timestamp = Some(request.expiry_timestamp);
    request_info.state = OnrampRequestState::Ready;

    // Also register the swap (so complete_swap works)
    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    let swap_info = SwapInfo {
        payment_hash: request.payment_hash,
        amount_msat: request_info.amount_sats.saturating_mul(1000),
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
    let state = STATE.read().expect("STATE lock: get_invoice_by_request");

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
    let mut state = STATE.write().expect("STATE lock: mark_onramp_completed");

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
