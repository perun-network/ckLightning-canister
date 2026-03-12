// =============================================================================
// Offramp Implementation (ckBTC → Lightning)
// =============================================================================

use super::STATE;
use super::admin::check_offramp_rate_limit;
use super::http_outcall::notify_relay_webhook;
use super::swaps::refund_icp_fee;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    DEVNET_CKBTC_LEDGER, DEVNET_ICP_LEDGER,
    OfframpRequest, OfframpResponse, OfframpRequestInfo, OfframpRequestState,
    PendingOfframpRequest, CompleteOfframpRequest, CompleteOfframpResponse,
    FailOfframpRequest, FailOfframpResponse, GetOfframpStatusResponse,
};

use bitcoin::hashes::Hash;
use candid::{Nat, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use std::str::FromStr;

/// Request an offramp (ckBTC → Lightning)
///
/// Called by a user who wants to pay a Lightning invoice using their ckBTC.
/// Requires prior ICRC-2 approval for the configured ICP anti-DDoS fee + ckBTC amount.
/// The canister takes custody of ICP fee first, then ckBTC.
/// If ckBTC collection fails, ICP fee is NOT refunded (this is the DDoS protection).
/// ICP fee is only refunded on successful Lightning payment completion.
pub async fn request_offramp_impl(request: OfframpRequest) -> OfframpResponse {
    let caller = msg_caller();

    // Check rate limit FIRST (before collecting fee)
    if let Err(e) = check_offramp_rate_limit(caller) {
        return OfframpResponse {
            request_id: String::new(),
            success: false,
            amount_sats: None,
            error: Some(e),
        };
    }

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

    // BTC amount the user wants to receive via Lightning
    let btc_out = amount_msat / 1000;

    // Extract payment hash
    let payment_hash_slice: &[u8] = invoice.payment_hash().as_ref();
    let payment_hash = payment_hash_slice.to_vec();

    // Get invoice expiry
    let invoice_expiry = invoice.expires_at()
        .map(|d| d.as_secs())
        .unwrap_or(ic_cdk::api::time() / 1_000_000_000 + 3600); // Default 1 hour

    // Generate request_id from full payment_hash
    let request_id = payment_hash.iter()
        .map(|b| format!("{:02x}", b))
        .collect::<String>();

    // Reject duplicate offramp requests for the same invoice (prevents ckBTC loss via overwrite)
    {
        let state = STATE.read().expect("STATE lock: request_offramp read");
        if state.offramp_requests.contains_key(&request_id) {
            return OfframpResponse {
                request_id,
                success: false,
                amount_sats: Some(btc_out as u64),
                error: Some("Duplicate offramp request: this invoice has already been submitted".to_string()),
            };
        }
    }

    // Check withdrawal caps before proceeding (early rejection)
    {
        let mut state = STATE.write().expect("STATE lock: request_offramp cap check");
        if let Err(cap_err) = super::check_swap_caps(&mut state, btc_out as u64) {
            return OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: Some(btc_out as u64),
                error: Some(cap_err),
            };
        }
    }

    // Use StableSwap to compute how much ckBTC the user must pay for the desired BTC output
    let (ckbtc_required, amount_sats, protocol_fee) = {
        let state = STATE.read().expect("STATE lock: request_offramp read 2");

        // BTC balance includes channel BTC for StableSwap pricing
        let btc_balance: u64 = state.liq_pool.get_total(&PoolAsset::BTC).0.clone().try_into().unwrap_or(0);
        let btc_balance = btc_balance.saturating_add(state.total_btc_in_channels);
        let ckbtc_balance: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC).0.clone().try_into().unwrap_or(0);

        match crate::stableswap::get_swap_input(
            &state.stableswap_config,
            btc_balance,
            ckbtc_balance,
            btc_out as u64,
            &crate::stableswap::SwapDirection::CkbtcToBtc,
        ) {
            Ok(swap_result) => {
                // Don't track protocol fees yet — only after both ICP and ckBTC collection succeed.
                // output_amount in get_swap_input is the required input
                (swap_result.output_amount, btc_out as u64, swap_result.protocol_fee)
            }
            Err(e) => {
                return OfframpResponse {
                    request_id: String::new(),
                    success: false,
                    amount_sats: Some(btc_out as u64),
                    error: Some(format!("StableSwap pricing error: {}", e)),
                };
            }
        }
    };

    let canister_principal = canister_self();

    // Read configured ICP anti-DDoS fee from state
    let icp_ddos_fee = {
        let state = STATE.read().expect("STATE lock: request_offramp read 3");
        state.icp_ddos_fee_e8s
    };

    // STEP 1: Collect ICP anti-DDoS fee first
    let icp_ledger = Principal::from_text(DEVNET_ICP_LEDGER).unwrap();
    let icp_transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
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

    let icp_call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,
    )> = ic_cdk::call(icp_ledger, "icrc2_transfer_from", (icp_transfer_args,)).await;

    let icp_fee_block_index = match icp_call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => block_index,
            Err(err) => {
                let fee_icp = icp_ddos_fee as f64 / 1e8;
                return OfframpResponse {
                    request_id: String::new(),
                    success: false,
                    amount_sats: Some(amount_sats),
                    error: Some(format!("Failed to collect ICP anti-DDoS fee: {:?}. Did you approve {} ICP?", err, fee_icp)),
                };
            }
        },
        Err((code, msg)) => {
            return OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: Some(amount_sats),
                error: Some(format!("ICP ledger call failed: {:?} - {}", code, msg)),
            };
        }
    };

    // STEP 2: Take custody of user's ckBTC via ICRC-2 transfer_from
    // User must have called icrc2_approve(ckLightning canister, ckbtc_required + fee) first
    // ckbtc_required includes the StableSwap premium over 1:1
    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap();

    // Transfer ckBTC from user to canister (StableSwap-computed amount)
    let ckbtc_transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc_ledger_types::icrc1::account::Account {
            owner: caller,
            subaccount: None,
        },
        to: icrc_ledger_types::icrc1::account::Account {
            owner: canister_principal,
            subaccount: None,
        },
        amount: candid::Nat::from(ckbtc_required),
        fee: None,
        memo: None,
        created_at_time: Some(ic_cdk::api::time()),
    };

    let ckbtc_call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc2_transfer_from", (ckbtc_transfer_args,)).await;

    match ckbtc_call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(_block_index) => {
                // Success - store the offramp request with ICP fee info
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
                    icp_fee_block_index: Some(icp_fee_block_index),
                    icp_fee_refunded: false,
                    ckbtc_collected: ckbtc_required,
                };

                {
                    let mut state = STATE.write().expect("STATE lock: request_offramp write");
                    // Track protocol fees only AFTER both ICP and ckBTC collection succeeded
                    state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(protocol_fee);
                    state.offramp_requests.insert(request_id.clone(), request_info);
                }

                // Notify relay via webhook outcall (fire-and-forget)
                notify_relay_webhook("/webhook/offramp");

                OfframpResponse {
                    request_id,
                    success: true,
                    amount_sats: Some(amount_sats),
                    error: None,
                }
            }
            Err(err) => {
                // ckBTC collection failed - ICP fee is NOT refunded (DDoS protection)
                ic_cdk::println!("ckBTC collection failed, ICP fee (block {}) not refunded", icp_fee_block_index);
                OfframpResponse {
                    request_id: String::new(),
                    success: false,
                    amount_sats: Some(amount_sats),
                    error: Some(format!("Failed to take custody of ckBTC: {:?}. ICP fee was collected and is NOT refunded.", err)),
                }
            }
        },
        Err((code, msg)) => {
            // ckBTC ledger call failed - ICP fee is NOT refunded (DDoS protection)
            ic_cdk::println!("ckBTC ledger call failed, ICP fee (block {}) not refunded", icp_fee_block_index);
            OfframpResponse {
                request_id: String::new(),
                success: false,
                amount_sats: Some(amount_sats),
                error: Some(format!("ckBTC ICRC-2 transfer_from failed: {:?} - {}. ICP fee was collected and is NOT refunded.", code, msg)),
            }
        }
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

        // Mark as completed and record volume
        request_info.state = OfframpRequestState::Completed {
            preimage: request.preimage.clone(),
        };
        request_info.preimage = Some(request.preimage);

        let user = request_info.user;
        let ckbtc_collected = request_info.ckbtc_collected;
        let amount_sats = request_info.amount_sats;

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
                    success: false,
                    refund_block_index: None,
                    error: Some("Request not found".to_string()),
                };
            }
        };

        // Check state — allow retry from FailedPendingRefund (refund transfer failed previously)
        if !matches!(request_info.state,
            OfframpRequestState::Pending
            | OfframpRequestState::PaymentInProgress
            | OfframpRequestState::FailedPendingRefund { .. }
        ) {
            return FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Invalid state for failure: {:?}", request_info.state)),
            };
        }

        // Mark as pending refund — the ckBTC transfer hasn't succeeded yet
        request_info.state = OfframpRequestState::FailedPendingRefund {
            reason: request.reason.clone(),
        };

        // Refund ckbtc_collected (the actual amount taken from the user), NOT amount_sats
        // (which is the BTC invoice amount before StableSwap premium).
        (request_info.user, request_info.ckbtc_collected)
    };

    // Refund ckBTC to user
    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap();

    let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
        from_subaccount: None,
        to: icrc_ledger_types::icrc1::account::Account {
            owner: user,
            subaccount: None,
        },
        amount: candid::Nat::from(ckbtc_collected),
        fee: None,
        memo: None,
        created_at_time: Some(ic_cdk::api::time()),
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc1_transfer", (transfer_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                // Update state to refunded
                let mut state = STATE.write().expect("STATE lock: fail_offramp write 2");
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
                // State remains FailedPendingRefund — retryable
                FailOfframpResponse {
                    success: false,
                    refund_block_index: None,
                    error: Some(format!("Refund transfer failed (retryable): {:?}", err)),
                }
            }
        },
        Err((code, msg)) => {
            // State remains FailedPendingRefund — retryable
            FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Refund call failed (retryable): {:?} - {}", code, msg)),
            }
        }
    }
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
                    success: false,
                    refund_block_index: None,
                    error: Some("Request not found".to_string()),
                };
            }
        };

        if !matches!(request_info.state, OfframpRequestState::FailedPendingRefund { .. }) {
            return FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Request not in FailedPendingRefund state: {:?}", request_info.state)),
            };
        }

        (request_info.user, request_info.ckbtc_collected)
    };

    // Retry ckBTC refund
    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap();

    let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
        from_subaccount: None,
        to: icrc_ledger_types::icrc1::account::Account {
            owner: user,
            subaccount: None,
        },
        amount: candid::Nat::from(ckbtc_collected),
        fee: None,
        memo: None,
        created_at_time: Some(ic_cdk::api::time()),
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc1_transfer", (transfer_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                let mut state = STATE.write().expect("STATE lock: retry_offramp_refund write");
                if let Some(request_info) = state.offramp_requests.get_mut(&request_id) {
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
                    error: Some(format!("Refund transfer failed (retryable): {:?}", err)),
                }
            }
        },
        Err((code, msg)) => {
            FailOfframpResponse {
                success: false,
                refund_block_index: None,
                error: Some(format!("Refund call failed (retryable): {:?} - {}", code, msg)),
            }
        }
    }
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
