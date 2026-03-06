// =============================================================================
// Swap Timeout Handling + Relay Registration + Rate Limiting + StableSwap Admin
// =============================================================================

use super::STATE;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    DEVNET_CKBTC_LEDGER, DEVNET_ICP_LEDGER, ICP_TRANSFER_FEE_E8S,
    ONRAMP_TIMEOUT_NS, OFFRAMP_TIMEOUT_NS, DEFAULT_CKBTC_FEE,
    OnrampRequestState, OfframpRequestState,
    RegisterRelayRequest, RegisterRelayResponse, GetRelayInfoResponse,
    RelayRegistration,
    RateLimitInfo, RateLimitStatus,
    RATE_LIMIT_WINDOW_NS, MAX_ONRAMP_REQUESTS_PER_WINDOW, MAX_OFFRAMP_REQUESTS_PER_WINDOW,
    SwapQuoteRequest, SwapQuoteResponse,
    UpdateStableSwapConfigRequest, UpdateStableSwapConfigResponse,
    WithdrawProtocolFeesResponse,
    SetIcpDdosFeeResponse, WithdrawIcpFeesResponse, RedistributeFeesResponse,
    StableSwapConfig,
};

use candid::{Nat, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use std::str::FromStr;

// =============================================================================
// Swap Timeout Handling
// =============================================================================

/// Check for expired swap requests and handle them appropriately.
///
/// - Onramp: Mark as Expired, DO NOT refund ICP fee (anti-DDoS)
/// - Offramp: Mark as Expired, refund ckBTC to user (not LP!)
///
/// This function is called periodically by the heartbeat.
pub async fn check_expired_swaps_impl() {
    let now = blocktime();

    // Get timeout values (use test overrides if set)
    let (onramp_timeout, offramp_timeout) = {
        let state = STATE.read().unwrap();
        (
            state.test_onramp_timeout_ns.unwrap_or(ONRAMP_TIMEOUT_NS),
            state.test_offramp_timeout_ns.unwrap_or(OFFRAMP_TIMEOUT_NS),
        )
    };

    // First, collect expired onramp request IDs
    let expired_onramp_ids: Vec<String> = {
        let state = STATE.read().unwrap();
        state.onramp_requests
            .iter()
            .filter(|(_, req)| {
                matches!(req.state, OnrampRequestState::Pending | OnrampRequestState::Ready)
                    && now > req.created_at + onramp_timeout
            })
            .map(|(id, _)| id.clone())
            .collect()
    };

    // Mark expired onramp requests AND their corresponding SwapInfo entries
    if !expired_onramp_ids.is_empty() {
        let mut state = STATE.write().unwrap();

        // Collect payment hashes to expire from swaps map
        let mut swap_hashes_to_expire: Vec<[u8; 32]> = Vec::new();
        for id in &expired_onramp_ids {
            if let Some(req) = state.onramp_requests.get_mut(id) {
                if let Some(ref ph) = req.payment_hash {
                    if ph.len() == 32 {
                        let mut hash_arr = [0u8; 32];
                        hash_arr.copy_from_slice(ph);
                        swap_hashes_to_expire.push(hash_arr);
                    }
                }
                req.state = OnrampRequestState::Expired;
                ic_cdk::println!("Onramp request {} expired (ICP fee not refunded)", id);
            }
        }

        // Now expire the corresponding SwapInfo entries
        for hash_arr in swap_hashes_to_expire {
            if let Some(swap) = state.swaps.get_mut(&hash_arr) {
                if matches!(swap.state, crate::ic_types::SwapState::Pending) {
                    swap.state = crate::ic_types::SwapState::Expired;
                }
            }
        }
    }

    // Collect expired offramp requests that need refunds
    let expired_offramp_requests: Vec<(String, Principal, u64)> = {
        let state = STATE.read().unwrap();
        state.offramp_requests
            .iter()
            .filter(|(_, req)| {
                // Only expire Pending requests — NEVER expire PaymentInProgress.
                // If the relay is actively paying an invoice, expiring it would cause
                // the user to get both a ckBTC refund AND the BTC Lightning payment.
                matches!(req.state, OfframpRequestState::Pending)
                    && now > req.created_at + offramp_timeout
            })
            .map(|(id, req)| (id.clone(), req.user, req.ckbtc_collected))
            .collect()
    };

    // Process offramp expirations one at a time (each requires async refund)
    for (request_id, user, ckbtc_collected) in expired_offramp_requests {
        // Mark as expired first
        {
            let mut state = STATE.write().unwrap();
            if let Some(req) = state.offramp_requests.get_mut(&request_id) {
                // Double-check state hasn't changed
                if !matches!(req.state, OfframpRequestState::Pending) {
                    continue;
                }
                req.state = OfframpRequestState::Expired { refund_block_index: None };
                ic_cdk::println!("Offramp request {} expired, initiating ckBTC refund to user", request_id);
            }
        }

        // Refund ckBTC to user (not to LP!)
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
            created_at_time: None,
        };

        let call_result: CallResult<(
            Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
        )> = ic_cdk::call(ckbtc_ledger, "icrc1_transfer", (transfer_args,)).await;

        match call_result {
            Ok((inner_result,)) => match inner_result {
                Ok(block_index) => {
                    let mut state = STATE.write().unwrap();
                    if let Some(req) = state.offramp_requests.get_mut(&request_id) {
                        req.state = OfframpRequestState::Expired {
                            refund_block_index: Some(block_index.clone()),
                        };
                        ic_cdk::println!(
                            "Offramp {} ckBTC refunded to user, block_index: {}",
                            request_id,
                            block_index
                        );
                    }
                }
                Err(err) => {
                    ic_cdk::println!(
                        "Failed to refund ckBTC for expired offramp {}: {:?}",
                        request_id,
                        err
                    );
                }
            },
            Err((code, msg)) => {
                ic_cdk::println!(
                    "ckBTC refund call failed for offramp {}: {:?} - {}",
                    request_id,
                    code,
                    msg
                );
            }
        }
    }
}

/// Get count of expired swaps for monitoring
pub fn get_expired_swap_counts() -> (u64, u64) {
    let state = STATE.read().unwrap();

    let expired_onramp = state.onramp_requests
        .values()
        .filter(|r| matches!(r.state, OnrampRequestState::Expired))
        .count() as u64;

    let expired_offramp = state.offramp_requests
        .values()
        .filter(|r| matches!(r.state, OfframpRequestState::Expired { .. }))
        .count() as u64;

    (expired_onramp, expired_offramp)
}

/// Set test timeout values for E2E testing.
///
/// Pass 0 to reset to default values.
/// This allows tests to use shorter timeouts instead of waiting 10-30 minutes.
pub fn set_test_timeouts_impl(onramp_timeout_ns: u64, offramp_timeout_ns: u64) {
    let mut state = STATE.write().unwrap();

    state.test_onramp_timeout_ns = if onramp_timeout_ns == 0 {
        None
    } else {
        Some(onramp_timeout_ns)
    };

    state.test_offramp_timeout_ns = if offramp_timeout_ns == 0 {
        None
    } else {
        Some(offramp_timeout_ns)
    };

    ic_cdk::println!(
        "Test timeouts set: onramp={:?}ns, offramp={:?}ns",
        state.test_onramp_timeout_ns,
        state.test_offramp_timeout_ns
    );
}

/// Get current timeout values (for testing/debugging)
pub fn get_timeout_values_impl() -> (u64, u64) {
    let state = STATE.read().unwrap();
    (
        state.test_onramp_timeout_ns.unwrap_or(ONRAMP_TIMEOUT_NS),
        state.test_offramp_timeout_ns.unwrap_or(OFFRAMP_TIMEOUT_NS),
    )
}

// =============================================================================
// Relay Registration Functions
// =============================================================================

/// Register a relay with its Lightning node pubkey.
pub fn register_relay_impl(request: RegisterRelayRequest) -> RegisterRelayResponse {
    let caller = msg_caller();

    // Validate node pubkey format (33 bytes compressed secp256k1)
    if request.node_pubkey.len() != 33 {
        return RegisterRelayResponse {
            success: false,
            error: Some("node_pubkey must be 33 bytes (compressed secp256k1)".to_string()),
        };
    }

    // Validate it's a valid compressed public key (starts with 0x02 or 0x03)
    let first_byte = request.node_pubkey[0];
    if first_byte != 0x02 && first_byte != 0x03 {
        return RegisterRelayResponse {
            success: false,
            error: Some("Invalid compressed pubkey format (must start with 0x02 or 0x03)".to_string()),
        };
    }

    let mut state = STATE.write().unwrap();

    // Check if a relay is already registered
    if let Some(existing) = &state.registered_relay {
        // Allow re-registration by the same principal (to update pubkey)
        if existing.principal != caller {
            return RegisterRelayResponse {
                success: false,
                error: Some(format!(
                    "A relay is already registered. Existing principal: {}",
                    existing.principal
                )),
            };
        }
    }

    // Register the relay
    let registration = RelayRegistration {
        principal: caller,
        node_pubkey: request.node_pubkey.clone(),
        registered_at: blocktime(),
        is_active: true,
        relay_http_url: request.relay_http_url.clone(),
        relay_auth_token: request.relay_auth_token.clone(),
    };

    ic_cdk::println!(
        "Relay registered: principal={}, node_pubkey={}, http_url={:?}",
        caller,
        hex::encode(&request.node_pubkey),
        request.relay_http_url
    );

    state.registered_relay = Some(registration);

    RegisterRelayResponse {
        success: true,
        error: None,
    }
}

/// Get information about the registered relay.
pub fn get_relay_info_impl() -> GetRelayInfoResponse {
    let state = STATE.read().unwrap();

    match &state.registered_relay {
        Some(relay) => GetRelayInfoResponse {
            registered: true,
            principal: Some(relay.principal),
            node_pubkey: Some(relay.node_pubkey.clone()),
            is_active: Some(relay.is_active),
        },
        None => GetRelayInfoResponse {
            registered: false,
            principal: None,
            node_pubkey: None,
            is_active: None,
        },
    }
}

/// Helper function to extract the payee (destination) node pubkey from a BOLT11 invoice.
fn extract_node_pubkey_from_invoice(invoice_str: &str) -> Result<Vec<u8>, String> {
    let invoice = lightning_invoice::Bolt11Invoice::from_str(invoice_str)
        .map_err(|e| format!("Invalid BOLT11 invoice: {}", e))?;

    // Get the payee public key
    let payee_pubkey = invoice.recover_payee_pub_key();

    // Convert to serialized bytes (33 bytes compressed)
    Ok(payee_pubkey.serialize().to_vec())
}

/// Verify that an invoice was created by the registered relay node.
///
/// This is called during submit_invoice to prevent invoice substitution attacks.
pub(super) fn verify_invoice_node_pubkey(invoice_str: &str) -> Result<(), String> {
    let state = STATE.read().unwrap();

    // Get registered relay
    let relay = match &state.registered_relay {
        Some(r) => r,
        None => {
            return Err("No relay registered. Call register_relay first.".to_string());
        }
    };

    if !relay.is_active {
        return Err("Registered relay is not active".to_string());
    }

    // Extract node pubkey from invoice
    let invoice_pubkey = extract_node_pubkey_from_invoice(invoice_str)?;

    // Compare with registered relay pubkey
    if invoice_pubkey != relay.node_pubkey {
        return Err(format!(
            "Invoice node pubkey mismatch! Expected: {}, Got: {}. This could indicate an invoice substitution attack.",
            hex::encode(&relay.node_pubkey),
            hex::encode(&invoice_pubkey)
        ));
    }

    Ok(())
}

// =============================================================================
// Rate Limiting Functions
// =============================================================================

/// Check if a principal is rate limited for onramp requests.
/// Returns Ok(()) if allowed, Err(message) if rate limited.
/// Also increments the request count if allowed.
pub(super) fn check_onramp_rate_limit(caller: Principal) -> Result<(), String> {
    let now = blocktime();
    let mut state = STATE.write().unwrap();

    if let Some(info) = state.onramp_rate_limits.get_mut(&caller) {
        // Check if window has expired
        if now >= info.window_start + RATE_LIMIT_WINDOW_NS {
            // Reset window
            info.window_start = now;
            info.request_count = 1;
            Ok(())
        } else if info.request_count >= MAX_ONRAMP_REQUESTS_PER_WINDOW {
            // Rate limited
            let reset_in_ns = (info.window_start + RATE_LIMIT_WINDOW_NS).saturating_sub(now);
            let reset_in_secs = reset_in_ns / 1_000_000_000;
            Err(format!(
                "Rate limited: {} onramp requests per hour exceeded. Try again in {} seconds.",
                MAX_ONRAMP_REQUESTS_PER_WINDOW, reset_in_secs
            ))
        } else {
            // Increment and allow
            info.request_count += 1;
            Ok(())
        }
    } else {
        // First request from this principal
        state.onramp_rate_limits.insert(caller, RateLimitInfo::new(now));
        Ok(())
    }
}

/// Check if a principal is rate limited for offramp requests.
/// Returns Ok(()) if allowed, Err(message) if rate limited.
/// Also increments the request count if allowed.
pub(super) fn check_offramp_rate_limit(caller: Principal) -> Result<(), String> {
    let now = blocktime();
    let mut state = STATE.write().unwrap();

    if let Some(info) = state.offramp_rate_limits.get_mut(&caller) {
        // Check if window has expired
        if now >= info.window_start + RATE_LIMIT_WINDOW_NS {
            // Reset window
            info.window_start = now;
            info.request_count = 1;
            Ok(())
        } else if info.request_count >= MAX_OFFRAMP_REQUESTS_PER_WINDOW {
            // Rate limited
            let reset_in_ns = (info.window_start + RATE_LIMIT_WINDOW_NS).saturating_sub(now);
            let reset_in_secs = reset_in_ns / 1_000_000_000;
            Err(format!(
                "Rate limited: {} offramp requests per hour exceeded. Try again in {} seconds.",
                MAX_OFFRAMP_REQUESTS_PER_WINDOW, reset_in_secs
            ))
        } else {
            // Increment and allow
            info.request_count += 1;
            Ok(())
        }
    } else {
        // First request from this principal
        state.offramp_rate_limits.insert(caller, RateLimitInfo::new(now));
        Ok(())
    }
}

/// Get rate limit status for a principal.
pub fn get_rate_limit_status_impl(principal: Principal) -> RateLimitStatus {
    let now = blocktime();
    let state = STATE.read().unwrap();

    let (onramp_count, onramp_window_start) = match state.onramp_rate_limits.get(&principal) {
        Some(info) => {
            if now >= info.window_start + RATE_LIMIT_WINDOW_NS {
                (0, now) // Window expired, would reset
            } else {
                (info.request_count, info.window_start)
            }
        }
        None => (0, now),
    };

    let (offramp_count, offramp_window_start) = match state.offramp_rate_limits.get(&principal) {
        Some(info) => {
            if now >= info.window_start + RATE_LIMIT_WINDOW_NS {
                (0, now) // Window expired, would reset
            } else {
                (info.request_count, info.window_start)
            }
        }
        None => (0, now),
    };

    // Calculate time until earliest window reset
    let onramp_reset = (onramp_window_start + RATE_LIMIT_WINDOW_NS).saturating_sub(now);
    let offramp_reset = (offramp_window_start + RATE_LIMIT_WINDOW_NS).saturating_sub(now);
    let reset_in_secs = std::cmp::max(onramp_reset, offramp_reset) / 1_000_000_000;

    RateLimitStatus {
        onramp_requests: onramp_count,
        offramp_requests: offramp_count,
        max_onramp_per_window: MAX_ONRAMP_REQUESTS_PER_WINDOW,
        max_offramp_per_window: MAX_OFFRAMP_REQUESTS_PER_WINDOW,
        window_resets_in_seconds: reset_in_secs,
    }
}

// =============================================================================
// StableSwap Configuration & Query Endpoints
// =============================================================================

/// Preview a swap output without executing — read-only query.
pub fn get_swap_quote_impl(request: SwapQuoteRequest) -> SwapQuoteResponse {
    let state = STATE.read().unwrap();

    // BTC balance includes channel BTC for StableSwap pricing
    let btc_balance: u64 = state.liq_pool.get_total(&PoolAsset::BTC).0.clone().try_into().unwrap_or(0);
    let btc_balance = btc_balance.saturating_add(state.total_btc_in_channels);
    let ckbtc_balance: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC).0.clone().try_into().unwrap_or(0);

    let effective_fee_bps = crate::stableswap::compute_effective_fee_bps(
        &state.stableswap_config,
        btc_balance as u128,
        ckbtc_balance as u128,
    );

    match crate::stableswap::get_swap_output(
        &state.stableswap_config,
        btc_balance,
        ckbtc_balance,
        request.amount_sats,
        &request.direction,
    ) {
        Ok(result) => SwapQuoteResponse {
            input_amount: request.amount_sats,
            output_amount: result.output_amount,
            total_fee: result.total_fee,
            lp_fee: result.lp_fee,
            protocol_fee: result.protocol_fee,
            price_impact_bps: result.price_impact_bps,
            effective_fee_bps,
            btc_pool_balance: btc_balance,
            ckbtc_pool_balance: ckbtc_balance,
            error: None,
        },
        Err(e) => SwapQuoteResponse {
            input_amount: request.amount_sats,
            output_amount: 0,
            total_fee: 0,
            lp_fee: 0,
            protocol_fee: 0,
            price_impact_bps: 0,
            effective_fee_bps,
            btc_pool_balance: btc_balance,
            ckbtc_pool_balance: ckbtc_balance,
            error: Some(format!("{}", e)),
        },
    }
}

/// Get the current StableSwap configuration.
pub fn get_stableswap_config_impl() -> StableSwapConfig {
    let state = STATE.read().unwrap();
    state.stableswap_config.clone()
}

/// Update the StableSwap configuration (admin-only).
pub fn update_stableswap_config_impl(
    request: UpdateStableSwapConfigRequest,
) -> UpdateStableSwapConfigResponse {
    let caller = msg_caller();
    let mut state = STATE.write().unwrap();

    // Check admin authorization
    match state.admin {
        Some(admin) if admin == caller => {}
        _ => {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("Unauthorized: caller is not admin".to_string()),
            };
        }
    }

    // Validate new values
    if let Some(amp) = request.amplification {
        if amp == 0 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("Amplification must be > 0".to_string()),
            };
        }
        state.stableswap_config.amplification = amp;
    }
    if let Some(fee) = request.fee_bps {
        if fee > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("fee_bps must be <= 10000".to_string()),
            };
        }
        state.stableswap_config.fee_bps = fee;
    }
    if let Some(share) = request.protocol_fee_share_bps {
        if share > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("protocol_fee_share_bps must be <= 10000".to_string()),
            };
        }
        state.stableswap_config.protocol_fee_share_bps = share;
    }
    if let Some(max_slip) = request.max_slippage_bps {
        if max_slip > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("max_slippage_bps must be <= 10000".to_string()),
            };
        }
        state.stableswap_config.max_slippage_bps = max_slip;
    }
    if let Some(imb_fee) = request.imbalance_fee_bps {
        if imb_fee > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("imbalance_fee_bps must be <= 10000".to_string()),
            };
        }
        if imb_fee < state.stableswap_config.fee_bps {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("imbalance_fee_bps must be >= fee_bps".to_string()),
            };
        }
        state.stableswap_config.imbalance_fee_bps = imb_fee;
    }
    if let Some(rebate) = request.rebate_bps {
        if rebate > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("rebate_bps must be <= 10000".to_string()),
            };
        }
        state.stableswap_config.rebate_bps = rebate;
    }
    if let Some(max_pct) = request.max_swap_pct_bps {
        if max_pct > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false,
                config: state.stableswap_config.clone(),
                error: Some("max_swap_pct_bps must be <= 10000".to_string()),
            };
        }
        state.stableswap_config.max_swap_pct_bps = max_pct;
    }

    UpdateStableSwapConfigResponse {
        success: true,
        config: state.stableswap_config.clone(),
        error: None,
    }
}

/// Withdraw accumulated protocol fees (admin-only).
/// Transfers accumulated ckBTC fees to the specified recipient via ICRC-1, then resets counter.
pub async fn withdraw_protocol_fees_impl(recipient: Principal) -> WithdrawProtocolFeesResponse {
    let caller = msg_caller();

    // Zero the counter atomically BEFORE the transfer to prevent double-withdrawal race.
    // Restore on failure.
    let (admin, amount) = {
        let mut state = STATE.write().unwrap();
        let amount = state.protocol_fees_ckbtc;
        state.protocol_fees_ckbtc = 0;
        (state.admin, amount)
    };

    // Check admin authorization
    match admin {
        Some(a) if a == caller => {}
        _ => {
            return WithdrawProtocolFeesResponse {
                success: false,
                btc_amount: 0,
                ckbtc_amount: 0,
                ckbtc_block_index: None,
                error: Some("Unauthorized: caller is not admin".to_string()),
            };
        }
    }

    if amount == 0 {
        return WithdrawProtocolFeesResponse {
            success: true,
            btc_amount: 0,
            ckbtc_amount: 0,
            ckbtc_block_index: None,
            error: None,
        };
    }

    // Transfer accumulated ckBTC fees to recipient
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: recipient,
            subaccount: None,
        },
        amount: Nat(amount.into()),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: None,
        created_at_time: None,
    };

    let ckbtc_ledger = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                // Counter already zeroed before transfer
                WithdrawProtocolFeesResponse {
                    success: true,
                    btc_amount: 0,
                    ckbtc_amount: amount,
                    ckbtc_block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Restore counter on failure
                let mut state = STATE.write().unwrap();
                state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(amount);
                ic_cdk::println!("Protocol fee withdrawal failed: {:?}", e);
                WithdrawProtocolFeesResponse {
                    success: false,
                    btc_amount: 0,
                    ckbtc_amount: amount,
                    ckbtc_block_index: None,
                    error: Some(format!("ckBTC transfer failed: {:?}", e)),
                }
            }
        },
        Err((code, msg)) => {
            // Restore counter on failure
            let mut state = STATE.write().unwrap();
            state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(amount);
            ic_cdk::println!("Protocol fee withdrawal call failed: {:?} - {}", code, msg);
            WithdrawProtocolFeesResponse {
                success: false,
                btc_amount: 0,
                ckbtc_amount: amount,
                ckbtc_block_index: None,
                error: Some(format!("Ledger call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

/// Set the admin principal (callable by canister controller only).
pub fn set_admin_impl(principal: Principal) {
    // ic_cdk::api::is_controller checks if the caller is a canister controller
    if !ic_cdk::api::is_controller(&msg_caller()) {
        ic_cdk::trap("Only canister controllers can set admin");
    }
    let mut state = STATE.write().unwrap();
    state.admin = Some(principal);
    ic_cdk::println!("Admin set to: {}", principal);
}

/// Set the ICP anti-DDoS fee amount (admin-only).
pub fn set_icp_ddos_fee_impl(fee_e8s: u64) -> SetIcpDdosFeeResponse {
    let caller = msg_caller();
    let mut state = STATE.write().unwrap();

    match state.admin {
        Some(admin) if admin == caller => {}
        _ => {
            return SetIcpDdosFeeResponse {
                success: false,
                fee_e8s: state.icp_ddos_fee_e8s,
                error: Some("Unauthorized: caller is not admin".to_string()),
            };
        }
    }

    state.icp_ddos_fee_e8s = fee_e8s;
    ic_cdk::println!("ICP anti-DDoS fee set to: {} e8s", fee_e8s);

    SetIcpDdosFeeResponse {
        success: true,
        fee_e8s,
        error: None,
    }
}

/// Get the current ICP anti-DDoS fee.
pub fn get_icp_ddos_fee_impl() -> u64 {
    let state = STATE.read().unwrap();
    state.icp_ddos_fee_e8s
}

/// Withdraw accumulated ICP fees from the canister (admin-only).
/// Transfers the canister's ICP balance (minus transfer fee) to the specified recipient.
pub async fn withdraw_icp_fees_impl(recipient: Principal) -> WithdrawIcpFeesResponse {
    let caller = msg_caller();

    let admin = {
        let state = STATE.read().unwrap();
        state.admin
    };

    match admin {
        Some(a) if a == caller => {}
        _ => {
            return WithdrawIcpFeesResponse {
                success: false,
                amount_e8s: 0,
                block_index: None,
                error: Some("Unauthorized: caller is not admin".to_string()),
            };
        }
    }

    // Query the canister's ICP balance first
    let icp_ledger = Principal::from_text(DEVNET_ICP_LEDGER).unwrap();
    let canister_principal = ic_cdk::api::canister_self();

    let balance_result: CallResult<(Nat,)> = ic_cdk::call(
        icp_ledger,
        "icrc1_balance_of",
        (Account { owner: canister_principal, subaccount: None },),
    ).await;

    let balance: u64 = match balance_result {
        Ok((bal,)) => bal.0.try_into().unwrap_or(0),
        Err((code, msg)) => {
            return WithdrawIcpFeesResponse {
                success: false,
                amount_e8s: 0,
                block_index: None,
                error: Some(format!("Failed to query ICP balance: {:?} - {}", code, msg)),
            };
        }
    };

    if balance <= ICP_TRANSFER_FEE_E8S {
        return WithdrawIcpFeesResponse {
            success: true,
            amount_e8s: 0,
            block_index: None,
            error: None,
        };
    }

    let withdraw_amount = balance - ICP_TRANSFER_FEE_E8S;

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: recipient,
            subaccount: None,
        },
        amount: Nat(withdraw_amount.into()),
        fee: Some(Nat(ICP_TRANSFER_FEE_E8S.into())),
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(icp_ledger, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => WithdrawIcpFeesResponse {
                success: true,
                amount_e8s: withdraw_amount,
                block_index: Some(block_index),
                error: None,
            },
            Err(e) => {
                ic_cdk::println!("ICP fee withdrawal failed: {:?}", e);
                WithdrawIcpFeesResponse {
                    success: false,
                    amount_e8s: withdraw_amount,
                    block_index: None,
                    error: Some(format!("ICP transfer failed: {:?}", e)),
                }
            }
        },
        Err((code, msg)) => {
            ic_cdk::println!("ICP fee withdrawal call failed: {:?} - {}", code, msg);
            WithdrawIcpFeesResponse {
                success: false,
                amount_e8s: withdraw_amount,
                block_index: None,
                error: Some(format!("Ledger call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

/// Redistribute accumulated ckBTC protocol fees to LPs proportionally (admin-only).
///
/// Takes the accumulated `protocol_fees_ckbtc` and credits each LP's ckBTC balance
/// proportionally based on their share of the ckBTC pool. Resets the counter on success.
pub fn redistribute_fees_impl() -> RedistributeFeesResponse {
    let caller = msg_caller();
    let mut state = STATE.write().unwrap();

    match state.admin {
        Some(admin) if admin == caller => {}
        _ => {
            return RedistributeFeesResponse {
                success: false,
                amount_distributed: 0,
                num_recipients: 0,
                error: Some("Unauthorized: caller is not admin".to_string()),
            };
        }
    }

    let amount = state.protocol_fees_ckbtc;
    if amount == 0 {
        return RedistributeFeesResponse {
            success: true,
            amount_distributed: 0,
            num_recipients: 0,
            error: None,
        };
    }

    let recipients = state.liq_pool.credit_proportional(
        PoolAsset::CkBTC,
        Nat::from(amount),
    );

    if recipients == 0 {
        return RedistributeFeesResponse {
            success: false,
            amount_distributed: 0,
            num_recipients: 0,
            error: Some("No LPs in pool to distribute to".to_string()),
        };
    }

    state.protocol_fees_ckbtc = 0;

    RedistributeFeesResponse {
        success: true,
        amount_distributed: amount,
        num_recipients: recipients as u64,
        error: None,
    }
}
