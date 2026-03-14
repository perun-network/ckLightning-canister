// =============================================================================
// Swap Timeout Handling + Relay Registration + Rate Limiting + StableSwap Admin
// =============================================================================

use super::STATE;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    CKBTC_LEDGER_PRINCIPAL, ICP_LEDGER_PRINCIPAL, ICP_TRANSFER_FEE_E8S,
    ONRAMP_TIMEOUT_NS, OFFRAMP_TIMEOUT_NS, DEFAULT_CKBTC_FEE,
    OnrampRequestState, OfframpRequestState, SwapState,
    RegisterRelayRequest, RegisterRelayResponse, GetRelayInfoResponse,
    RelayRegistration,
    RateLimitInfo, RateLimitStatus,
    RATE_LIMIT_WINDOW_NS, MAX_ONRAMP_REQUESTS_PER_WINDOW, MAX_OFFRAMP_REQUESTS_PER_WINDOW,
    SwapQuoteRequest, SwapQuoteResponse,
    UpdateStableSwapConfigRequest, UpdateStableSwapConfigResponse,
    WithdrawProtocolFeesResponse,
    SetIcpDdosFeeResponse, WithdrawIcpFeesResponse, RedistributeFeesResponse,
    StableSwapConfig,
    PruneResult, StateStats,
};

use candid::{Nat, Principal};
use ic_cdk::call::Call;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use std::str::FromStr;

// =============================================================================
// Swap Timeout Handling
// =============================================================================

/// Expire onramp requests that have timed out.
/// Marks them as Expired and releases reserved ckBTC. ICP fee is NOT refunded.
fn expire_onramp_requests(now: u64, timeout: u64) {
    let expired_ids: Vec<String> = {
        let state = STATE.read().expect("STATE lock: expire_onramp read");
        state.active_onramp_ids.iter()
            .filter(|id| {
                state.onramp_requests.get(*id).is_some_and(|req| {
                    matches!(req.state, OnrampRequestState::Pending | OnrampRequestState::Ready)
                        && now > req.created_at + timeout
                })
            })
            .cloned()
            .collect()
    };

    if expired_ids.is_empty() {
        return;
    }

    let mut state = STATE.write().expect("STATE lock: expire_onramp write");

    // Collect payment hashes and reserved amounts
    let mut swap_hashes: Vec<[u8; 32]> = Vec::new();
    let mut total_reserved: u64 = 0;
    for id in &expired_ids {
        if let Some(req) = state.onramp_requests.get(id) {
            if let Some(ref ph) = req.payment_hash {
                if let Ok(arr) = <[u8; 32]>::try_from(ph.as_slice()) {
                    swap_hashes.push(arr);
                }
            }
            total_reserved += req.amount_sats;
        }
    }

    // Update state
    state.reserved_ckbtc_sats = state.reserved_ckbtc_sats.saturating_sub(total_reserved);
    for id in &expired_ids {
        if let Some(req) = state.onramp_requests.get_mut(id) {
            req.state = OnrampRequestState::Expired;
            ic_cdk::println!("Onramp request {} expired (ICP fee not refunded)", id);
        }
        state.active_onramp_ids.remove(id);
    }
    for hash in swap_hashes {
        if let Some(swap) = state.swaps.get_mut(&hash) {
            if matches!(swap.state, SwapState::Pending) {
                swap.state = SwapState::Expired;
            }
        }
    }
}

/// Expire offramp requests that have timed out and refund ckBTC to users.
/// Only expires Pending requests — NEVER PaymentInProgress (would cause double-spend).
async fn expire_offramp_requests(now: u64, timeout: u64) {
    let expired: Vec<(String, Principal, u64)> = {
        let state = STATE.read().expect("STATE lock: expire_offramp read");
        state.active_offramp_ids.iter()
            .filter_map(|id| {
                state.offramp_requests.get(id).and_then(|req| {
                    if matches!(req.state, OfframpRequestState::Pending)
                        && now > req.created_at + timeout
                    {
                        Some((id.clone(), req.user, req.ckbtc_collected))
                    } else {
                        None
                    }
                })
            })
            .collect()
    };

    for (request_id, user, ckbtc_collected) in expired {
        // Mark as expired first, double-check state
        {
            let mut state = STATE.write().expect("STATE lock: expire_offramp write");
            if let Some(req) = state.offramp_requests.get_mut(&request_id) {
                if !matches!(req.state, OfframpRequestState::Pending) {
                    continue;
                }
                req.state = OfframpRequestState::Expired { refund_block_index: None };
                state.active_offramp_ids.remove(&request_id);
                ic_cdk::println!("Offramp request {} expired, initiating ckBTC refund to user", request_id);
            }
        }

        // Refund ckBTC to user (not to LP!)
        let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
            from_subaccount: None,
            to: icrc_ledger_types::icrc1::account::Account { owner: user, subaccount: None },
            amount: candid::Nat::from(ckbtc_collected),
            fee: None,
            memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:offramp_expire_refund".to_vec())),
            created_at_time: Some(ic_cdk::api::time()),
        };

        match Call::unbounded_wait(*CKBTC_LEDGER_PRINCIPAL, "icrc1_transfer")
            .with_args(&(transfer_args,))
            .await
            .map_err(ic_cdk::call::Error::from)
            .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
        {
            Ok((Ok(block_index),)) => {
                let mut state = STATE.write().expect("STATE lock: expire_offramp refund");
                if let Some(req) = state.offramp_requests.get_mut(&request_id) {
                    req.state = OfframpRequestState::Expired {
                        refund_block_index: Some(block_index.clone()),
                    };
                }
                ic_cdk::println!("Offramp {} ckBTC refunded to user, block_index: {}", request_id, block_index);
            }
            Ok((Err(err),)) => {
                ic_cdk::println!("Failed to refund ckBTC for expired offramp {}: {:?}", request_id, err);
            }
            Err(e) => {
                ic_cdk::println!("ckBTC refund call failed for offramp {}: {}", request_id, e);
            }
        }
    }
}

/// Check for expired swap requests and handle them appropriately.
///
/// - Onramp: Mark as Expired, DO NOT refund ICP fee (anti-DDoS)
/// - Offramp: Mark as Expired, refund ckBTC to user (not LP!)
///
/// This function is called periodically by the heartbeat.
pub async fn check_expired_swaps_impl() {
    let now = blocktime();

    let (onramp_timeout, offramp_timeout) = {
        let state = STATE.read().expect("STATE lock: check_expired_swaps read");
        (
            state.test_onramp_timeout_ns.unwrap_or(ONRAMP_TIMEOUT_NS),
            state.test_offramp_timeout_ns.unwrap_or(OFFRAMP_TIMEOUT_NS),
        )
    };

    expire_onramp_requests(now, onramp_timeout);
    expire_offramp_requests(now, offramp_timeout).await;
}

/// Get count of expired swaps for monitoring
pub fn get_expired_swap_counts() -> (u64, u64) {
    let state = STATE.read().expect("STATE lock: get_expired_swap_counts");

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
    let mut state = STATE.write().expect("STATE lock: set_test_timeouts");

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
    let state = STATE.read().expect("STATE lock: get_timeout_values");
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

    let mut state = STATE.write().expect("STATE lock: register_relay");

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
    let state = STATE.read().expect("STATE lock: get_relay_info");

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
        .map_err(|e| format!("Invalid BOLT11 invoice: {e}"))?;

    // Get the payee public key
    let payee_pubkey = invoice.recover_payee_pub_key();

    // Convert to serialized bytes (33 bytes compressed)
    Ok(payee_pubkey.serialize().to_vec())
}

/// Verify that an invoice was created by the registered relay node.
///
/// This is called during submit_invoice to prevent invoice substitution attacks.
pub(super) fn verify_invoice_node_pubkey(invoice_str: &str) -> Result<(), String> {
    let state = STATE.read().expect("STATE lock: extract_node_pubkey_from_invoice read");

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

/// Generic rate limit check: looks up `caller` in `limits`, enforces `max_requests`
/// per window, and returns Ok(()) or an error message.
fn check_rate_limit(
    limits: &mut std::collections::HashMap<Principal, RateLimitInfo>,
    caller: Principal,
    max_requests: u32,
    label: &str,
) -> Result<(), String> {
    let now = blocktime();

    if let Some(info) = limits.get_mut(&caller) {
        if now >= info.window_start + RATE_LIMIT_WINDOW_NS {
            info.window_start = now;
            info.request_count = 1;
            Ok(())
        } else if info.request_count >= max_requests {
            let reset_in_secs = (info.window_start + RATE_LIMIT_WINDOW_NS).saturating_sub(now) / 1_000_000_000;
            Err(format!(
                "Rate limited: {max_requests} {label} requests per hour exceeded. Try again in {reset_in_secs} seconds."
            ))
        } else {
            info.request_count += 1;
            Ok(())
        }
    } else {
        limits.insert(caller, RateLimitInfo::new(now));
        Ok(())
    }
}

/// Check if a principal is rate limited for onramp requests.
pub(super) fn check_onramp_rate_limit(caller: Principal) -> Result<(), String> {
    let mut state = STATE.write().expect("STATE lock: check_onramp_rate_limit");
    check_rate_limit(&mut state.onramp_rate_limits, caller, MAX_ONRAMP_REQUESTS_PER_WINDOW, "onramp")
}

/// Check if a principal is rate limited for offramp requests.
pub(super) fn check_offramp_rate_limit(caller: Principal) -> Result<(), String> {
    let mut state = STATE.write().expect("STATE lock: check_offramp_rate_limit");
    check_rate_limit(&mut state.offramp_rate_limits, caller, MAX_OFFRAMP_REQUESTS_PER_WINDOW, "offramp")
}

/// Get rate limit status for a principal.
pub fn get_rate_limit_status_impl(principal: Principal) -> RateLimitStatus {
    let now = blocktime();
    let state = STATE.read().expect("STATE lock: get_rate_limit_status");

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
    let state = STATE.read().expect("STATE lock: get_swap_quote");

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
            error: Some(format!("{e}")),
        },
    }
}

/// Get the current StableSwap configuration.
pub fn get_stableswap_config_impl() -> StableSwapConfig {
    let state = STATE.read().expect("STATE lock: get_stableswap_config");
    state.stableswap_config.clone()
}

/// Update the StableSwap configuration (admin-only).
pub fn update_stableswap_config_impl(
    request: UpdateStableSwapConfigRequest,
) -> UpdateStableSwapConfigResponse {
    let caller = msg_caller();
    let mut state = STATE.write().expect("STATE lock: update_stableswap_config");

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

    // Macro: validate an optional bps field (must be <= 10_000) and assign.
    macro_rules! set_bps {
        ($req_field:expr, $cfg_field:expr, $name:expr) => {
            if let Some(v) = $req_field {
                if v > 10_000 {
                    return UpdateStableSwapConfigResponse {
                        success: false,
                        config: state.stableswap_config.clone(),
                        error: Some(format!("{} must be <= 10000", $name)),
                    };
                }
                $cfg_field = v;
            }
        };
    }

    // Validate amplification separately (> 0, not bps)
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

    set_bps!(request.fee_bps, state.stableswap_config.fee_bps, "fee_bps");
    set_bps!(request.protocol_fee_share_bps, state.stableswap_config.protocol_fee_share_bps, "protocol_fee_share_bps");
    set_bps!(request.max_slippage_bps, state.stableswap_config.max_slippage_bps, "max_slippage_bps");
    set_bps!(request.rebate_bps, state.stableswap_config.rebate_bps, "rebate_bps");
    set_bps!(request.max_swap_pct_bps, state.stableswap_config.max_swap_pct_bps, "max_swap_pct_bps");

    // imbalance_fee_bps has an additional constraint: must be >= fee_bps
    if let Some(imb_fee) = request.imbalance_fee_bps {
        if imb_fee > 10_000 {
            return UpdateStableSwapConfigResponse {
                success: false, config: state.stableswap_config.clone(),
                error: Some("imbalance_fee_bps must be <= 10000".to_string()),
            };
        }
        if imb_fee < state.stableswap_config.fee_bps {
            return UpdateStableSwapConfigResponse {
                success: false, config: state.stableswap_config.clone(),
                error: Some("imbalance_fee_bps must be >= fee_bps".to_string()),
            };
        }
        state.stableswap_config.imbalance_fee_bps = imb_fee;
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
        let mut state = STATE.write().expect("STATE lock: withdraw_protocol_fees write");
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
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:protocol_fee".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    let ckbtc_ledger = *CKBTC_LEDGER_PRINCIPAL;

    match Call::unbounded_wait(ckbtc_ledger, "icrc1_transfer")
        .with_args(&(transfer_arg,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
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
                let mut state = STATE.write().expect("STATE lock: withdraw_protocol_fees write 2");
                state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(amount);
                ic_cdk::println!("Protocol fee withdrawal failed: {:?}", e);
                WithdrawProtocolFeesResponse {
                    success: false,
                    btc_amount: 0,
                    ckbtc_amount: amount,
                    ckbtc_block_index: None,
                    error: Some(format!("ckBTC transfer failed: {e:?}")),
                }
            }
        },
        Err(e) => {
            // Restore counter on failure
            let mut state = STATE.write().expect("STATE lock: withdraw_protocol_fees write 3");
            state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(amount);
            ic_cdk::println!("Protocol fee withdrawal call failed: {}", e);
            WithdrawProtocolFeesResponse {
                success: false,
                btc_amount: 0,
                ckbtc_amount: amount,
                ckbtc_block_index: None,
                error: Some(format!("Ledger call failed: {e}")),
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
    let mut state = STATE.write().expect("STATE lock: set_admin");
    state.admin = Some(principal);
    ic_cdk::println!("Admin set to: {}", principal);
}

/// Set the ICP anti-DDoS fee amount (admin-only).
pub fn set_icp_ddos_fee_impl(fee_e8s: u64) -> SetIcpDdosFeeResponse {
    let caller = msg_caller();
    let mut state = STATE.write().expect("STATE lock: set_icp_ddos_fee");

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
    let state = STATE.read().expect("STATE lock: get_icp_ddos_fee");
    state.icp_ddos_fee_e8s
}

/// Withdraw accumulated ICP fees from the canister (admin-only).
/// Transfers the canister's ICP balance (minus transfer fee) to the specified recipient.
pub async fn withdraw_icp_fees_impl(recipient: Principal) -> WithdrawIcpFeesResponse {
    let caller = msg_caller();

    let admin = {
        let state = STATE.read().expect("STATE lock: withdraw_icp_fees read");
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
    let icp_ledger = *ICP_LEDGER_PRINCIPAL;
    let canister_principal = ic_cdk::api::canister_self();

    let balance: u64 = match Call::unbounded_wait(icp_ledger, "icrc1_balance_of")
        .with_args(&(Account { owner: canister_principal, subaccount: None },))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Nat,)>().map_err(Into::into))
    {
        Ok((bal,)) => bal.0.try_into().unwrap_or(0),
        Err(e) => {
            return WithdrawIcpFeesResponse {
                success: false,
                amount_e8s: 0,
                block_index: None,
                error: Some(format!("Failed to query ICP balance: {e}")),
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
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:icp_fee_withdraw".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(icp_ledger, "icrc1_transfer")
        .with_args(&(transfer_arg,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
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
                    error: Some(format!("ICP transfer failed: {e:?}")),
                }
            }
        },
        Err(e) => {
            ic_cdk::println!("ICP fee withdrawal call failed: {}", e);
            WithdrawIcpFeesResponse {
                success: false,
                amount_e8s: withdraw_amount,
                block_index: None,
                error: Some(format!("Ledger call failed: {e}")),
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
    let mut state = STATE.write().expect("STATE lock: redistribute_fees");

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

// =============================================================================
// State Pruning & Monitoring
// =============================================================================

/// Prune terminal-state entries older than `older_than_ns` (nanoseconds).
///
/// Removes Completed/Expired/Failed/Refunded entries from swaps, onramp_requests,
/// offramp_requests, and stale rate limit entries. This prevents unbounded state
/// growth that could brick pre_upgrade serialization.
pub fn prune_state_impl(older_than_ns: u64) -> PruneResult {
    let caller = msg_caller();
    let mut state = STATE.write().expect("STATE lock: prune_state");

    // Admin-only
    match state.admin {
        Some(admin) if admin == caller => {}
        _ => {
            return PruneResult {
                swaps_pruned: 0,
                onramp_requests_pruned: 0,
                offramp_requests_pruned: 0,
                rate_limits_pruned: 0,
            };
        }
    }

    let cutoff = older_than_ns;

    // Prune swaps
    let swaps_before = state.swaps.len();
    state.swaps.retain(|_, swap| {
        let is_terminal = matches!(swap.state, SwapState::Completed { .. } | SwapState::Expired | SwapState::Failed { .. });
        !(is_terminal && swap.created_at < cutoff)
    });
    let swaps_pruned = (swaps_before - state.swaps.len()) as u64;

    // Prune onramp requests
    let onramp_before = state.onramp_requests.len();
    state.onramp_requests.retain(|_, req| {
        let is_terminal = matches!(req.state,
            OnrampRequestState::Completed { .. } | OnrampRequestState::Expired | OnrampRequestState::Failed { .. }
        );
        !(is_terminal && req.created_at < cutoff)
    });
    let onramp_pruned = (onramp_before - state.onramp_requests.len()) as u64;

    // Prune offramp requests
    let offramp_before = state.offramp_requests.len();
    state.offramp_requests.retain(|_, req| {
        let is_terminal = matches!(req.state,
            OfframpRequestState::Completed { .. } | OfframpRequestState::Failed { .. }
            | OfframpRequestState::Refunded { .. } | OfframpRequestState::Expired { .. }
        );
        !(is_terminal && req.created_at < cutoff)
    });
    let offramp_pruned = (offramp_before - state.offramp_requests.len()) as u64;

    // Prune stale rate limit entries (older than the rate limit window)
    let now = blocktime();
    let onramp_rl_before = state.onramp_rate_limits.len();
    state.onramp_rate_limits.retain(|_, rl| {
        now.saturating_sub(rl.window_start) < RATE_LIMIT_WINDOW_NS
    });
    let offramp_rl_before = state.offramp_rate_limits.len();
    state.offramp_rate_limits.retain(|_, rl| {
        now.saturating_sub(rl.window_start) < RATE_LIMIT_WINDOW_NS
    });
    let rate_limits_pruned = (onramp_rl_before - state.onramp_rate_limits.len()
        + offramp_rl_before - state.offramp_rate_limits.len()) as u64;

    PruneResult {
        swaps_pruned,
        onramp_requests_pruned: onramp_pruned,
        offramp_requests_pruned: offramp_pruned,
        rate_limits_pruned,
    }
}

/// Get statistics about canister state collection sizes.
pub fn get_state_stats_impl() -> StateStats {
    let state = STATE.read().expect("STATE lock: get_state_stats");
    StateStats {
        swaps_count: state.swaps.len() as u64,
        onramp_requests_count: state.onramp_requests.len() as u64,
        offramp_requests_count: state.offramp_requests.len() as u64,
        processed_utxos_count: state.processed_utxos.len() as u64,
        funded_channels_count: state.funded_channels.len() as u64,
        onramp_rate_limits_count: state.onramp_rate_limits.len() as u64,
        offramp_rate_limits_count: state.offramp_rate_limits.len() as u64,
        channel_secrets_count: state.channel_secrets.len() as u64,
        htlc_tx_details_count: state.htlc_tx_details.len() as u64,
    }
}

/// Set withdrawal / swap amount caps (admin only).
/// Pass 0 to disable a cap.
pub fn set_swap_caps_impl(max_single_swap_sats: u64, max_hourly_swap_sats: u64) -> Result<(), String> {
    let caller = msg_caller();
    let mut state = STATE.write().expect("STATE lock: set_swap_caps");

    match state.admin {
        Some(admin) if admin == caller => {}
        _ => return Err("Unauthorized: caller is not admin".to_string()),
    }

    state.max_single_swap_sats = max_single_swap_sats;
    state.max_hourly_swap_sats = max_hourly_swap_sats;

    ic_cdk::println!(
        "Swap caps updated: max_single={} sats, max_hourly={} sats (0=disabled)",
        max_single_swap_sats, max_hourly_swap_sats
    );

    Ok(())
}
