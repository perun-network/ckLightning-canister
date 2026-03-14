// =============================================================================
// Lightning → ckBTC Swap Implementation
// =============================================================================

use super::STATE;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    CKBTC_LEDGER_PRINCIPAL, CompleteSwapRequest, CompleteSwapResponse, ICP_LEDGER_PRINCIPAL,
    ICP_TRANSFER_FEE_E8S,
    RegisterSwapRequest, RegisterSwapResponse,
    SwapInfo, SwapState, OnrampRequestState,
};
use crate::ic_types::DEFAULT_CKBTC_FEE;

use bitcoin::hashes::{Hash, sha256};
use candid::{Nat, Principal};
use ic_cdk::call::Call;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

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
        let state = STATE.read().expect("STATE lock: register_swap read");
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
        let mut state = STATE.write().expect("STATE lock: register_swap write");
        state.swaps.insert(payment_hash_arr, swap_info);
    }

    RegisterSwapResponse {
        success: true,
        error: None,
    }
}

/// Validate payment_hash and preimage, returning the fixed-size hash array.
fn validate_swap_request(request: &CompleteSwapRequest) -> Result<[u8; 32], CompleteSwapResponse> {
    if request.payment_hash.len() != 32 {
        return Err(CompleteSwapResponse {
            success: false, block_index: None,
            error: Some("Invalid payment_hash length".to_string()),
        });
    }
    if request.preimage.len() != 32 {
        return Err(CompleteSwapResponse {
            success: false, block_index: None,
            error: Some("Invalid preimage length".to_string()),
        });
    }
    let computed_hash = sha256::Hash::hash(&request.preimage);
    if computed_hash.as_byte_array() != request.payment_hash.as_slice() {
        return Err(CompleteSwapResponse {
            success: false, block_index: None,
            error: Some("Preimage does not match payment_hash".to_string()),
        });
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&request.payment_hash);
    Ok(arr)
}

/// Restore LP ckBTC after a failed transfer and mark the swap as failed.
fn restore_lp_and_fail_swap(payment_hash: &[u8; 32], ckbtc_out: u64, reason: String) {
    let mut state = STATE.write().expect("STATE lock: complete_swap restore");
    state.liq_pool.credit_proportional(PoolAsset::CkBTC, Nat::from(ckbtc_out));
    if let Some(swap) = state.swaps.get_mut(payment_hash) {
        swap.state = SwapState::Failed { reason };
    }
}

/// After successful ckBTC transfer: mark completed, update onramp request, handle ICP refund.
async fn finalize_swap_completion(payment_hash: [u8; 32], block_index: Nat, ckbtc_out: u64) {
    let icp_fee_payer = {
        let mut state = STATE.write().expect("STATE lock: complete_swap finalize");
        if let Some(swap) = state.swaps.get_mut(&payment_hash) {
            swap.state = SwapState::Completed { block_index: block_index.clone() };
        }
        super::record_swap_volume(&mut state, ckbtc_out);

        let found = state.onramp_requests.values()
            .find(|req| req.payment_hash.as_deref() == Some(payment_hash.as_slice()))
            .map(|req| (req.request_id.clone(), req.amount_sats, req.icp_fee_payer));

        if let Some((request_id, amount_sats, icp_fee_payer)) = found {
            if let Some(request) = state.onramp_requests.get_mut(&request_id) {
                request.state = OnrampRequestState::Completed { block_index: block_index.clone() };
            }
            state.active_onramp_ids.remove(&request_id);
            state.reserved_ckbtc_sats = state.reserved_ckbtc_sats.saturating_sub(amount_sats);
            icp_fee_payer
        } else {
            None
        }
    };

    if let Some(fee_payer) = icp_fee_payer {
        try_refund_icp_fee(fee_payer, &payment_hash).await;
    }
}

/// Attempt ICP fee refund with optimistic flag + rollback on failure.
async fn try_refund_icp_fee(fee_payer: Principal, payment_hash: &[u8; 32]) {
    // Mark as refunded BEFORE the call to prevent double-refund race
    {
        let mut state = STATE.write().expect("STATE lock: icp_refund_flag");
        set_icp_refund_flag(&mut state, payment_hash, true);
    }
    if let Err(e) = refund_icp_fee(fee_payer).await {
        ic_cdk::println!("Warning: Failed to refund ICP fee: {}", e);
        let mut state = STATE.write().expect("STATE lock: icp_refund_rollback");
        set_icp_refund_flag(&mut state, payment_hash, false);
    }
}

/// Set the `icp_fee_refunded` flag for the onramp request matching a payment hash.
fn set_icp_refund_flag<Q: crate::receiver::TXQuerier>(
    state: &mut super::CanisterState<Q>,
    payment_hash: &[u8; 32],
    value: bool,
) {
    for request in state.onramp_requests.values_mut() {
        if let Some(ref ph) = request.payment_hash {
            if ph.as_slice() == payment_hash.as_slice() {
                request.icp_fee_refunded = value;
                break;
            }
        }
    }
}

/// Complete a Lightning → ckBTC swap
///
/// Called by the relay node when a Lightning payment is received.
/// Verifies the preimage, then transfers ckBTC to the recipient.
pub async fn complete_swap_impl(request: CompleteSwapRequest) -> CompleteSwapResponse {
    let payment_hash_arr = match validate_swap_request(&request) {
        Ok(h) => h,
        Err(resp) => return resp,
    };

    // Atomically: verify state, set InFlight, compute swap, deduct LP — all in ONE write lock.
    // This prevents TOCTOU double-spend: a concurrent call will see InFlight and bail out.
    let (swap_info, ckbtc_out) = {
        let mut state = STATE.write().expect("STATE lock: complete_swap write");

        let swap = match state.swaps.get(&payment_hash_arr) {
            Some(info) => info.clone(),
            None => {
                return CompleteSwapResponse {
                    success: false, block_index: None,
                    error: Some("Swap not found for this payment_hash".to_string()),
                };
            }
        };

        // Check swap state — reject anything that isn't Pending
        if let Err(msg) = check_swap_state_pending(&swap.state) {
            return CompleteSwapResponse { success: false, block_index: None, error: Some(msg) };
        }

        // Convert amount from millisatoshis to satoshis
        let input_sat = swap.amount_msat / 1000;
        if input_sat == 0 {
            if let Some(s) = state.swaps.get_mut(&payment_hash_arr) {
                s.state = SwapState::Failed { reason: "Amount too small".to_string() };
            }
            return CompleteSwapResponse {
                success: false, block_index: None,
                error: Some("Amount too small (< 1000 msat)".to_string()),
            };
        }

        // Compute StableSwap output
        let btc_balance: u64 = state.liq_pool.get_total(&PoolAsset::BTC).0.clone().try_into().unwrap_or(0);
        let btc_balance = btc_balance.saturating_add(state.total_btc_in_channels);
        let ckbtc_balance: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC).0.clone().try_into().unwrap_or(0);

        let swap_result = match crate::stableswap::get_swap_output(
            &state.stableswap_config, btc_balance, ckbtc_balance,
            input_sat as u64, &crate::stableswap::SwapDirection::BtcToCkbtc,
        ) {
            Ok(r) => r,
            Err(e) => {
                if let Some(s) = state.swaps.get_mut(&payment_hash_arr) {
                    s.state = SwapState::Failed { reason: format!("StableSwap error: {e}") };
                }
                return CompleteSwapResponse {
                    success: false, block_index: None,
                    error: Some(format!("StableSwap pricing error: {e}")),
                };
            }
        };

        let ckbtc_out = swap_result.output_amount;

        if let Err(cap_err) = super::check_swap_caps(&mut state, ckbtc_out) {
            if let Some(s) = state.swaps.get_mut(&payment_hash_arr) {
                s.state = SwapState::Failed { reason: cap_err.clone() };
            }
            return CompleteSwapResponse { success: false, block_index: None, error: Some(cap_err) };
        }

        state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(swap_result.protocol_fee);
        state.total_btc_in_channels = state.total_btc_in_channels.saturating_add(input_sat as u64);

        if state.liq_pool.deduct_proportional(PoolAsset::CkBTC, Nat::from(ckbtc_out)).is_err() {
            if let Some(s) = state.swaps.get_mut(&payment_hash_arr) {
                s.state = SwapState::Failed { reason: "Insufficient LP liquidity".to_string() };
            }
            return CompleteSwapResponse {
                success: false, block_index: None,
                error: Some("Insufficient LP liquidity for swap".to_string()),
            };
        }

        // Mark as InFlight BEFORE releasing the lock — prevents concurrent double-spend
        if let Some(s) = state.swaps.get_mut(&payment_hash_arr) {
            s.state = SwapState::InFlight;
        }

        (swap, ckbtc_out)
    };

    // Execute ckBTC transfer
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account { owner: swap_info.recipient, subaccount: None },
        amount: Nat(ckbtc_out.into()),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(request.payment_hash.clone())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(*CKBTC_LEDGER_PRINCIPAL, "icrc1_transfer")
        .with_args(&(transfer_arg,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
        Ok((Ok(block_index),)) => {
            finalize_swap_completion(payment_hash_arr, block_index.clone(), ckbtc_out).await;
            CompleteSwapResponse { success: true, block_index: Some(block_index), error: None }
        }
        Ok((Err(e),)) => {
            let reason = format!("Transfer error: {e:?}");
            restore_lp_and_fail_swap(&payment_hash_arr, ckbtc_out, reason.clone());
            CompleteSwapResponse { success: false, block_index: None, error: Some(format!("ckBTC transfer failed: {e:?}")) }
        }
        Err(e) => {
            let reason = format!("Call error: {e}");
            restore_lp_and_fail_swap(&payment_hash_arr, ckbtc_out, reason);
            CompleteSwapResponse {
                success: false, block_index: None,
                error: Some(format!("Canister call failed: {e}")),
            }
        }
    }
}

/// Check that a swap is in Pending state, returning an error message if not.
fn check_swap_state_pending(state: &SwapState) -> Result<(), String> {
    match state {
        SwapState::Pending => Ok(()),
        SwapState::InFlight => Err("Swap already in progress".to_string()),
        SwapState::Completed { .. } => Err("Swap already completed".to_string()),
        SwapState::Expired => Err("Swap has expired".to_string()),
        SwapState::Failed { reason } => Err(format!("Swap failed: {reason}")),
    }
}

/// Collect ICP anti-DDoS fee from a caller via ICRC-2 transfer_from.
pub(super) async fn collect_icp_fee(caller: Principal, memo: &[u8]) -> Result<Nat, String> {
    let icp_ddos_fee = {
        let state = STATE.read().expect("STATE lock: collect_icp_fee");
        state.icp_ddos_fee_e8s
    };

    let transfer_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: icrc_ledger_types::icrc1::account::Account { owner: caller, subaccount: None },
        to: icrc_ledger_types::icrc1::account::Account { owner: ic_cdk::api::canister_self(), subaccount: None },
        amount: candid::Nat::from(icp_ddos_fee),
        fee: None,
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(memo.to_vec())),
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
            Err(format!("Failed to collect ICP anti-DDoS fee: {err:?}. Did you approve {fee_icp} ICP?"))
        }
        Err(e) => Err(format!("ICP ledger call failed: {e}")),
    }
}

/// Helper function to refund ICP anti-DDoS fee to a recipient
pub(super) async fn refund_icp_fee(recipient: Principal) -> Result<Nat, String> {
    let icp_ledger = *ICP_LEDGER_PRINCIPAL;

    // Read configured fee from state and refund minus the transfer fee
    let icp_ddos_fee = {
        let state = STATE.read().expect("STATE lock: complete_swap read");
        state.icp_ddos_fee_e8s
    };
    let refund_amount = icp_ddos_fee.saturating_sub(ICP_TRANSFER_FEE_E8S);

    let transfer_args = icrc_ledger_types::icrc1::transfer::TransferArg {
        from_subaccount: None,
        to: icrc_ledger_types::icrc1::account::Account {
            owner: recipient,
            subaccount: None,
        },
        amount: candid::Nat::from(refund_amount),
        fee: Some(candid::Nat::from(ICP_TRANSFER_FEE_E8S)),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:icp_fee_refund".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(icp_ledger, "icrc1_transfer")
        .with_args(&(transfer_args,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => Ok(block_index),
            Err(e) => Err(format!("ICP transfer failed: {e:?}")),
        },
        Err(e) => Err(format!("ICP ledger call failed: {e}")),
    }
}
