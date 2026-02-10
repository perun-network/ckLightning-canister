// =============================================================================
// Lightning → ckBTC Swap Implementation
// =============================================================================

use super::STATE;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    CompleteSwapRequest, CompleteSwapResponse, DEVNET_CKBTC_LEDGER, DEVNET_ICP_LEDGER,
    ICP_TRANSFER_FEE_E8S,
    RegisterSwapRequest, RegisterSwapResponse,
    SwapInfo, SwapState, OnrampRequestState,
};
use crate::ic_types::DEFAULT_CKBTC_FEE;

use bitcoin::hashes::{Hash, sha256};
use candid::{Nat, Principal};
use ic_cdk::api::call::CallResult;
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
    let input_sat = swap_info.amount_msat / 1000;
    if input_sat == 0 {
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

    // Use StableSwap AMM to compute ckBTC output for BTC input
    let ckbtc_out = {
        let mut state = STATE.write().unwrap();

        // Get pool balances for StableSwap pricing
        // BTC balance includes channel BTC (it's still system BTC, just in channels not on-chain)
        let btc_balance: u64 = state.liq_pool.get_total(&PoolAsset::BTC).0.clone().try_into().unwrap_or(0);
        let btc_balance = btc_balance + state.total_btc_in_channels;
        let ckbtc_balance: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC).0.clone().try_into().unwrap_or(0);

        let swap_result = match crate::stableswap::get_swap_output(
            &state.stableswap_config,
            btc_balance,
            ckbtc_balance,
            input_sat as u64,
            &crate::stableswap::SwapDirection::BtcToCkbtc,
        ) {
            Ok(r) => r,
            Err(e) => {
                if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                    swap.state = SwapState::Failed {
                        reason: format!("StableSwap error: {}", e),
                    };
                }
                return CompleteSwapResponse {
                    success: false,
                    block_index: None,
                    error: Some(format!("StableSwap pricing error: {}", e)),
                };
            }
        };

        // Track protocol fees
        state.protocol_fees_ckbtc = state.protocol_fees_ckbtc.saturating_add(swap_result.protocol_fee);

        let ckbtc_out = swap_result.output_amount;

        // Deduct ckBTC from LP proportionally (only the output amount — LP fee stays in pool)
        let amount_nat = Nat::from(ckbtc_out);
        if let Err(_) = state.liq_pool.deduct_proportional(PoolAsset::CkBTC, amount_nat) {
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

        ckbtc_out
    };

    // Execute ckBTC transfer
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: swap_info.recipient,
            subaccount: None,
        },
        amount: Nat(ckbtc_out.into()),
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
                // Mark swap as completed and get ICP fee payer
                let icp_fee_payer = {
                    let mut state = STATE.write().unwrap();
                    if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                        swap.state = SwapState::Completed {
                            block_index: block_index.clone(),
                        };
                    }
                    // Find the onramp request by payment_hash and get ICP fee payer
                    let mut fee_payer = None;
                    for request in state.onramp_requests.values_mut() {
                        if let Some(ref ph) = request.payment_hash {
                            if ph.as_slice() == payment_hash_arr.as_slice() {
                                request.state = OnrampRequestState::Completed { block_index: block_index.clone() };
                                fee_payer = request.icp_fee_payer;
                                break;
                            }
                        }
                    }
                    fee_payer
                };

                // Refund ICP fee to the fee payer (if there was one)
                if let Some(fee_payer) = icp_fee_payer {
                    let refund_result = refund_icp_fee(fee_payer).await;
                    if let Err(e) = refund_result {
                        ic_cdk::println!("Warning: Failed to refund ICP fee: {}", e);
                        // Don't fail the swap - ckBTC was already transferred successfully
                    } else {
                        // Mark ICP fee as refunded
                        let mut state = STATE.write().unwrap();
                        for request in state.onramp_requests.values_mut() {
                            if let Some(ref ph) = request.payment_hash {
                                if ph.as_slice() == payment_hash_arr.as_slice() {
                                    request.icp_fee_refunded = true;
                                    break;
                                }
                            }
                        }
                    }
                }

                CompleteSwapResponse {
                    success: true,
                    block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Restore LP balances proportionally and mark as failed
                {
                    let mut state = STATE.write().unwrap();
                    let restore_nat = Nat::from(ckbtc_out);
                    state.liq_pool.credit_proportional(PoolAsset::CkBTC, restore_nat);
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
            // Restore LP balances proportionally and mark as failed
            {
                let mut state = STATE.write().unwrap();
                let restore_nat = Nat::from(ckbtc_out);
                state.liq_pool.credit_proportional(PoolAsset::CkBTC, restore_nat);
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

/// Helper function to refund ICP anti-DDoS fee to a recipient
pub(super) async fn refund_icp_fee(recipient: Principal) -> Result<Nat, String> {
    let icp_ledger = Principal::from_text(DEVNET_ICP_LEDGER).unwrap();

    // Read configured fee from state and refund minus the transfer fee
    let icp_ddos_fee = {
        let state = STATE.read().unwrap();
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
        memo: None,
        created_at_time: None,
    };

    let call_result: CallResult<(
        Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(icp_ledger, "icrc1_transfer", (transfer_args,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => Ok(block_index),
            Err(e) => Err(format!("ICP transfer failed: {:?}", e)),
        },
        Err((code, msg)) => Err(format!("ICP ledger call failed: {:?} - {}", code, msg)),
    }
}
