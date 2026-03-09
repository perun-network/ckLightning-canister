// =============================================================================
// BTC Liquidity Pool Implementation (Shared LP Address - Option C)
// + User BTC Operations (from depositor address)
// + Channel Funding from LP BTC
// =============================================================================

use super::STATE;
use crate::BtcPurpose;
use crate::btc::address::get_segwit_address;
use crate::btc::common::get_fee_per_byte;
use crate::btc::ecdsa::{get_ecdsa_public_key, sign_with_ecdsa};
use crate::btc::p2wpkh;
use crate::error::BtcError;
use crate::helpers::send_btc_from_lp_address;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    LpBtcAddressResponse, LpBtcDepositRequest, LpBtcDepositResponse,
    LpBtcWithdrawRequest, LpBtcWithdrawResponse,
    SendFromDepositorRequest, SendFromDepositorResponse, DepositorBtcBalanceResponse,
    FundChannelRequest, FundChannelResponse,
};

use bitcoin::{Address, CompressedPublicKey, PublicKey, consensus::serialize};
use candid::Nat;
use ic_cdk::api::msg_caller;
use ic_cdk::bitcoin_canister::{
    GetBalanceRequest, GetUtxosRequest, SendTransactionRequest,
    bitcoin_get_balance, bitcoin_get_utxos, bitcoin_send_transaction,
};
use std::str::FromStr;

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
    // Use a single write lock for the check-and-insert to prevent TOCTOU double-credit
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

        // If a specific txid was provided, only process matching UTXOs
        if let Some(ref expected_txid) = request.txid {
            if utxo.outpoint.txid.as_slice() != expected_txid.as_slice() {
                continue;
            }
        }

        // Atomically check+insert processed_utxos and credit in one write lock
        let utxo_key = (utxo.outpoint.txid.clone(), utxo.outpoint.vout);
        let amount = utxo.value;
        {
            let mut state = STATE.write().unwrap();
            if state.processed_utxos.contains_key(&utxo_key) {
                continue;
            }
            state.processed_utxos.insert(utxo_key, caller);
            state.liq_pool.deposit(caller, PoolAsset::BTC, Nat::from(amount));
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

/// Get the caller's per-user LP BTC deposit address
///
/// Each LP depositor gets a unique address derived from their principal.
/// This prevents the first-claimer-wins issue of the shared address.
pub async fn get_lp_btc_user_address_impl() -> Result<LpBtcAddressResponse, BtcError> {
    let caller = msg_caller();

    // Check cache first
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_liquidity_addresses.get(&caller) {
            return Ok(LpBtcAddressResponse {
                address: addr.clone(),
            });
        }
    }

    // Derive per-user LP BTC address
    let purpose = BtcPurpose::LiquidityDepositor(caller);
    let address = get_segwit_address(purpose).await?;

    // Cache it
    {
        let mut state = STATE.write().unwrap();
        state.btc_liquidity_addresses.insert(caller, address.clone());
    }

    Ok(LpBtcAddressResponse { address })
}

/// Deposit BTC to the liquidity pool using the caller's per-user address
///
/// Scans the caller's own LP deposit address for new UTXOs with 6+ confirmations.
/// Only the address owner can claim their UTXOs (no first-claimer-wins).
pub async fn deposit_btc_user_impl(request: LpBtcDepositRequest) -> LpBtcDepositResponse {
    let caller = msg_caller();

    // Get the caller's per-user LP BTC address
    let user_address = match get_lp_btc_user_address_impl().await {
        Ok(resp) => resp.address,
        Err(e) => {
            return LpBtcDepositResponse {
                success: false,
                credited_amount: Nat::from(0u64),
                new_btc_balance: Nat::from(0u64),
                error: Some(format!("Failed to get user LP address: {:?}", e)),
            };
        }
    };

    // Get Bitcoin context and query UTXOs on the per-user address
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    let utxos_result = bitcoin_get_utxos(&GetUtxosRequest {
        address: user_address.clone(),
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

    // Process each UTXO — same TOCTOU-safe pattern as deposit_btc_impl
    for utxo in &utxos_response.utxos {
        let confirmations = if utxo.height > 0 {
            tip_height.saturating_sub(utxo.height) + 1
        } else {
            0
        };

        if confirmations < REQUIRED_BTC_CONFIRMATIONS as u32 {
            continue;
        }

        if let Some(ref expected_txid) = request.txid {
            if utxo.outpoint.txid.as_slice() != expected_txid.as_slice() {
                continue;
            }
        }

        // Atomically check+insert processed_utxos and credit
        let utxo_key = (utxo.outpoint.txid.clone(), utxo.outpoint.vout);
        let amount = utxo.value;
        {
            let mut state = STATE.write().unwrap();
            if state.processed_utxos.contains_key(&utxo_key) {
                continue;
            }
            state.processed_utxos.insert(utxo_key, caller);
            state.liq_pool.deposit(caller, PoolAsset::BTC, Nat::from(amount));
        }

        total_credited += amount;
    }

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
                REQUIRED_BTC_CONFIRMATIONS, user_address
            )),
        }
    }
}

/// Withdraw BTC from the liquidity pool
///
/// Sends BTC from the shared LP address to the user's destination address.
/// The caller's LP BTC balance must be sufficient for the withdrawal.
/// Additionally, the requested amount must not exceed available on-chain BTC
/// (total LP BTC minus BTC locked in Lightning channels).
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

    // Deduct from LP balance
    // LP balances already reflect channel deductions (deduct_proportional on fund),
    // so we just check the individual LP balance via liq_pool.withdraw().
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

    // Idempotency guard: reject duplicate fund_channel for the same address
    {
        let state = STATE.read().unwrap();
        if state.funded_channels.contains(&request.funding_address) {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel already funded for this address".to_string()),
            };
        }
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
    if total_available < request.amount_sat.saturating_add(fee_margin) {
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

    // Track the funding in canister state (atomically with idempotency guard)
    // Two-phase model: create reservation only. LP deduction happens in channel_funded.
    {
        let mut state = STATE.write().unwrap();
        if !state.funded_channels.insert(request.funding_address.clone()) {
            // Race: another call funded this address between our read check and here
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel already funded for this address".to_string()),
            };
        }
        // Reserve the amount — LP balances and total_btc_in_channels are NOT modified yet.
        // They will be updated when channel_funded is called after TX confirmation.
        state.channel_funding_reservations.insert(
            request.funding_address.clone(),
            super::ChannelFundingReservation {
                amount_sat: request.amount_sat,
                created_at: ic_cdk::api::time(),
                funding_address: request.funding_address.clone(),
            },
        );
    }

    FundChannelResponse {
        success: true,
        signed_tx: Some(tx_bytes),
        txid: Some(txid),
        error: None,
    }
}
