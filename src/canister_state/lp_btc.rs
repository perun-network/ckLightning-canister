// =============================================================================
// BTC Liquidity Pool Implementation (Per-User LP Addresses + Internal Treasury)
// + User BTC Operations (from depositor address)
// + Channel Funding from LP BTC
// =============================================================================

use super::STATE;
use crate::BtcPurpose;
use crate::btc::address::get_segwit_address;
use crate::btc::common::get_fee_per_byte;
use crate::btc::ecdsa::{get_ecdsa_public_key, sign_with_ecdsa};
use crate::btc::p2wpkh::{self, SourcedUtxo};
use crate::error::BtcError;
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

/// Get the caller's per-user LP BTC deposit address
///
/// Each LP depositor gets a unique address derived from their principal.
/// This prevents the first-claimer-wins issue of the shared address.
pub async fn get_lp_btc_user_address_impl() -> Result<LpBtcAddressResponse, BtcError> {
    let caller = msg_caller();

    // Check cache first
    {
        let state = STATE.read().expect("STATE lock: get_lp_btc_user_address read");
        if let Some(addr) = state.btc_liquidity_addresses.get(&caller) {
            return Ok(LpBtcAddressResponse {
                address: addr.clone(),
            });
        }
    }

    // Derive per-user LP deposit address (distinct from user's personal BTC address)
    let purpose = BtcPurpose::LiquidityPoolUser(caller);
    let address = get_segwit_address(purpose).await?;

    // Cache it
    {
        let mut state = STATE.write().expect("STATE lock: get_lp_btc_user_address write");
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
            let mut state = STATE.write().expect("STATE lock: deposit_btc_user write");
            if state.processed_utxos.contains_key(&utxo_key) {
                continue;
            }
            state.processed_utxos.insert(utxo_key, caller);
            state.liq_pool.deposit(caller, PoolAsset::BTC, Nat::from(amount));
        }

        total_credited += amount;
    }

    let new_btc_balance = {
        let state = STATE.read().expect("STATE lock: deposit_btc_user read");
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
/// Collects UTXOs from all LP addresses (per-user + shared) and sends BTC
/// to the user's destination address. Change goes to the shared LP address.
pub async fn withdraw_btc_impl(request: LpBtcWithdrawRequest) -> LpBtcWithdrawResponse {
    let caller = msg_caller();
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    if request.destination_address.len() > 200 {
        return LpBtcWithdrawResponse {
            success: false,
            amount_withdrawn: Nat::from(0u64),
            new_btc_balance: Nat::from(0u64),
            txid: None,
            error: Some("Destination address too long (max 200 chars)".to_string()),
        };
    }

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
    {
        let mut state = STATE.write().expect("STATE lock: withdraw_btc write");

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

    // Parse destination address
    let dst_address = match Address::from_str(&request.destination_address) {
        Ok(addr) => match addr.require_network(ctx.bitcoin_network) {
            Ok(a) => a,
            Err(e) => {
                // Restore LP balance
                let mut state = STATE.write().expect("STATE lock: withdraw_btc restore");
                state.liq_pool.deposit(caller, PoolAsset::BTC, amount_nat.clone());
                let bal = state.liq_pool.get_balance(&caller, &PoolAsset::BTC);
                return LpBtcWithdrawResponse {
                    success: false, amount_withdrawn: Nat::from(0u64),
                    new_btc_balance: bal, txid: None,
                    error: Some(format!("Address network mismatch: {:?}", e)),
                };
            }
        },
        Err(e) => {
            let mut state = STATE.write().expect("STATE lock: withdraw_btc restore 2");
            state.liq_pool.deposit(caller, PoolAsset::BTC, amount_nat.clone());
            let bal = state.liq_pool.get_balance(&caller, &PoolAsset::BTC);
            return LpBtcWithdrawResponse {
                success: false, amount_withdrawn: Nat::from(0u64),
                new_btc_balance: bal, txid: None,
                error: Some(format!("Invalid destination address: {}", e)),
            };
        }
    };

    // Collect UTXOs from all LP addresses
    let (all_sourced_utxos, change_address) = match collect_all_lp_sourced_utxos(&ctx).await {
        Ok(result) => result,
        Err(e) => {
            let mut state = STATE.write().expect("STATE lock: withdraw_btc restore 3");
            state.liq_pool.deposit(caller, PoolAsset::BTC, amount_nat.clone());
            let bal = state.liq_pool.get_balance(&caller, &PoolAsset::BTC);
            return LpBtcWithdrawResponse {
                success: false, amount_withdrawn: Nat::from(0u64),
                new_btc_balance: bal, txid: None,
                error: Some(format!("Failed to collect LP UTXOs: {:?}", e)),
            };
        }
    };

    let fee_per_byte = get_fee_per_byte(&ctx).await;

    let (transaction, prevouts, selected_indices) =
        p2wpkh::build_multi_address_transaction(
            &ctx, &all_sourced_utxos, &change_address,
            &dst_address, request.amount_sat, fee_per_byte,
        ).await;

    let signed_tx = p2wpkh::sign_multi_address_transaction(
        &ctx, &all_sourced_utxos, &selected_indices,
        transaction, &prevouts, sign_with_ecdsa,
    ).await;

    match bitcoin_send_transaction(&SendTransactionRequest {
        network: ctx.network,
        transaction: serialize(&signed_tx),
    }).await {
        Ok(_) => {
            let new_btc_balance = {
                let state = STATE.read().expect("STATE lock: withdraw_btc read");
                state.liq_pool.get_balance(&caller, &PoolAsset::BTC)
            };
            LpBtcWithdrawResponse {
                success: true,
                amount_withdrawn: amount_nat,
                new_btc_balance,
                txid: Some(signed_tx.compute_txid().to_string()),
                error: None,
            }
        }
        Err(e) => {
            // Restore LP balance on broadcast failure
            {
                let mut state = STATE.write().expect("STATE lock: withdraw_btc write 2");
                state.liq_pool.deposit(caller, PoolAsset::BTC, amount_nat.clone());
            }
            let new_btc_balance = {
                let state = STATE.read().expect("STATE lock: withdraw_btc read 2");
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

    // Get or derive the caller's personal depositor address (NOT the LP address)
    let address = {
        let state = STATE.read().expect("STATE lock: get_depositor_btc_balance read");
        state.btc_depositor_addresses.get(&caller).cloned()
    };

    let address = match address {
        Some(addr) => addr,
        None => {
            // Derive the personal address if not yet stored
            let purpose = BtcPurpose::LiquidityDepositor(caller);
            match get_segwit_address(purpose).await {
                Ok(addr) => {
                    // Store in personal depositor cache (separate from LP addresses)
                    let mut state = STATE.write().expect("STATE lock: get_depositor_btc_balance write");
                    state.btc_depositor_addresses.insert(caller, addr.clone());
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

    if request.destination_address.len() > 200 {
        return SendFromDepositorResponse {
            success: false,
            txid: None,
            error: Some("Destination address too long (max 200 chars)".to_string()),
        };
    }

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

// =============================================================================
// Multi-address UTXO collection for LP spending
// =============================================================================

/// Collect UTXOs from all LP-related addresses (shared treasury + all per-user depositor addresses).
/// The canister controls the keys for all of these via threshold ECDSA.
async fn collect_all_lp_sourced_utxos(
    ctx: &crate::BitcoinContext,
) -> Result<(Vec<SourcedUtxo>, Address), BtcError> {
    let mut sourced = Vec::new();

    // 1. Shared LP address (receives change from multi-address spends)
    let shared_purpose = BtcPurpose::LiquidityPoolShared;
    let shared_deriv = shared_purpose.derivation_path();
    let shared_pk_bytes = get_ecdsa_public_key(ctx, shared_deriv.clone()).await;
    let shared_compressed = CompressedPublicKey::from_slice(&shared_pk_bytes)
        .map_err(|e| BtcError::Other(format!("Failed to parse shared LP public key: {}", e)))?;
    let shared_pk = PublicKey::from_slice(&shared_pk_bytes)
        .map_err(|e| BtcError::Other(format!("Failed to parse shared LP public key: {}", e)))?;
    let shared_addr = Address::p2wpkh(&shared_compressed, ctx.bitcoin_network);

    let shared_utxos = bitcoin_get_utxos(&GetUtxosRequest {
        address: shared_addr.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to fetch shared LP UTXOs: {:?}", e)))?
    .utxos;

    for utxo in shared_utxos {
        sourced.push(SourcedUtxo {
            utxo,
            address: shared_addr.clone(),
            public_key: shared_pk,
            derivation_path: shared_deriv.clone(),
        });
    }

    // 2. All per-user depositor addresses
    let depositor_principals: Vec<candid::Principal> = {
        let state = STATE.read().expect("STATE lock: collect_lp_utxos");
        state.btc_liquidity_addresses.keys().cloned().collect()
    };

    for principal in depositor_principals {
        let purpose = BtcPurpose::LiquidityPoolUser(principal);
        let deriv = purpose.derivation_path();
        let pk_bytes = get_ecdsa_public_key(ctx, deriv.clone()).await;
        let compressed = CompressedPublicKey::from_slice(&pk_bytes)
            .map_err(|e| BtcError::Other(format!("Failed to parse depositor key: {}", e)))?;
        let pk = PublicKey::from_slice(&pk_bytes)
            .map_err(|e| BtcError::Other(format!("Failed to parse depositor key: {}", e)))?;
        let addr = Address::p2wpkh(&compressed, ctx.bitcoin_network);

        let utxos = bitcoin_get_utxos(&GetUtxosRequest {
            address: addr.to_string(),
            network: ctx.network,
            filter: None,
        })
        .await
        .map_err(|e| BtcError::Other(format!("Failed to fetch depositor UTXOs: {:?}", e)))?
        .utxos;

        for utxo in utxos {
            sourced.push(SourcedUtxo {
                utxo,
                address: addr.clone(),
                public_key: pk,
                derivation_path: deriv.clone(),
            });
        }
    }

    // Return all sourced UTXOs + the shared address (used as change address)
    Ok((sourced, shared_addr))
}

/// Fund a Lightning channel from LP BTC
/// Collects UTXOs from all LP addresses (per-user + shared) and builds a
/// multi-input transaction. Change goes to the shared LP address.
/// The relay passes the signed tx to LDK which handles broadcast timing.
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
        let state = STATE.read().expect("STATE lock: fund_channel read");
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

    // Collect UTXOs from all LP addresses (shared + all per-user depositor addresses)
    let (all_sourced_utxos, change_address) = match collect_all_lp_sourced_utxos(&ctx).await {
        Ok(result) => result,
        Err(e) => {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to collect LP UTXOs: {:?}", e)),
            };
        }
    };

    let total_available: u64 = all_sourced_utxos.iter().map(|su| su.utxo.value).sum();
    let fee_margin = 5000u64;
    if total_available < request.amount_sat.saturating_add(fee_margin) {
        return FundChannelResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some(format!(
                "Insufficient BTC across all LP addresses: available {} sats, requested {} sats (+ ~{} fees)",
                total_available, request.amount_sat, fee_margin
            )),
        };
    }

    let fee_per_byte = get_fee_per_byte(&ctx).await;

    // Build multi-address transaction (inputs from different depositor addresses)
    let (transaction, prevouts, selected_indices) =
        p2wpkh::build_multi_address_transaction(
            &ctx,
            &all_sourced_utxos,
            &change_address,
            &funding_address,
            request.amount_sat,
            fee_per_byte,
        )
        .await;

    // Sign with real ECDSA — each input signed with its own derivation path
    let signed_tx = p2wpkh::sign_multi_address_transaction(
        &ctx,
        &all_sourced_utxos,
        &selected_indices,
        transaction,
        &prevouts,
        sign_with_ecdsa,
    )
    .await;

    let tx_bytes = serialize(&signed_tx);
    let txid = signed_tx.compute_txid().to_string();

    // Track the funding in canister state (atomically with idempotency guard)
    // Two-phase model: create reservation only. LP deduction happens in channel_funded.
    {
        let mut state = STATE.write().expect("STATE lock: fund_channel write");
        if !state.funded_channels.insert(request.funding_address.clone()) {
            return FundChannelResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel already funded for this address".to_string()),
            };
        }
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
