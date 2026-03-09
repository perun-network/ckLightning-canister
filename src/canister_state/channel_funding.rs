// =============================================================================
// LP Liquidity Management (Canister-Controlled BTC for Lightning)
// =============================================================================

use super::STATE;
use crate::error::BtcError;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    LpBtcUtxo, GetFundingUtxosResponse,
    UpdateChannelBalanceRequest, UpdateChannelBalanceResponse,
    LpLiquidityStatus, LnChannelBalance,
};

use bitcoin::Address;
use candid::Nat;
use ic_cdk::api::time as blocktime;
use ic_cdk::bitcoin_canister::{GetUtxosRequest, bitcoin_get_utxos};
use std::str::FromStr;

/// Get available UTXOs from the LP's BTC address for channel funding
pub async fn get_funding_utxos_impl(_min_amount_sats: u64) -> Result<GetFundingUtxosResponse, BtcError> {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Get the LP BTC address
    let lp_address = {
        let state = STATE.read().expect("STATE lock: get_funding_utxos read");
        state.lp_btc_address.clone()
    };

    let lp_address = match lp_address {
        Some(addr) => addr,
        None => {
            return Ok(GetFundingUtxosResponse {
                utxos: vec![],
                total_sats: 0,
                lp_address: None,
            });
        }
    };

    // Parse address
    let _address = Address::from_str(&lp_address)
        .map_err(|e| BtcError::Other(format!("Invalid LP address: {}", e)))?
        .require_network(ctx.bitcoin_network)
        .map_err(|e| BtcError::Other(format!("LP address network mismatch: {:?}", e)))?;

    // Fetch UTXOs from Bitcoin canister
    let utxo_response = bitcoin_get_utxos(&GetUtxosRequest {
        address: lp_address.clone(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to get UTXOs: {:?}", e)))?;

    // Get reserved UTXOs to exclude
    let reserved = {
        let state = STATE.read().expect("STATE lock: get_funding_utxos read 2");
        state.reserved_utxos.clone()
    };

    // Filter out reserved UTXOs and convert to our type
    let mut available_utxos = Vec::new();
    let mut total_sats = 0u64;

    for utxo in utxo_response.utxos {
        let key = (utxo.outpoint.txid.clone(), utxo.outpoint.vout);
        if !reserved.contains_key(&key) {
            total_sats += utxo.value;
            available_utxos.push(LpBtcUtxo {
                txid: utxo.outpoint.txid,
                vout: utxo.outpoint.vout,
                value_sats: utxo.value,
                height: utxo.height,
            });
        }
    }

    // Sort by value descending (prefer larger UTXOs)
    available_utxos.sort_by(|a, b| b.value_sats.cmp(&a.value_sats));

    Ok(GetFundingUtxosResponse {
        utxos: available_utxos,
        total_sats,
        lp_address: Some(lp_address),
    })
}

/// Update channel balance after payment activity
pub fn update_channel_balance_impl(request: UpdateChannelBalanceRequest) -> UpdateChannelBalanceResponse {
    let channel_id: [u8; 32] = match request.channel_id.try_into() {
        Ok(id) => id,
        Err(_) => {
            return UpdateChannelBalanceResponse {
                success: false,
                error: Some("Invalid channel_id length".to_string()),
            };
        }
    };

    let mut state = STATE.write().expect("STATE lock: update_channel_balance");

    // Check if channel exists and get capacity for potential new entry
    let channel_capacity = match state.ln_channels.get(&channel_id) {
        Some(info) => info.capacity_sats,
        None => {
            return UpdateChannelBalanceResponse {
                success: false,
                error: Some("Channel not registered".to_string()),
            };
        }
    };

    // Update or insert channel balance
    let balance = state.channel_balances.entry(channel_id).or_insert_with(|| {
        LnChannelBalance {
            channel_id: channel_id.to_vec(),
            capacity_sats: channel_capacity,
            our_balance_sats: channel_capacity, // Initially we funded it
            their_balance_sats: 0,
            is_active: true,
            last_updated: blocktime(),
        }
    });

    balance.our_balance_sats = request.our_balance_sats;
    balance.their_balance_sats = request.their_balance_sats;
    balance.last_updated = blocktime();

    UpdateChannelBalanceResponse {
        success: true,
        error: None,
    }
}

/// Get overall LP liquidity status
pub async fn get_lp_liquidity_status_impl() -> Result<LpLiquidityStatus, BtcError> {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Get on-chain BTC balance
    let (lp_address, channel_balances, total_btc_deposited, total_btc_in_channels) = {
        let state = STATE.read().expect("STATE lock: get_lp_liquidity_status read");
        (
            state.lp_btc_address.clone(),
            state.channel_balances.clone(),
            state.total_btc_deposited,
            state.total_btc_in_channels,
        )
    };

    // Get on-chain UTXOs
    let (btc_onchain_sats, btc_utxo_count) = if let Some(addr) = &lp_address {
        let utxo_response = bitcoin_get_utxos(&GetUtxosRequest {
            address: addr.clone(),
            network: ctx.network,
            filter: None,
        })
        .await
        .map_err(|e| BtcError::Other(format!("Failed to get UTXOs: {:?}", e)))?;

        let total: u64 = utxo_response.utxos.iter().map(|u| u.value).sum();
        (total, utxo_response.utxos.len() as u32)
    } else {
        (0, 0)
    };

    // Calculate channel liquidity
    let mut channel_total_capacity_sats = 0u64;
    let mut channel_outbound_sats = 0u64;
    let mut channel_inbound_sats = 0u64;
    let mut channel_count = 0u32;

    for balance in channel_balances.values() {
        if balance.is_active {
            channel_total_capacity_sats += balance.capacity_sats;
            channel_outbound_sats += balance.our_balance_sats;
            channel_inbound_sats += balance.their_balance_sats;
            channel_count += 1;
        }
    }

    // Get ckBTC pool balance from liquidity pool
    let ckbtc_pool_sats = {
        let state = STATE.read().expect("STATE lock: get_lp_liquidity_status read 2");
        state.liq_pool.get_total(&PoolAsset::CkBTC).0.try_into().unwrap_or(0)
    };

    Ok(LpLiquidityStatus {
        ckbtc_pool_sats,
        btc_onchain_sats,
        btc_utxo_count,
        channel_total_capacity_sats,
        channel_outbound_sats,
        channel_inbound_sats,
        channel_count,
        total_btc_deposited,
        total_btc_in_channels,
    })
}

/// Reserve UTXOs for a pending channel open
pub fn reserve_utxos_for_channel_impl(utxos: &[LpBtcUtxo], channel_id: [u8; 32]) {
    let mut state = STATE.write().expect("STATE lock: reserve_utxos_for_channel");
    for utxo in utxos {
        let key = (utxo.txid.clone(), utxo.vout);
        state.reserved_utxos.insert(key, channel_id);
    }
}

/// Release reserved UTXOs (on channel open failure)
pub fn release_reserved_utxos_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().expect("STATE lock: release_reserved_utxos");
    state.reserved_utxos.retain(|_, v| *v != channel_id);
}

/// Called when a channel is successfully funded and TX confirmed.
///
/// Two-phase model: this is where LP balances are actually deducted and
/// total_btc_in_channels is incremented. Looks up the reservation by
/// funding_address (from ln_channels registry) or falls back to capacity_sats.
pub fn channel_funded_impl(channel_id: [u8; 32], capacity_sats: u64) {
    let mut state = STATE.write().expect("STATE lock: channel_funded");

    // Remove from reserved UTXOs
    state.reserved_utxos.retain(|_, v| *v != channel_id);

    // Find the funding address for this channel to look up the reservation
    let funding_address = state.ln_channels.get(&channel_id)
        .map(|ch| ch.funding_address.clone());

    // Resolve reservation amount (prefer reservation, fall back to capacity_sats)
    let amount_sat = if let Some(ref addr) = funding_address {
        if let Some(reservation) = state.channel_funding_reservations.remove(addr) {
            reservation.amount_sat
        } else {
            ic_cdk::println!(
                "channel_funded: no reservation found for address {}, using capacity_sats={}",
                addr, capacity_sats
            );
            capacity_sats
        }
    } else {
        ic_cdk::println!(
            "channel_funded: no ln_channel entry for channel, using capacity_sats={}",
            capacity_sats
        );
        capacity_sats
    };

    // NOW commit: increment total and deduct from LPs
    state.total_btc_in_channels = state.total_btc_in_channels.saturating_add(amount_sat);
    let amount_nat = Nat::from(amount_sat);
    if let Err(e) = state.liq_pool.deduct_proportional(PoolAsset::BTC, amount_nat) {
        ic_cdk::println!("ERROR: deduct_proportional failed on channel_funded: {:?}", e);
        // Don't silently continue — this is a real accounting error
        return;
    }

    // Initialize channel balance tracking
    state.channel_balances.insert(channel_id, LnChannelBalance {
        channel_id: channel_id.to_vec(),
        capacity_sats,
        our_balance_sats: capacity_sats, // We funded it, so initially all ours
        their_balance_sats: 0,
        is_active: true,
        last_updated: blocktime(),
    });
}

/// Cancel a pending channel funding (TX never broadcast or failed).
///
/// Removes the idempotency guard and reservation so the channel can be re-attempted.
/// No LP balance changes needed since deduction hasn't happened yet (two-phase model).
pub fn cancel_channel_funding_impl(funding_address: String) -> Result<(), String> {
    let mut state = STATE.write().expect("STATE lock: cancel_channel_funding");

    // Remove idempotency guard
    if !state.funded_channels.remove(&funding_address) {
        return Err(format!("No funded_channels entry for address {}", funding_address));
    }

    // Remove reservation (may not exist if already timed out)
    if state.channel_funding_reservations.remove(&funding_address).is_some() {
        ic_cdk::println!("Cancelled channel funding reservation for {}", funding_address);
    }

    // Release any reserved UTXOs associated with this funding
    // (UTXOs are keyed by outpoint, not funding address, so we can't easily map them here.
    //  The relay should call release_reserved_utxos separately if needed.)

    Ok(())
}

/// Expire stale channel funding reservations (called from heartbeat).
///
/// If a reservation is older than the timeout and channel_funded was never called,
/// release the idempotency guard so the channel can be re-attempted.
pub fn expire_channel_funding_reservations() {
    let now = blocktime();
    // 6 hours in nanoseconds (IC time is in nanoseconds)
    const RESERVATION_TIMEOUT_NS: u64 = 6 * 60 * 60 * 1_000_000_000;

    let mut state = STATE.write().expect("STATE lock: expire_channel_funding_reservations");

    let expired: Vec<String> = state.channel_funding_reservations.iter()
        .filter(|(_, r)| now.saturating_sub(r.created_at) > RESERVATION_TIMEOUT_NS)
        .map(|(k, _)| k.clone())
        .collect();

    for addr in &expired {
        state.channel_funding_reservations.remove(addr);
        state.funded_channels.remove(addr);
        ic_cdk::println!("Expired channel funding reservation for {}", addr);
    }
}

/// Called when a channel is closed - update tracking and credit LPs
///
/// Uses the last known `our_balance_sats` from `channel_balances` (updated
/// by periodic `update_channel_balance` calls from the relay) to credit LPs
/// proportionally with the BTC returned from the channel.
pub fn channel_closed_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().expect("STATE lock: channel_closed");

    // Try channel_balances first (has per-update balance tracking)
    let (our_sats, capacity) = if let Some(balance) = state.channel_balances.get_mut(&channel_id) {
        let our_sats = balance.our_balance_sats;
        let capacity = balance.capacity_sats;
        balance.is_active = false;
        (our_sats, capacity)
    } else if let Some(channel_info) = state.ln_channels.get(&channel_id) {
        // Fallback: channel was registered but no balance updates happened.
        // Assume full capacity is returned (no payments routed through channel yet).
        let capacity = channel_info.capacity_sats;
        ic_cdk::println!(
            "Channel closed (no balance tracking): using capacity {} sats as credit amount",
            capacity
        );
        (capacity, capacity)
    } else {
        ic_cdk::println!("Channel closed: unknown channel_id, no LP credit applied");
        return;
    };

    // Decrement the global channel counter by the original capacity
    state.total_btc_in_channels = state.total_btc_in_channels.saturating_sub(capacity);

    // Credit LPs proportionally with the returned BTC (our_balance_sats)
    // If channel opened at 100k and closes with 95k, LPs get back 95k (5k was paid out)
    if our_sats > 0 {
        let amount_nat = Nat::from(our_sats);
        let recipients = state.liq_pool.credit_proportional(PoolAsset::BTC, amount_nat);
        ic_cdk::println!(
            "Channel closed: credited {} sats back to {} LPs (capacity was {} sats)",
            our_sats, recipients, capacity
        );
    }
}
