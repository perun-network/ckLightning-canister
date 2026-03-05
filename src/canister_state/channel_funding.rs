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
        let state = STATE.read().unwrap();
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
        let state = STATE.read().unwrap();
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

    let mut state = STATE.write().unwrap();

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
        let state = STATE.read().unwrap();
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
        let state = STATE.read().unwrap();
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
    let mut state = STATE.write().unwrap();
    for utxo in utxos {
        let key = (utxo.txid.clone(), utxo.vout);
        state.reserved_utxos.insert(key, channel_id);
    }
}

/// Release reserved UTXOs (on channel open failure)
pub fn release_reserved_utxos_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().unwrap();
    state.reserved_utxos.retain(|_, v| *v != channel_id);
}

/// Called when a channel is successfully funded - update tracking
///
/// NOTE: total_btc_in_channels is already incremented in fund_channel_impl(),
/// so we do NOT increment it again here to avoid double-counting.
pub fn channel_funded_impl(channel_id: [u8; 32], capacity_sats: u64) {
    let mut state = STATE.write().unwrap();

    // Remove from reserved UTXOs
    state.reserved_utxos.retain(|_, v| *v != channel_id);

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

/// Called when a channel is closed - update tracking and credit LPs
///
/// Uses the last known `our_balance_sats` from `channel_balances` (updated
/// by periodic `update_channel_balance` calls from the relay) to credit LPs
/// proportionally with the BTC returned from the channel.
pub fn channel_closed_impl(channel_id: [u8; 32]) {
    let mut state = STATE.write().unwrap();

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
