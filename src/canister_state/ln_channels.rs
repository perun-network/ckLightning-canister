// =============================================================================
// Lightning Channel Funding Verification Implementation
// =============================================================================

use super::STATE;
use crate::ic_types::{
    BtcOutpoint, LnChannelInfo, LnChannelStatus,
    QueryLnChannelRequest, QueryLnChannelsResponse, RegisterLnChannelRequest,
    RegisterLnChannelResponse, VerifyLnChannelResponse,
};

use ic_cdk::api::time as blocktime;
use ic_cdk::bitcoin_canister::{GetUtxosRequest, bitcoin_get_utxos};

/// Register a new Lightning channel for funding verification
///
/// Called by the relay node when a channel is opened.
/// Stores the channel info so the funding UTXO can be verified on-chain.
pub fn register_ln_channel_impl(request: RegisterLnChannelRequest) -> RegisterLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    // Validate funding_txid length
    if request.funding_txid.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid funding_txid length (must be 32 bytes)".to_string()),
        };
    }

    // Validate node IDs (33 bytes compressed pubkey)
    if request.local_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid local_node_id length (must be 33 bytes)".to_string()),
        };
    }
    if request.remote_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid remote_node_id length (must be 33 bytes)".to_string()),
        };
    }

    // Convert to fixed array
    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Check if channel already exists
    {
        let state = STATE.read().expect("STATE lock: register_ln_channel read");
        if state.ln_channels.contains_key(&channel_id_arr) {
            return RegisterLnChannelResponse {
                success: false,
                error: Some("Channel with this channel_id already registered".to_string()),
            };
        }
    }

    // Create channel info
    let channel_info = LnChannelInfo {
        channel_id: request.channel_id.clone(),
        funding_outpoint: BtcOutpoint {
            txid: request.funding_txid.clone(),
            vout: request.funding_vout,
        },
        capacity_sats: request.capacity_sats,
        local_node_id: request.local_node_id.clone(),
        remote_node_id: request.remote_node_id.clone(),
        funding_address: request.funding_address.clone(),
        registered_at: blocktime(),
        last_verified_at: None,
        status: LnChannelStatus::Pending,
    };

    // Store channel
    {
        let mut state = STATE.write().expect("STATE lock: register_ln_channel write");
        state.ln_channels.insert(channel_id_arr, channel_info);
    }

    RegisterLnChannelResponse {
        success: true,
        error: None,
    }
}

/// Verify a Lightning channel's funding UTXO on-chain
///
/// Queries the Bitcoin canister to check if the funding UTXO exists
/// and has sufficient confirmations.
pub async fn verify_ln_channel_impl(
    request: QueryLnChannelRequest,
) -> VerifyLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return VerifyLnChannelResponse {
            verified: false,
            confirmations: None,
            utxo_value_sats: None,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Get channel info
    let channel_info = {
        let state = STATE.read().expect("STATE lock: verify_ln_channel read");
        match state.ln_channels.get(&channel_id_arr) {
            Some(info) => info.clone(),
            None => {
                return VerifyLnChannelResponse {
                    verified: false,
                    confirmations: None,
                    utxo_value_sats: None,
                    error: Some("Channel not found".to_string()),
                };
            }
        }
    };

    // Get Bitcoin context
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Use the stored funding address (provided by relay when registering)
    let funding_address = &channel_info.funding_address;

    // Query UTXOs for the funding address
    let utxos_result = bitcoin_get_utxos(&GetUtxosRequest {
        address: funding_address.clone(),
        network: ctx.network,
        filter: None, // Get all UTXOs including unconfirmed
    })
    .await;

    let utxos_response = match utxos_result {
        Ok(response) => response,
        Err(e) => {
            return VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!("Failed to query UTXOs: {:?}", e)),
            };
        }
    };

    // Get current tip height to calculate confirmations
    let tip_height = utxos_response.tip_height;

    // Look for the specific funding UTXO by matching txid and vout
    // Note: The txid in the UTXO response is in internal byte order (little-endian)
    // while Lightning typically uses big-endian (display order)
    let funding_txid = &channel_info.funding_outpoint.txid;
    let funding_vout = channel_info.funding_outpoint.vout;

    let mut found_utxo: Option<(u64, u32)> = None; // (value, confirmations)

    for utxo in &utxos_response.utxos {
        // Compare txid (both should be in the same byte order from the canister)
        if utxo.outpoint.txid.as_slice() == funding_txid.as_slice()
            && utxo.outpoint.vout == funding_vout
        {
            // Found the funding UTXO
            let confirmations = if utxo.height > 0 {
                tip_height.saturating_sub(utxo.height) + 1
            } else {
                0 // Unconfirmed
            };
            found_utxo = Some((utxo.value, confirmations));
            break;
        }
    }

    match found_utxo {
        Some((value, confirmations)) => {
            // Verify the value matches the claimed capacity
            let value_matches = value == channel_info.capacity_sats;

            // Update channel status
            let current_time = blocktime();
            {
                let mut state = STATE.write().expect("STATE lock: verify_ln_channel write");
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    if value_matches && confirmations >= 3 {
                        channel.status = LnChannelStatus::Verified {
                            confirmations: confirmations as u32,
                        };
                    } else if !value_matches {
                        channel.status = LnChannelStatus::Failed {
                            reason: format!(
                                "Value mismatch: expected {} sats, found {} sats",
                                channel_info.capacity_sats, value
                            ),
                        };
                    } else {
                        // Not enough confirmations yet, keep as pending
                        channel.status = LnChannelStatus::Pending;
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: value_matches && confirmations >= 3,
                confirmations: Some(confirmations as u32),
                utxo_value_sats: Some(value),
                error: if !value_matches {
                    Some(format!(
                        "Value mismatch: expected {} sats, found {} sats",
                        channel_info.capacity_sats, value
                    ))
                } else if confirmations < 3 {
                    Some(format!(
                        "Insufficient confirmations: {} (need at least 3)",
                        confirmations
                    ))
                } else {
                    None
                },
            }
        }
        None => {
            // UTXO not found - channel might be closed or funding tx not yet confirmed
            let current_time = blocktime();
            {
                let mut state = STATE.write().expect("STATE lock: verify_ln_channel write 2");
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    // Check if channel was previously verified - if so, it's now closed
                    match &channel.status {
                        LnChannelStatus::Verified { .. } => {
                            channel.status = LnChannelStatus::Closed;
                        }
                        _ => {
                            // Keep current status, UTXO might not be confirmed yet
                        }
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!(
                    "Funding UTXO not found at address {}. Channel may be closed or funding tx not yet confirmed.",
                    funding_address
                )),
            }
        }
    }
}

/// Query a specific Lightning channel
pub fn query_ln_channel_impl(request: QueryLnChannelRequest) -> Option<LnChannelInfo> {
    if request.channel_id.len() != 32 {
        return None;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    let state = STATE.read().expect("STATE lock: query_ln_channel");
    state.ln_channels.get(&channel_id_arr).cloned()
}

/// Query all registered Lightning channels (relay or admin only)
pub fn query_ln_channels_impl() -> QueryLnChannelsResponse {
    let caller = ic_cdk::api::msg_caller();
    let state = STATE.read().expect("STATE lock: query_ln_channels");

    let is_relay = matches!(&state.registered_relay, Some(r) if r.principal == caller);
    let is_admin = state.admin == Some(caller);
    if !is_relay && !is_admin {
        return QueryLnChannelsResponse { channels: vec![] };
    }

    let channels: Vec<LnChannelInfo> = state.ln_channels.values().cloned().collect();
    QueryLnChannelsResponse { channels }
}

/// Update a Lightning channel's status (e.g., when closed)
pub fn update_ln_channel_status_impl(channel_id: Vec<u8>, status: LnChannelStatus) -> bool {
    if channel_id.len() != 32 {
        return false;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&channel_id);

    let mut state = STATE.write().expect("STATE lock: update_ln_channel_status");
    if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
        channel.status = status;
        true
    } else {
        false
    }
}
