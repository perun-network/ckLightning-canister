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

/// Parse and validate a 32-byte channel_id, returning a fixed-size array.
fn parse_channel_id(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| format!(
        "Invalid channel_id length: expected 32 bytes, got {}", bytes.len()
    ))
}

/// Validate a byte field has the expected length, returning descriptive error.
fn validate_len(field: &str, bytes: &[u8], expected: usize) -> Result<(), String> {
    if bytes.len() != expected {
        Err(format!("Invalid {field} length (must be {expected} bytes)"))
    } else {
        Ok(())
    }
}

/// Register a new Lightning channel for funding verification
///
/// Called by the relay node when a channel is opened.
/// Stores the channel info so the funding UTXO can be verified on-chain.
pub fn register_ln_channel_impl(request: RegisterLnChannelRequest) -> RegisterLnChannelResponse {
    let channel_id_arr = match parse_channel_id(&request.channel_id) {
        Ok(arr) => arr,
        Err(e) => return RegisterLnChannelResponse { success: false, error: Some(e) },
    };

    // Validate field lengths
    for (field, bytes, len) in [
        ("funding_txid", request.funding_txid.as_slice(), 32),
        ("local_node_id", request.local_node_id.as_slice(), 33),
        ("remote_node_id", request.remote_node_id.as_slice(), 33),
    ] {
        if let Err(e) = validate_len(field, bytes, len) {
            return RegisterLnChannelResponse { success: false, error: Some(e) };
        }
    }

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
    let channel_id_arr = match parse_channel_id(&request.channel_id) {
        Ok(arr) => arr,
        Err(e) => return verify_err(e),
    };

    // Get channel info
    let channel_info = {
        let state = STATE.read().expect("STATE lock: verify_ln_channel read");
        match state.ln_channels.get(&channel_id_arr) {
            Some(info) => info.clone(),
            None => return verify_err("Channel not found".to_string()),
        }
    };

    // Query UTXOs for the funding address
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());
    let utxos_response = match bitcoin_get_utxos(&GetUtxosRequest {
        address: channel_info.funding_address.clone(),
        network: ctx.network,
        filter: None,
    }).await {
        Ok(response) => response,
        Err(e) => return verify_err(format!("Failed to query UTXOs: {e:?}")),
    };

    // Find the specific funding UTXO by txid and vout
    let found_utxo = find_funding_utxo(&utxos_response, &channel_info);

    // Update channel status and build response
    update_channel_verification(&channel_id_arr, &channel_info, found_utxo)
}

/// Build a failed VerifyLnChannelResponse.
fn verify_err(msg: String) -> VerifyLnChannelResponse {
    VerifyLnChannelResponse { verified: false, confirmations: None, utxo_value_sats: None, error: Some(msg) }
}

/// Search UTXO set for the channel's funding outpoint, returning (value, confirmations).
fn find_funding_utxo(
    utxos_response: &ic_cdk::bitcoin_canister::GetUtxosResponse,
    channel_info: &LnChannelInfo,
) -> Option<(u64, u32)> {
    let funding_txid = &channel_info.funding_outpoint.txid;
    let funding_vout = channel_info.funding_outpoint.vout;

    utxos_response.utxos.iter().find_map(|utxo| {
        if utxo.outpoint.txid.as_slice() == funding_txid.as_slice()
            && utxo.outpoint.vout == funding_vout
        {
            let confirmations = if utxo.height > 0 {
                utxos_response.tip_height.saturating_sub(utxo.height) + 1
            } else {
                0
            };
            Some((utxo.value, confirmations))
        } else {
            None
        }
    })
}

/// Update channel status based on UTXO verification result and build the response.
fn update_channel_verification(
    channel_id_arr: &[u8; 32],
    channel_info: &LnChannelInfo,
    found_utxo: Option<(u64, u32)>,
) -> VerifyLnChannelResponse {
    let current_time = blocktime();
    let mut state = STATE.write().expect("STATE lock: verify_ln_channel write");
    let channel = match state.ln_channels.get_mut(channel_id_arr) {
        Some(ch) => ch,
        None => return verify_err("Channel not found".to_string()),
    };
    channel.last_verified_at = Some(current_time);

    match found_utxo {
        Some((value, confirmations)) => {
            let value_matches = value == channel_info.capacity_sats;

            channel.status = if value_matches && confirmations >= 2 {
                LnChannelStatus::Verified { confirmations }
            } else if !value_matches {
                LnChannelStatus::Failed {
                    reason: format!("Value mismatch: expected {} sats, found {} sats",
                        channel_info.capacity_sats, value),
                }
            } else {
                LnChannelStatus::Pending
            };

            let error = if !value_matches {
                Some(format!("Value mismatch: expected {} sats, found {} sats",
                    channel_info.capacity_sats, value))
            } else if confirmations < 2 {
                Some(format!("Insufficient confirmations: {confirmations} (need at least 2)"))
            } else {
                None
            };

            VerifyLnChannelResponse {
                verified: value_matches && confirmations >= 2,
                confirmations: Some(confirmations),
                utxo_value_sats: Some(value),
                error,
            }
        }
        None => {
            if matches!(&channel.status, LnChannelStatus::Verified { .. }) {
                channel.status = LnChannelStatus::Closed;
            }

            VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!(
                    "Funding UTXO not found at address {}. Channel may be closed or funding tx not yet confirmed.",
                    channel_info.funding_address
                )),
            }
        }
    }
}

/// Query a specific Lightning channel
pub fn query_ln_channel_impl(request: QueryLnChannelRequest) -> Option<LnChannelInfo> {
    let channel_id_arr = parse_channel_id(&request.channel_id).ok()?;
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
    let channel_id_arr = match parse_channel_id(&channel_id) {
        Ok(arr) => arr,
        Err(_) => return false,
    };
    let mut state = STATE.write().expect("STATE lock: update_ln_channel_status");
    if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
        channel.status = status;
        true
    } else {
        false
    }
}
