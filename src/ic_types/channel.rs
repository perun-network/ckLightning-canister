use candid::{CandidType, Deserialize};

use super::btc::BtcOutpoint;

// =============================================================================
// Lightning Channel Types
// =============================================================================

/// Status of a Lightning channel's on-chain funding
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum LnChannelStatus {
    /// Channel registered, funding UTXO not yet verified
    Pending,
    /// Funding UTXO verified on-chain with sufficient confirmations
    Verified { confirmations: u32 },
    /// Channel closed (funding UTXO spent)
    Closed,
    /// Verification failed
    Failed { reason: String },
}

/// Information about a Lightning channel's on-chain funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LnChannelInfo {
    /// Unique channel ID (from LDK, typically funding_txid XOR funding_output_index)
    pub channel_id: Vec<u8>,
    /// Funding transaction outpoint
    pub funding_outpoint: BtcOutpoint,
    /// Channel capacity in satoshis
    pub capacity_sats: u64,
    /// Our node's public key (33 bytes compressed)
    pub local_node_id: Vec<u8>,
    /// Remote peer's public key (33 bytes compressed)
    pub remote_node_id: Vec<u8>,
    /// The P2WSH funding address (provided by relay)
    pub funding_address: String,
    /// When the channel was registered (Unix nanoseconds)
    pub registered_at: u64,
    /// Last verification timestamp (Unix nanoseconds)
    pub last_verified_at: Option<u64>,
    /// Current status
    pub status: LnChannelStatus,
}

/// Request to register a new Lightning channel
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterLnChannelRequest {
    /// Unique channel ID (32 bytes)
    pub channel_id: Vec<u8>,
    /// Funding transaction ID (32 bytes)
    pub funding_txid: Vec<u8>,
    /// Funding output index
    pub funding_vout: u32,
    /// Channel capacity in satoshis
    pub capacity_sats: u64,
    /// Our node's public key (33 bytes compressed)
    pub local_node_id: Vec<u8>,
    /// Remote peer's public key (33 bytes compressed)
    pub remote_node_id: Vec<u8>,
    /// The P2WSH funding address
    pub funding_address: String,
}

/// Response from registering a Lightning channel
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterLnChannelResponse {
    /// Whether the channel was successfully registered
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Response from verifying a Lightning channel's funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct VerifyLnChannelResponse {
    /// Whether the funding UTXO was found on-chain
    pub verified: bool,
    /// Number of confirmations (if found)
    pub confirmations: Option<u32>,
    /// Actual value of the UTXO in satoshis (if found)
    pub utxo_value_sats: Option<u64>,
    /// Error message if verification failed
    pub error: Option<String>,
}

/// Query request for channel information
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryLnChannelRequest {
    /// Channel ID to query (32 bytes)
    pub channel_id: Vec<u8>,
}

/// Response containing all registered Lightning channels
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct QueryLnChannelsResponse {
    /// List of all registered channels
    pub channels: Vec<LnChannelInfo>,
}

/// Response containing the canister's Lightning funding pubkey
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LnFundingPubkeyResponse {
    /// Compressed SEC1 public key (33 bytes)
    pub pubkey: Vec<u8>,
    /// The derived P2WSH address (when combined with counterparty key)
    /// This is None until we know the counterparty's pubkey
    pub address: Option<String>,
}

/// Request for the canister to sign a Lightning-related message
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LnSignRequest {
    /// The 32-byte message hash to sign (e.g., commitment transaction sighash)
    pub message_hash: Vec<u8>,
    /// Optional context/purpose for logging/auditing
    pub purpose: Option<String>,
}

/// Response containing the ECDSA signature
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LnSignResponse {
    /// Whether signing succeeded
    pub success: bool,
    /// The 64-byte compact ECDSA signature (r || s)
    pub signature: Option<Vec<u8>>,
    /// Error message if signing failed
    pub error: Option<String>,
}
