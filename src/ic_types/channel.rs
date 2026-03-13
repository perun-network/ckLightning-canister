use candid::{CandidType, Deserialize, Nat, Principal};

use super::btc::BtcOutpoint;
use super::constants::Amount;
use super::primitives::*;

// =============================================================================
// Perun Channel Types
// =============================================================================

#[derive(Deserialize, CandidType, Default, Clone, Debug)]
pub enum CklChannelAction {
    #[default]
    Idle,
    Depositing,
    Withdrawing,
}

#[derive(Deserialize, CandidType, Default, Clone, Debug)]
/// The mutable parameters and state of a channel.
pub struct State {
    /// The cannel's unique identifier.
    pub channel: ChannelId,
    /// The channel's current state revision number.
    pub version: Version,
    /// The channel's asset allocation. Contains each participant's current
    /// balance in the order of the channel parameters' participant list.
    pub allocation: Vec<Amount>,
    /// Whether the channel is finalized, i.e., no more updates can be made and
    /// funds can be withdrawn immediately. A non-finalized channel has to be
    /// finalized via the canister after the channel's challenge duration
    /// elapses.
    pub remote_id: Option<L2Account>,
    pub action: CklChannelAction,
    pub finalized: bool,
}

impl State {
    pub fn get_channelid(&self) -> ChannelId {
        self.channel.clone()
    }

    pub fn get_action(&self) -> CklChannelAction {
        self.action.clone()
    }

    pub fn total(&self) -> Amount {
        self.allocation
            .iter()
            .fold(Amount::default(), |x, y| x + y.clone())
    }

    /// Channels that are in their initial state may not yet be fully funded,
    /// but may be registered already for disputes. This is to retrieve funds of
    /// channels where the funding phase does not complete.
    pub fn may_be_underfunded(&self) -> bool {
        self.version == 0 && !self.finalized
    }
}

#[derive(Deserialize, CandidType, Clone)]
/// The immutable parameters and state of a Perun channel.
pub struct Params {
    /// The channel's unique nonce, to protect against replay attacks.
    pub nonce: Nonce,
    /// The channel's participants' layer-2 identities.
    pub participants: Vec<L2Account>,
    /// When a dispute occurs, how long to wait for responses.
    pub challenge_duration: Duration,
}

impl Params {
    pub fn id(&self) -> ChannelId {
        let mut params_bytes = Vec::new();
        params_bytes.extend_from_slice(&self.nonce.0);

        for participant in &self.participants {
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            params_bytes.extend_from_slice(participant.0.to_encoded_point(false).as_bytes());
        }

        let challenge_duration_bytes = self.challenge_duration.to_le_bytes();
        params_bytes.extend_from_slice(&challenge_duration_bytes);

        let hash = Hash::digest(&params_bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash.0[..32]); // Take only first 32 bytes
        ChannelId(arr)
    }
}

#[derive(Clone, Deserialize, CandidType)]
/// A registered channel's state, as seen by the canister. Represents a channel
/// after a call to "conclude" or "dispute" on the canister. The timeout, in
/// combination with the state's "finalized" flag determine whether a channel is
/// concluded and its funds ready for withdrawing.
pub struct RegisteredState {
    /// The channel's state, containing challenge duration, outcomes, and
    /// whether the channel is already finalized.
    pub state: State,
    /// The challenge timeout after which the currently registered state becomes
    /// available for withdrawing. Ignored for finalized channels.
    pub timeout: Timestamp,
}

impl RegisteredState {
    pub fn settled(&self, now: Timestamp) -> bool {
        self.state.finalized || now >= self.timeout
    }
}

#[derive(Deserialize, CandidType, Clone)]
pub struct WithdrawalReq {
    /// The funds to be withdrawn.
    pub channel: ChannelId,
    pub participant: L2Account,
    pub amount: Nat,
    /// The layer-1 identity to send the funds to.
    pub receiver: Principal,
}

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
