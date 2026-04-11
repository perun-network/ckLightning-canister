use candid::{CandidType, Deserialize};

// =============================================================================
// HTLC Types (Hash Time-Locked Contracts)
// =============================================================================

/// Request to create a new HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateHtlcRequest {
    /// SHA256 hash of the preimage (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Absolute block height for timeout (CLTV)
    pub cltv_expiry: u32,
    /// Sender's public key (33 bytes compressed)
    pub sender_pubkey: Vec<u8>,
    /// Receiver's public key (33 bytes compressed)
    pub receiver_pubkey: Vec<u8>,
}

/// Response from creating an HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateHtlcResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Request to fulfill an HTLC with preimage
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FulfillHtlcRequest {
    /// The preimage that hashes to the payment_hash (32 bytes)
    pub preimage: Vec<u8>,
}

/// Response from fulfilling an HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FulfillHtlcResponse {
    pub success: bool,
    pub payment_hash: Option<Vec<u8>>,
    pub amount_msat: Option<u64>,
    pub error: Option<String>,
}

/// Request to timeout an HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct TimeoutHtlcRequest {
    /// The payment hash of the HTLC to timeout (32 bytes)
    pub payment_hash: Vec<u8>,
}

/// Response from timing out an HTLC
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct TimeoutHtlcResponse {
    pub success: bool,
    pub amount_msat: Option<u64>,
    pub error: Option<String>,
}

/// HTLC info returned by queries
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct HtlcInfo {
    pub payment_hash: Vec<u8>,
    pub amount_msat: u64,
    pub cltv_expiry: u32,
    /// "Pending", "Fulfilled", "TimedOut", or "Failed"
    pub state: String,
    pub sender_pubkey: Vec<u8>,
    pub receiver_pubkey: Vec<u8>,
}

// =============================================================================
// Channel Secrets (Phase 2: Full channel control by canister)
// =============================================================================

/// All secrets needed to control a Lightning channel.
///
/// These are stored in canister state (NOT threshold-protected).
/// Security tradeoff: Subnet nodes (~13) could theoretically extract these,
/// but this is accepted per HTLC_SECRET_IMPL.md research.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChannelSecrets {
    /// Channel identifier (32 bytes)
    pub channel_id: Vec<u8>,
    /// HTLC base secret - signs HTLC-Success and HTLC-Timeout transactions
    pub htlc_base_secret: Vec<u8>,
    /// Revocation base secret - signs justice/penalty transactions
    pub revocation_base_secret: Vec<u8>,
    /// Delayed payment base secret - signs timelocked outputs after channel close
    pub delayed_payment_base_secret: Vec<u8>,
    /// Payment secret - signs to_remote outputs after channel close
    pub payment_secret: Vec<u8>,
    /// Commitment seed - derives per-commitment secrets
    pub commitment_seed: Vec<u8>,
}

/// Query channel secrets status
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ChannelSecretsInfo {
    pub channel_id: Vec<u8>,
    pub has_secrets: bool,
    /// Public keys (secrets are never exposed)
    pub htlc_basepoint: Vec<u8>,
    pub revocation_basepoint: Vec<u8>,
    pub delayed_payment_basepoint: Vec<u8>,
    pub payment_point: Vec<u8>,
}

// =============================================================================
// HTLC Transaction Details (for signing - stored when HTLC is created)
// =============================================================================

/// Extended HTLC creation request with transaction details for later signing.
///
/// This follows approach A: store full HTLC transaction details in canister
/// so signing doesn't require relay to provide all details again.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateHtlcWithTxDetailsRequest {
    /// SHA256 hash of the preimage (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Absolute block height for timeout (CLTV)
    pub cltv_expiry: u32,
    /// Sender's public key (33 bytes compressed)
    pub sender_pubkey: Vec<u8>,
    /// Receiver's public key (33 bytes compressed)
    pub receiver_pubkey: Vec<u8>,
    /// Channel ID this HTLC belongs to (32 bytes)
    pub channel_id: Vec<u8>,
    /// The HTLC output's outpoint (txid:vout) - where the HTLC is locked
    pub htlc_outpoint_txid: Vec<u8>,
    pub htlc_outpoint_vout: u32,
    /// The HTLC output amount in satoshis
    pub htlc_amount_sat: u64,
    /// Receiver's address for HTLC-Success (where funds go when claimed)
    pub receiver_address: String,
    /// Sender's address for HTLC-Timeout (where funds return on timeout)
    pub sender_address: String,
    /// Per-commitment point for this HTLC (33 bytes, for key derivation)
    pub per_commitment_point: Vec<u8>,
}

/// Response from creating an HTLC with transaction details
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CreateHtlcWithTxDetailsResponse {
    pub success: bool,
    /// The witness script for this HTLC (P2WSH)
    pub witness_script: Option<Vec<u8>>,
    pub error: Option<String>,
}

// =============================================================================
// HTLC Signing Requests/Responses
// =============================================================================

/// Request to sign an HTLC-Success transaction (receiver claims with preimage)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHtlcSuccessRequest {
    /// The payment hash identifying the HTLC
    pub payment_hash: Vec<u8>,
    /// The preimage (32 bytes) - proves receiver knows the secret
    pub preimage: Vec<u8>,
    /// Fee in satoshis for the HTLC-Success transaction
    pub fee_sat: u64,
}

/// Request to sign an HTLC-Timeout transaction (sender reclaims after expiry)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHtlcTimeoutRequest {
    /// The payment hash identifying the HTLC
    pub payment_hash: Vec<u8>,
    /// Fee in satoshis for the HTLC-Timeout transaction
    pub fee_sat: u64,
}

/// Response containing a signed HTLC transaction
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHtlcResponse {
    pub success: bool,
    /// The fully signed transaction (serialized, ready to broadcast)
    pub signed_tx: Option<Vec<u8>>,
    /// The transaction ID (txid)
    pub txid: Option<Vec<u8>>,
    pub error: Option<String>,
}

// =============================================================================
// Channel Secret Generation Types (Phase 3: Canister generates secrets)
// =============================================================================

/// Request to generate channel secrets on the canister.
///
/// The canister uses `raw_rand()` to generate a master seed, then derives
/// all 5 channel secrets via HMAC-SHA256. Secrets never leave the canister.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenerateChannelSecretsRequest {
    /// Unique channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
}

/// Response from generating channel secrets.
///
/// Contains only public keys — the underlying secrets are stored in canister
/// state and never exposed.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GenerateChannelSecretsResponse {
    pub success: bool,
    /// HTLC basepoint (33 bytes compressed)
    pub htlc_basepoint: Option<Vec<u8>>,
    /// Revocation basepoint (33 bytes compressed)
    pub revocation_basepoint: Option<Vec<u8>>,
    /// Delayed payment basepoint (33 bytes compressed)
    pub delayed_payment_basepoint: Option<Vec<u8>>,
    /// Payment point (33 bytes compressed)
    pub payment_point: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Request to get a per-commitment point for a specific commitment index.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetPerCommitmentPointRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Commitment number (0-indexed, counting from first commitment)
    pub idx: u64,
}

/// Response containing the per-commitment point.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetPerCommitmentPointResponse {
    pub success: bool,
    /// Per-commitment public key (33 bytes compressed)
    pub point: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Request to release (reveal) a per-commitment secret.
///
/// Called when the counterparty needs the secret for a revoked commitment.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ReleaseCommitmentSecretRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Commitment number to release the secret for
    pub idx: u64,
}

/// Response containing the released per-commitment secret.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct ReleaseCommitmentSecretResponse {
    pub success: bool,
    /// The 32-byte per-commitment secret
    pub secret: Option<Vec<u8>>,
    pub error: Option<String>,
}

// =============================================================================
// Commitment/Justice/HTLC Transaction Signing Types (Phase 3)
// =============================================================================

/// Request to sign a counterparty commitment transaction.
///
/// The canister computes all sighashes itself from the full transaction bytes.
/// Returns commitment signature (chainkey) + HTLC signatures (local ECDSA).
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignCounterpartyCommitmentRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Full serialized commitment transaction
    pub commitment_tx_bytes: Vec<u8>,
    /// Per-commitment point (33 bytes compressed)
    pub per_commitment_point: Vec<u8>,
    /// Serialized second-level HTLC transactions
    pub htlc_tx_bytes: Vec<Vec<u8>>,
    /// Amount for each HTLC sighash (in satoshis)
    pub htlc_amounts_sat: Vec<u64>,
    /// Witness scripts for each HTLC
    pub htlc_redeemscripts: Vec<Vec<u8>>,
    /// Channel capacity for funding sighash (in satoshis)
    pub funding_amount_sat: u64,
}

/// Response from signing a counterparty commitment.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignCounterpartyCommitmentResponse {
    pub success: bool,
    /// Commitment signature (64-byte compact ECDSA from chainkey)
    pub commitment_sig: Option<Vec<u8>>,
    /// HTLC signatures (64-byte compact ECDSA each, from local keys)
    pub htlc_sigs: Option<Vec<Vec<u8>>>,
    pub error: Option<String>,
}

/// Request to sign a holder commitment transaction.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHolderCommitmentRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Full serialized commitment transaction
    pub commitment_tx_bytes: Vec<u8>,
    /// Channel capacity for funding sighash (in satoshis)
    pub funding_amount_sat: u64,
}

/// Response from signing a holder commitment.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHolderCommitmentResponse {
    pub success: bool,
    /// Commitment signature (64-byte compact ECDSA from chainkey)
    pub commitment_sig: Option<Vec<u8>>,
    pub error: Option<String>,
}

/// Request to sign a closing transaction.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignClosingTxRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Full serialized closing transaction
    pub closing_tx_bytes: Vec<u8>,
    /// Channel capacity for funding sighash (in satoshis)
    pub funding_amount_sat: u64,
}

// SignClosingTxResponse reuses SignHolderCommitmentResponse

/// Request to sign a justice (penalty) transaction.
///
/// Used to punish a cheating counterparty who broadcasts a revoked commitment.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignJusticeTxRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Full serialized justice transaction
    pub justice_tx_bytes: Vec<u8>,
    /// Input index to sign
    pub input_index: u32,
    /// Amount of the input being spent (in satoshis)
    pub amount_sat: u64,
    /// The revealed per-commitment secret (32 bytes) from the cheating counterparty
    pub per_commitment_secret: Vec<u8>,
    /// Witness script for the input being spent
    pub witness_script: Vec<u8>,
}

/// Request to sign an HTLC transaction (holder or counterparty).
///
/// Used for signing second-level HTLC-Success and HTLC-Timeout transactions.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignHtlcTxRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Full serialized HTLC transaction
    pub htlc_tx_bytes: Vec<u8>,
    /// Input index to sign
    pub input_index: u32,
    /// Amount of the input being spent (in satoshis)
    pub amount_sat: u64,
    /// Per-commitment point (33 bytes compressed)
    pub per_commitment_point: Vec<u8>,
    /// Witness script for the HTLC input
    pub witness_script: Vec<u8>,
}

/// Request to register counterparty channel info for a channel.
///
/// Stores the counterparty's funding pubkey so the canister can reconstruct
/// the funding redeemscript for sighash computation. Also stores the
/// counterparty's payment basepoint and channel direction for BOLT-3
/// commitment number extraction (old-state attack prevention).
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterChannelInfoRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Counterparty's funding public key (33 bytes compressed)
    pub counterparty_funding_pubkey: Vec<u8>,
    /// Counterparty's payment basepoint (33 bytes compressed).
    /// Used with our payment basepoint to compute the BOLT-3 commitment
    /// number obscuring factor.
    pub counterparty_payment_basepoint: Vec<u8>,
    /// Whether we opened the channel (true) or the peer did (false).
    /// Determines the ordering of payment basepoints in the obscuring factor.
    pub is_outbound: bool,
}
