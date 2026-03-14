use candid::{CandidType, Deserialize, Nat, Principal};

use super::constants::StableSwapConfig;

// =============================================================================
// Relay Registration Types
// =============================================================================

/// Registered relay information
///
/// The relay must register its Lightning node pubkey before it can submit
/// invoices for onramp requests. This prevents invoice substitution attacks
/// where a malicious relay could redirect payments to a different node.
#[derive(CandidType, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct RelayRegistration {
    /// The IC principal of the relay
    pub principal: Principal,
    /// The Lightning node pubkey (33 bytes compressed secp256k1)
    pub node_pubkey: Vec<u8>,
    /// When the relay was registered (nanoseconds)
    pub registered_at: u64,
    /// Whether the relay is currently active
    pub is_active: bool,
    /// HTTP base URL for webhook outcalls (e.g. "http://host:9740")
    pub relay_http_url: Option<String>,
    /// Auth token for webhook Bearer authentication
    pub relay_auth_token: Option<String>,
}

/// Request to register a relay
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RegisterRelayRequest {
    /// The Lightning node pubkey (33 bytes compressed secp256k1)
    pub node_pubkey: Vec<u8>,
    /// Optional HTTP base URL for webhook outcalls (e.g. "http://host:9740")
    pub relay_http_url: Option<String>,
    /// Optional auth token for webhook Bearer authentication
    pub relay_auth_token: Option<String>,
}

/// Response from registering a relay
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RegisterRelayResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Query response for relay info
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct GetRelayInfoResponse {
    pub registered: bool,
    pub principal: Option<Principal>,
    pub node_pubkey: Option<Vec<u8>>,
    pub is_active: Option<bool>,
    pub relay_http_url: Option<String>,
    pub has_auth_token: Option<bool>,
}

// =============================================================================
// Rate Limiting Types
// =============================================================================

/// Rate limit tracking for a principal
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RateLimitInfo {
    /// Number of requests in current window
    pub request_count: u32,
    /// Start of current time window (nanoseconds)
    pub window_start: u64,
}

impl RateLimitInfo {
    pub fn new(now: u64) -> Self {
        Self {
            request_count: 1,
            window_start: now,
        }
    }
}

/// Rate limit status response
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RateLimitStatus {
    /// Requests made in current window
    pub onramp_requests: u32,
    /// Requests made in current window
    pub offramp_requests: u32,
    /// Max allowed per window
    pub max_onramp_per_window: u32,
    /// Max allowed per window
    pub max_offramp_per_window: u32,
    /// Seconds until window resets
    pub window_resets_in_seconds: u64,
}

// =============================================================================
// StableSwap AMM Types
// =============================================================================

/// Request to update the StableSwap configuration (admin-only)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdateStableSwapConfigRequest {
    /// New amplification coefficient (None = keep current)
    pub amplification: Option<u64>,
    /// New fee in basis points (None = keep current)
    pub fee_bps: Option<u64>,
    /// New protocol fee share in basis points (None = keep current)
    pub protocol_fee_share_bps: Option<u64>,
    /// New max slippage in basis points (None = keep current). 0 = disabled.
    pub max_slippage_bps: Option<u64>,
    /// New imbalance fee in basis points (None = keep current). Must be >= fee_bps.
    pub imbalance_fee_bps: Option<u64>,
    /// New rebate in basis points (None = keep current). Max rebate at full rebalance. 0 = disabled.
    pub rebate_bps: Option<u64>,
    /// New max swap size as % of output pool in bps (None = keep current). 0 = disabled, 1000 = 10%.
    pub max_swap_pct_bps: Option<u64>,
}

/// Response from updating StableSwap configuration
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdateStableSwapConfigResponse {
    pub success: bool,
    pub config: StableSwapConfig,
    pub error: Option<String>,
}

/// Request for a swap quote (preview without executing)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SwapQuoteRequest {
    pub direction: super::constants::SwapDirection,
    pub amount_sats: u64,
}

/// Response with swap quote details
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SwapQuoteResponse {
    pub input_amount: u64,
    pub output_amount: u64,
    pub total_fee: u64,
    pub lp_fee: u64,
    pub protocol_fee: u64,
    pub price_impact_bps: u64,
    pub effective_fee_bps: u64,
    pub btc_pool_balance: u64,
    pub ckbtc_pool_balance: u64,
    pub error: Option<String>,
}

/// Response from withdrawing accumulated protocol fees
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct WithdrawProtocolFeesResponse {
    pub success: bool,
    pub btc_amount: u64,
    pub ckbtc_amount: u64,
    pub ckbtc_block_index: Option<Nat>,
    pub error: Option<String>,
}

/// Response from setting the ICP anti-DDoS fee
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SetIcpDdosFeeResponse {
    pub success: bool,
    pub fee_e8s: u64,
    pub error: Option<String>,
}

/// Response from redistributing protocol fees to LPs
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RedistributeFeesResponse {
    pub success: bool,
    pub amount_distributed: u64,
    pub num_recipients: u64,
    pub error: Option<String>,
}

/// Response from withdrawing accumulated ICP fees
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct WithdrawIcpFeesResponse {
    pub success: bool,
    pub amount_e8s: u64,
    pub block_index: Option<Nat>,
    pub error: Option<String>,
}

// =============================================================================
// State Pruning & Monitoring
// =============================================================================

/// Result of pruning old terminal-state entries from canister state.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PruneResult {
    pub swaps_pruned: u64,
    pub onramp_requests_pruned: u64,
    pub offramp_requests_pruned: u64,
    pub rate_limits_pruned: u64,
}

/// Statistics about canister state collections (for monitoring growth).
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct StateStats {
    pub swaps_count: u64,
    pub onramp_requests_count: u64,
    pub offramp_requests_count: u64,
    pub processed_utxos_count: u64,
    pub funded_channels_count: u64,
    pub onramp_rate_limits_count: u64,
    pub offramp_rate_limits_count: u64,
    pub channel_secrets_count: u64,
    pub htlc_tx_details_count: u64,
}
