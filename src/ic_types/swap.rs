use candid::{CandidType, Deserialize, Nat, Principal};

// =============================================================================
// Lightning Swap Types (Onramp: Lightning → ckBTC)
// =============================================================================

/// State of a Lightning → ckBTC swap
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum SwapState {
    /// Swap registered, waiting for Lightning payment
    Pending,
    /// LP balance deducted, ckBTC transfer in progress (prevents TOCTOU double-spend)
    InFlight,
    /// Lightning payment received, ckBTC transfer completed
    Completed { block_index: Nat },
    /// Swap expired (Lightning payment not received in time)
    Expired,
    /// Swap failed
    Failed { reason: String },
}

/// Request to register a new Lightning → ckBTC swap
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterSwapRequest {
    /// Payment hash from the Lightning invoice (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// IC Principal to receive ckBTC
    pub recipient: Principal,
    /// Expiry timestamp (Unix seconds)
    pub expiry_timestamp: u64,
}

/// Response from registering a swap
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterSwapResponse {
    /// Whether the swap was successfully registered
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to complete a swap after Lightning payment received
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CompleteSwapRequest {
    /// Payment hash that was paid (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Payment preimage as proof (32 bytes)
    pub preimage: Vec<u8>,
}

/// Response from completing a swap
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CompleteSwapResponse {
    /// Whether the ckBTC transfer was successful
    pub success: bool,
    /// Block index of the ckBTC transfer (if successful)
    pub block_index: Option<Nat>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Internal storage for swap information
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SwapInfo {
    /// Payment hash (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// IC Principal to receive ckBTC
    pub recipient: Principal,
    /// When the swap was registered (Unix nanoseconds)
    pub created_at: u64,
    /// Expiry timestamp (Unix seconds)
    pub expiry_timestamp: u64,
    /// Current state of the swap
    pub state: SwapState,
}

// =============================================================================
// Onramp Invoice Request Types (Canister-First Flow)
// =============================================================================

/// State of an onramp invoice request
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq)]
pub enum OnrampRequestState {
    /// Request created, waiting for relay to create invoice
    Pending,
    /// Invoice created by relay, ready for client to pay
    Ready,
    /// Invoice paid, swap completed
    Completed { block_index: Nat },
    /// Request expired
    Expired,
    /// Request failed
    Failed { reason: String },
}

/// Request to create an onramp invoice (client → canister)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OnrampInvoiceRequest {
    /// IC Principal to receive ckBTC
    pub recipient: Principal,
    /// Amount in satoshis
    pub amount_sats: u64,
}

/// Response from requesting an onramp invoice
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OnrampInvoiceResponse {
    /// Unique request ID (used to poll for invoice)
    pub request_id: String,
    /// Whether the request was accepted
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Pending invoice request (for relay to process)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PendingInvoiceRequest {
    /// Unique request ID
    pub request_id: String,
    /// IC Principal to receive ckBTC
    pub recipient: Principal,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// When the request was created (Unix nanoseconds)
    pub created_at: u64,
}

/// Request from relay to submit a created invoice
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SubmitInvoiceRequest {
    /// Request ID this invoice fulfills
    pub request_id: String,
    /// BOLT11 invoice string
    pub invoice: String,
    /// Payment hash from the invoice (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Expiry timestamp (Unix seconds)
    pub expiry_timestamp: u64,
}

/// Response from submitting an invoice
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SubmitInvoiceResponse {
    /// Whether the invoice was accepted
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Response when querying for an invoice by request ID
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetInvoiceResponse {
    /// Current state of the request
    pub state: OnrampRequestState,
    /// BOLT11 invoice (if ready)
    pub invoice: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Internal storage for onramp invoice requests
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OnrampRequestInfo {
    /// Unique request ID
    pub request_id: String,
    /// IC Principal to receive ckBTC
    pub recipient: Principal,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// When the request was created (Unix nanoseconds)
    pub created_at: u64,
    /// Current state
    pub state: OnrampRequestState,
    /// BOLT11 invoice (when ready)
    pub invoice: Option<String>,
    /// Payment hash (when invoice created)
    pub payment_hash: Option<Vec<u8>>,
    /// Expiry timestamp (Unix seconds, when invoice created)
    pub expiry_timestamp: Option<u64>,
    /// Principal who paid the ICP anti-DDoS fee (caller)
    pub icp_fee_payer: Option<Principal>,
    /// Block index of the ICP fee transfer
    pub icp_fee_block_index: Option<Nat>,
    /// Whether the ICP fee has been refunded (on success)
    pub icp_fee_refunded: bool,
}

// =============================================================================
// Offramp Types (ckBTC → Lightning)
// =============================================================================

/// State of an offramp request
#[derive(Clone, Debug, CandidType, Deserialize, PartialEq)]
pub enum OfframpRequestState {
    /// Request created, ckBTC taken into custody, waiting for relay to pay
    Pending,
    /// Relay is attempting to pay the invoice
    PaymentInProgress,
    /// Invoice paid successfully
    Completed { preimage: Vec<u8> },
    /// Payment failed, ckBTC refund pending (refund transfer not yet confirmed)
    FailedPendingRefund { reason: String },
    /// Payment failed, refund attempted but transfer failed (retryable)
    Failed { reason: String },
    /// ckBTC refunded to user
    Refunded { block_index: Nat },
    /// Request expired without completion, ckBTC refunded to user
    Expired { refund_block_index: Option<Nat> },
}

/// Request to offramp ckBTC to Lightning (user → canister)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OfframpRequest {
    /// BOLT11 invoice to pay
    pub invoice: String,
    /// Fallback BTC address if Lightning payment fails
    pub fallback_btc_address: Option<String>,
}

/// Response from requesting an offramp
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OfframpResponse {
    /// Unique request ID
    pub request_id: String,
    /// Whether the request was accepted and ckBTC taken into custody
    pub success: bool,
    /// Amount in satoshis (parsed from invoice)
    pub amount_sats: Option<u64>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Pending offramp request (for relay to poll)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PendingOfframpRequest {
    /// Unique request ID
    pub request_id: String,
    /// BOLT11 invoice to pay
    pub invoice: String,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Payment hash from the invoice (32 bytes)
    pub payment_hash: Vec<u8>,
    /// When the request was created (Unix nanoseconds)
    pub created_at: u64,
    /// Expiry timestamp of the invoice (Unix seconds)
    pub invoice_expiry: u64,
}

/// Request from relay to report successful payment
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CompleteOfframpRequest {
    /// Request ID
    pub request_id: String,
    /// Payment hash (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Payment preimage (32 bytes) - proves payment was made
    pub preimage: Vec<u8>,
}

/// Response from completing an offramp
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CompleteOfframpResponse {
    /// Whether the completion was recorded
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request from relay to report failed payment
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FailOfframpRequest {
    /// Request ID
    pub request_id: String,
    /// Payment hash (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Reason for failure
    pub reason: String,
}

/// Response from failing an offramp (triggers refund)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FailOfframpResponse {
    /// Whether the failure was recorded
    pub success: bool,
    /// Refund block index (if ckBTC refunded)
    pub refund_block_index: Option<Nat>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Response when querying offramp status
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetOfframpStatusResponse {
    /// Current state of the request
    pub state: OfframpRequestState,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Error message if any
    pub error: Option<String>,
}

/// Internal storage for offramp requests
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct OfframpRequestInfo {
    /// Unique request ID
    pub request_id: String,
    /// User who initiated the offramp
    pub user: Principal,
    /// BOLT11 invoice to pay
    pub invoice: String,
    /// Amount in satoshis
    pub amount_sats: u64,
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Payment hash from invoice (32 bytes)
    pub payment_hash: Vec<u8>,
    /// Invoice expiry timestamp (Unix seconds)
    pub invoice_expiry: u64,
    /// Fallback BTC address
    pub fallback_btc_address: Option<String>,
    /// When the request was created (Unix nanoseconds)
    pub created_at: u64,
    /// Current state
    pub state: OfframpRequestState,
    /// Preimage (when completed)
    pub preimage: Option<Vec<u8>>,
    /// Block index of the ICP fee transfer
    pub icp_fee_block_index: Option<Nat>,
    /// Whether the ICP fee has been refunded (on success)
    pub icp_fee_refunded: bool,
    /// ckBTC amount collected from user (StableSwap-computed, for LP crediting on completion)
    pub ckbtc_collected: u64,
}
