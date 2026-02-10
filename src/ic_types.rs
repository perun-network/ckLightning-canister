//  Copyright 2025 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
use crate::require;
use digest::{FixedOutputDirty, Update};
use ed25519_dalek::Sha512 as Hasher;
use icrc_ledger_types::icrc1::account::Subaccount;
use icrc_ledger_types::icrc1::transfer::Memo;
use k256::EncodedPoint;
use k256::PublicKey as SecpPublicKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use std::collections::HashMap;

pub const MAINNET_ICP_LEDGER: &str = "bkyz2-fmaaa-aaaaa-qaaaq-cai";
pub const DEVNET_ICP_LEDGER: &str = "ufxgi-4p777-77774-qaadq-cai";
pub const DEVNET_CKBTC_LEDGER: &str = "u6s2n-gx777-77774-qaaba-cai";
pub const DEVNET_CKBTC_MINTER: &str = "be2us-64aaa-aaaaa-qaabq-cai";
pub const DEVNET_BASIC_BITCOIN: &str = "vpyes-67777-77774-qaaeq-cai";
pub const DEFAULT_CKBTC_FEE: u64 = 1000;

// Anti-DDoS ICP fee constants
pub const ICP_DDOS_FEE_E8S: u64 = 100_000_000; // 1 ICP in e8s (default; configurable via admin endpoint)
pub const ICP_TRANSFER_FEE_E8S: u64 = 10_000;     // 0.0001 ICP in e8s

// Swap timeout constants (in nanoseconds)
pub const ONRAMP_TIMEOUT_NS: u64 = 30 * 60 * 1_000_000_000;  // 30 minutes
pub const OFFRAMP_TIMEOUT_NS: u64 = 10 * 60 * 1_000_000_000; // 10 minutes

// Rate limiting constants
pub const RATE_LIMIT_WINDOW_NS: u64 = 60 * 60 * 1_000_000_000; // 1 hour window
pub const MAX_ONRAMP_REQUESTS_PER_WINDOW: u32 = 10;  // 10 onramp requests per hour
pub const MAX_OFFRAMP_REQUESTS_PER_WINDOW: u32 = 10; // 10 offramp requests per hour

// Re-export StableSwap types from the math module
pub use crate::stableswap::{StableSwapConfig, SwapDirection};

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
}

/// Request to register a relay
#[derive(CandidType, Deserialize, Clone, Debug)]
pub struct RegisterRelayRequest {
    /// The Lightning node pubkey (33 bytes compressed secp256k1)
    pub node_pubkey: Vec<u8>,
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

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct L2Account(pub SecpPublicKey);
use candid::{CandidType, Principal};
pub use candid::{
    Deserialize, Int, Nat,
    types::{Serializer, Type},
    types::{TypeInner, TypeInner::Nat8},
};
use core::cmp::*;
use core::convert::*;

use serde::de::{Deserializer, Error as _};
use serde_bytes::ByteBuf;

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct SetBtcAddressResponse {
    pub address: String,
    pub msg: SetBtcAddressMsg,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct GetBtcBalancesResponse {
    pub balances: HashMap<Principal, Option<u64>>, // None if address missing
    pub msg: SetBtcAddressMsg,                     // Overall status, e.g. BtcAddressNotSet if none
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct SendBtcTxResponse {
    pub balances: HashMap<BtcAddressType, Option<u64>>, // None if address missing
    pub msg: SetBtcAddressMsg, // Overall status, e.g. BtcAddressNotSet if none
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct QueryBtcAddressResponse {
    pub msg: SetBtcAddressMsg,
    pub addresses: Option<HashMap<BtcAddressType, String>>,
}

#[derive(CandidType, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BtcPurpose {
    LiquidityDepositor(Principal), // multiple: ["btc", "liq_deposit", principal]
    LnInvoiceDeposit,              // SINGLE: ["btc", "ln_invoice"]
    LiquidityPoolShared,           // SINGLE: ["btc", "lp_shared"] - shared LP BTC address
}

#[derive(CandidType, Deserialize, Clone)]
pub struct LnInvoiceRequest {
    pub caller_principal: Principal, // for derivation
    pub btc_address: String,         // deposit address verification
    pub amount_msat: u64,            // invoice amount
}

impl BtcPurpose {
    pub fn derivation_path(&self) -> Vec<Vec<u8>> {
        match self {
            BtcPurpose::LiquidityDepositor(principal) => {
                vec![
                    b"btc".to_vec(),
                    b"liq_deposit".to_vec(),
                    principal.as_slice().to_vec(),
                ]
            }
            BtcPurpose::LnInvoiceDeposit => {
                vec![b"btc".to_vec(), b"ln_invoice".to_vec()]
            }
            BtcPurpose::LiquidityPoolShared => {
                vec![b"btc".to_vec(), b"lp_shared".to_vec()]
            }
        }
    }
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct GetBtcBalanceArgs {
    pub address: String, // specify which address type to get balance for
    pub confirmations: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]

pub enum SetBtcAddressMsg {
    BtcAddressNotSet,
    BtcAddressAlreadySetSingle(BtcAddressType),
    BtcAddressSetNowSingle(BtcAddressType),
    BtcAddressSetFailedSingle(BtcAddressType),
    BtcAddressesAvailable, // New variant to indicate multiple addresses available
}

#[derive(PartialEq, Eq, Clone, Debug, CandidType, Deserialize)]
pub struct SetLiquidityBtcAddressResponse {
    pub address: String,
    pub already_existed: bool,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct CandidInvoice {
    pub invoice: String, // bech32 BOLT11 string
    pub amount_msat: Option<Nat>,
    pub payment_hash: Vec<u8>,   // 32 bytes
    pub payment_secret: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    pub expiry_secs: Option<u64>,
    pub currency: String,
    pub channel_id: Vec<u8>, // 32 bytes from ChannelId
}

#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignedCandidInvoice {
    pub invoice: String, // Signed BOLT11 string
    pub amount_msat: Option<Nat>,
    pub payment_hash: Vec<u8>,   // 32 bytes
    pub payment_secret: Vec<u8>, // 32 bytes
    pub timestamp: u64,
    pub expiry_secs: Option<u64>,
    pub currency: String,
    pub channel_id: Vec<u8>, // 32 bytes
    pub signature: Vec<u8>,  // ✅ NEW: Invoice signature bytes
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]

pub struct SendBtcTxArgs {
    pub recipient: String,
    pub from_address_type: BtcAddressType,
    pub amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub enum SendBtcTxMsg {
    Success(String),
    Fail,
}

// Type definitions start here.

#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Default, Clone)]
/// A hash as used by the signature scheme.
pub struct Hash(pub digest::Output<Hasher>);

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub enum Funding {
    Channel(ChannelFunding),
    Pool(PoolFunding),
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
pub struct FundingLPQuery {
    pub address: L1Account,
    pub pubkey_l1: Vec<u8>,
    pub asset: PoolAsset,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
pub struct FundingLPQueryArgs {
    pub funding_query: FundingLPQuery,
    pub funding_query_sig: Vec<u8>,
}
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]

pub struct SendBtcArgs {
    pub to_address: String,
    pub amount_sat: Nat,
}
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]

pub struct SendFromP2pkhAddressArgs {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, CandidType)]
pub enum PoolAsset {
    CkBTC,
    BTC,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct ChannelFunding {
    /// The channel's unique identifier.
    pub channel: ChannelId,
    /// The funds' owner's layer-2 identity within the channel.
    pub participant: L2Account,
    // pub amount: Amount,
    // pub receiver: L1Account,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct NotifyArgs {
    pub block_height: u64,
    pub amount: u64,
    pub funding: Funding,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct PoolFunding {
    pub pubkey_l1: Vec<u8>,
    /// The layer-1 identity to send the funds to.
    pub depositor: L1Account,
    pub timestamp: u64,
    pub asset: PoolAsset,
}

impl Funding {
    pub fn get_depositor(&self) -> Option<&L1Account> {
        match self {
            Funding::Pool(p) => Some(&p.depositor),
            _ => None,
        }
    }

    pub fn get_asset(&self) -> Option<&PoolAsset> {
        match self {
            Funding::Pool(p) => Some(&p.asset),
            _ => None,
        }
    }

    pub fn get_pubkey(&self) -> Option<&Vec<u8>> {
        match self {
            Funding::Pool(p) => Some(&p.pubkey_l1),
            _ => None,
        }
    }
}
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct HoldingsResponse {
    pub ckbtc_amount: Amount,
    pub btc_amount: Amount,
}

// =============================================================================
// Simplified Liquidity Pool Types
// =============================================================================

/// Response for LP balance queries
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBalanceResponse {
    pub ckbtc_balance: Amount,
    pub btc_balance: Amount,
}

/// Response for LP deposit operations
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpDepositResponse {
    pub success: bool,
    pub new_balance: Amount,
    pub error: Option<String>,
}

/// Response for LP withdraw operations
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpWithdrawResponse {
    pub success: bool,
    pub amount_withdrawn: Amount,
    pub new_balance: Amount,
    pub block_index: Option<Nat>,
    pub error: Option<String>,
}

/// Response for total LP balance query
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct TotalLpBalanceResponse {
    pub total_ckbtc: Amount,
    pub total_btc: Amount,
    pub num_depositors: u64,
}

// =============================================================================
// BTC Liquidity Pool Types (shared LP address - Option C)
// =============================================================================

/// Response for getting the shared LP BTC address
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBtcAddressResponse {
    pub address: String,
}

/// Request to deposit BTC to LP (after sending to shared LP address)
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBtcDepositRequest {
    /// The txid of the deposit transaction (for tracking)
    pub txid: Option<Vec<u8>>,
    /// Amount deposited in satoshis
    pub amount_sat: u64,
}

/// Response for BTC LP deposit
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBtcDepositResponse {
    pub success: bool,
    pub credited_amount: Amount,
    pub new_btc_balance: Amount,
    pub error: Option<String>,
}

/// Request to withdraw BTC from LP
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBtcWithdrawRequest {
    /// Amount to withdraw in satoshis
    pub amount_sat: u64,
    /// Destination BTC address
    pub destination_address: String,
}

/// Response for BTC LP withdrawal
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct LpBtcWithdrawResponse {
    pub success: bool,
    pub amount_withdrawn: Amount,
    pub new_btc_balance: Amount,
    pub txid: Option<String>,
    pub error: Option<String>,
}

// =============================================================================
// User BTC Operations (from depositor address)
// =============================================================================

/// Request to send BTC from the caller's depositor address
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct SendFromDepositorRequest {
    /// Amount to send in satoshis
    pub amount_sat: u64,
    /// Destination BTC address
    pub destination_address: String,
}

/// Response for sending BTC from depositor address
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct SendFromDepositorResponse {
    pub success: bool,
    pub txid: Option<String>,
    pub error: Option<String>,
}

/// Response for getting depositor BTC balance
#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct DepositorBtcBalanceResponse {
    pub address: String,
    pub balance_sat: u64,
    pub error: Option<String>,
}

/// Request to fund a Lightning channel from LP BTC
/// The canister will build and sign a transaction but NOT broadcast it
/// The relay is responsible for passing it to LDK which handles broadcasting
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FundChannelRequest {
    /// Amount to fund in satoshis
    pub amount_sat: u64,
    /// The funding output address (2-of-2 multisig P2WSH address)
    pub funding_address: String,
}

/// Response for channel funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct FundChannelResponse {
    pub success: bool,
    /// The signed funding transaction bytes (ready for broadcast)
    pub signed_tx: Option<Vec<u8>>,
    /// Transaction ID (for tracking)
    pub txid: Option<String>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Pending BTC deposit info (stored in canister state)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct PendingBtcDeposit {
    /// Principal who initiated the deposit claim
    pub depositor: Principal,
    /// Transaction ID
    pub txid: Vec<u8>,
    /// Output index
    pub vout: u32,
    /// Amount in satoshis
    pub amount_sat: u64,
    /// When the deposit was detected
    pub detected_at: u64,
    /// Number of confirmations when last checked
    pub confirmations: u32,
    /// Whether the deposit has been credited
    pub credited: bool,
}

// =============================================================================

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]

pub struct DepositorInfo {
    pub pubkey: Vec<u8>,
    pub ckbtc_amount: Amount,
    pub btc_amount: Amount,
}
impl DepositorInfo {
    pub fn new(pubkey: Vec<u8>) -> Self {
        Self {
            pubkey,
            ckbtc_amount: Amount::default(),
            btc_amount: Amount::default(),
        }
    }

    /// Deposit amounts to the appropriate asset balance.
    pub fn deposit(&mut self, asset: PoolAsset, amount: Amount) {
        match asset {
            PoolAsset::CkBTC => self.ckbtc_amount += amount,
            PoolAsset::BTC => self.btc_amount += amount,
        }
    }

    pub fn get_ckbtc_amount(&self) -> Amount {
        self.ckbtc_amount.clone()
    }

    pub fn get_btc_amount(&self) -> Amount {
        self.btc_amount.clone()
    }

    pub fn total(&self) -> Amount {
        self.ckbtc_amount.clone() + self.btc_amount.clone()
    }
}
impl Default for DepositorInfo {
    fn default() -> Self {
        Self {
            pubkey: Vec::new(),
            ckbtc_amount: Amount::default(),
            btc_amount: Amount::default(),
        }
    }
}

/// An amount of a currency.
pub type Amount = Nat;

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

/// Request to register channel secrets (called by relay when channel opens)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterChannelSecretsRequest {
    pub secrets: ChannelSecrets,
}

/// Response from registering channel secrets
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterChannelSecretsResponse {
    pub success: bool,
    /// Public keys derived from the secrets (for verification)
    pub htlc_basepoint: Option<Vec<u8>>,
    pub revocation_basepoint: Option<Vec<u8>>,
    pub delayed_payment_basepoint: Option<Vec<u8>>,
    pub payment_point: Option<Vec<u8>>,
    pub error: Option<String>,
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

/// Duration in nanoseconds (same as ICP timestamps).
pub type Duration = u64;
/// Timestamp in nanoseconds (same as ICP timestamps).
pub type Timestamp = u64;
/// Unique channel identifier.
#[derive(PartialEq, Eq, Ord, PartialOrd, Hash, Debug)]
pub struct ChannelId(pub [u8; 32]);

impl Clone for ChannelId {
    fn clone(&self) -> Self {
        ChannelId(self.0.clone())
    }
}

impl Default for ChannelId {
    fn default() -> Self {
        ChannelId([0; 32])
    }
}

#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Clone, Deserialize, CandidType, Debug)]
pub struct L1Account(pub Principal);

/// A channel's unique nonce.
#[derive(PartialEq, Eq, Ord, PartialOrd)]

pub struct Nonce(pub [u8; 32]);

/// Channel state version identifier.
pub type Version = u64;

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

#[derive(Deserialize, CandidType, Default, Clone)]
pub struct LiquidityPoolState {
    pub total_ckbtc: Amount,
    pub locked_ckbtc: Amount,
    pub total_btc: Amount,
    pub locked_btc: Amount,
}
#[derive(Deserialize, CandidType, Default, Clone)]
pub enum WithdrawalState {
    #[default]
    Idle,
    AwaitingConfirmations {
        txid: String,
        confirmations: u64,
    },
}
#[derive(Deserialize, CandidType, Default, Clone)]
pub enum DepositingState {
    #[default]
    Idle,
    AwaitingConfirmations {
        txid: String,
        confirmations: u64,
    },
}

#[derive(Deserialize, CandidType, Default, Clone)]
pub struct CklChannelState {
    pub depositing: DepositingState,
    pub total_btc: Amount,
}
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
    // pub l1_accounts: Vec<L1Account>,
    pub finalized: bool,
    // shows the phase the channel is in
}

impl State {
    pub fn get_channelid(&self) -> ChannelId {
        self.channel.clone()
    }

    pub fn get_action(&self) -> CklChannelAction {
        self.action.clone()
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

#[derive(CandidType)]
pub struct ckAccount {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}

#[derive(Deserialize, CandidType, Clone)]
// / Contains the payload of a request to withdraw a participant's funds from a
// / registered channel. Does not contain the authorization signature.
pub struct WithdrawalReq {
    /// The funds to be withdrawn.
    pub channel: ChannelId,
    pub participant: L2Account,
    pub amount: Nat,
    /// The layer-1 identity to send the funds to.
    pub receiver: Principal,
}

#[derive(Deserialize, CandidType, Clone)]
// / Contains the payload of a request to withdraw a participant's funds from a
// / registered channel. Does not contain the authorization signature.
pub struct PoolWithdrawal {
    /// The funds to be withdrawn.
    pub asset: PoolAsset,
    pub pubkey_l1: Vec<u8>,
    pub depositor: L1Account,
    pub amount: Nat,
}

#[derive(Deserialize, CandidType, Clone)]
pub struct WithdrawalLPArgs {
    pub pool_withdrawal: PoolWithdrawal,
    pub signature: Vec<u8>,
}

#[derive(Deserialize, CandidType, Clone)]
pub struct FundingLPArgs {
    pub pool_funding: PoolFunding,
    pub signature: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]

pub enum BtcAddressType {
    P2WPKH, //Native SegWit (Pay-to-Witness-PubKey-Hash). This address uses a compressed ECDSA public key and is encoded in Bech32 (BIP-173)
    P2PKH,  //(Pay-to-PubKey-Hash). This address is encoded in the legacy Base58 format.
    P2TR, //Pay-to-Taproot. This address does not commit to a script path (it commits to an unspendable path per BIP-341)
}

// =============================================================================
// Lightning Swap Types
// =============================================================================

/// State of a Lightning → ckBTC swap
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub enum SwapState {
    /// Swap registered, waiting for Lightning payment
    Pending,
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
    /// Payment failed, refund initiated
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
}

// =============================================================================
// Lightning Channel Funding Verification Types
// =============================================================================

/// Bitcoin transaction outpoint (txid + output index)
#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct BtcOutpoint {
    /// Transaction ID (32 bytes, little-endian)
    pub txid: Vec<u8>,
    /// Output index in the transaction
    pub vout: u32,
}

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

// =============================================================================
// LP Liquidity Types (Canister-Controlled BTC for Lightning)
// =============================================================================

/// A UTXO available for channel funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LpBtcUtxo {
    /// Transaction ID (32 bytes)
    pub txid: Vec<u8>,
    /// Output index
    pub vout: u32,
    /// Value in satoshis
    pub value_sats: u64,
    /// Block height when confirmed (0 if unconfirmed)
    pub height: u32,
}

/// Request to get available UTXOs for channel funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetFundingUtxosRequest {
    /// Minimum amount needed in satoshis
    pub min_amount_sats: u64,
}

/// Response with available UTXOs for channel funding
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct GetFundingUtxosResponse {
    /// Available UTXOs
    pub utxos: Vec<LpBtcUtxo>,
    /// Total value available
    pub total_sats: u64,
    /// The LP's BTC address (for change outputs)
    pub lp_address: Option<String>,
}

/// Request to sign a channel funding transaction
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignFundingTxRequest {
    /// The unsigned transaction (serialized)
    pub unsigned_tx: Vec<u8>,
    /// UTXOs being spent (for signing context)
    pub input_utxos: Vec<LpBtcUtxo>,
    /// Channel ID being funded
    pub channel_id: Vec<u8>,
    /// Expected channel capacity
    pub capacity_sats: u64,
}

/// Response from signing a funding transaction
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct SignFundingTxResponse {
    /// Whether signing succeeded
    pub success: bool,
    /// The signed transaction (serialized)
    pub signed_tx: Option<Vec<u8>>,
    /// Error message if failed
    pub error: Option<String>,
}

/// Request to update channel balance (from relay)
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdateChannelBalanceRequest {
    /// Channel ID
    pub channel_id: Vec<u8>,
    /// Our (canister's) balance in satoshis
    pub our_balance_sats: u64,
    /// Their (counterparty's) balance in satoshis
    pub their_balance_sats: u64,
}

/// Response from updating channel balance
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct UpdateChannelBalanceResponse {
    pub success: bool,
    pub error: Option<String>,
}

/// Overall LP liquidity status
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LpLiquidityStatus {
    // ckBTC Pool (for onramp payouts)
    /// Total ckBTC in the LP pool
    pub ckbtc_pool_sats: u64,

    // BTC Pool (for Lightning channel funding)
    /// Total on-chain BTC in canister-controlled UTXOs
    pub btc_onchain_sats: u64,
    /// Number of unspent UTXOs available
    pub btc_utxo_count: u32,

    // Lightning Channel Liquidity
    /// Total capacity across all channels
    pub channel_total_capacity_sats: u64,
    /// Our (outbound) balance - available for offramp payments
    pub channel_outbound_sats: u64,
    /// Their (inbound) balance - available for onramp receipts
    pub channel_inbound_sats: u64,
    /// Number of active channels
    pub channel_count: u32,

    // Tracking
    /// Total BTC deposited by LP providers (lifetime)
    pub total_btc_deposited: u64,
    /// Total BTC used for channel funding (lifetime)
    pub total_btc_in_channels: u64,
}

/// Enhanced channel info with balance tracking
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct LnChannelBalance {
    /// Channel ID
    pub channel_id: Vec<u8>,
    /// Channel capacity
    pub capacity_sats: u64,
    /// Our balance (outbound capacity)
    pub our_balance_sats: u64,
    /// Their balance (inbound capacity)
    pub their_balance_sats: u64,
    /// Is channel active/usable
    pub is_active: bool,
    /// Last balance update timestamp
    pub last_updated: u64,
}

#[derive(Deserialize, CandidType, Clone)]
pub struct SetBtcAddressArgs {
    pub principal: Option<Principal>,
    pub subaccount: Option<Subaccount>,
    pub address_type: BtcAddressType,
}
#[derive(Deserialize, CandidType, Clone)]

pub struct GetBtcAddressArgs {
    pub principal: Option<Principal>,
    pub subaccount: Option<Subaccount>,
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        require!(
            bytes.len() == 32,
            D::Error::invalid_length(bytes.len(), &"32-byte ChannelId")
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(ChannelId(arr))
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        require!(
            bytes.len() == 32,
            D::Error::invalid_length(bytes.len(), &"32-byte Nonce")
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Nonce(arr))
    }
}

impl CandidType for Hash {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&*self.0)
    }
}

impl std::fmt::Display for Hash {
    /// Formats the first 4 byte of a hash as lower case hex with 0x prefix.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let data = &self.0[..4];
        write!(f, "0x{}…", hex::encode(data))
    }
}

impl std::hash::Hash for L2Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_point: EncodedPoint = self.0.to_encoded_point(false); // false for uncompressed
        encoded_point.as_bytes().hash(state);
    }
}
impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl Hash {
    pub fn digest(msg: &[u8]) -> Self {
        let mut h = Hasher::default();
        h.update(msg);
        let mut out: Hash = Hash::default();
        h.finalize_into_dirty(&mut out.0);
        out
    }
}

impl<'de> Deserialize<'de> for L2Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = ByteBuf::deserialize(deserializer)?;
        let pk = SecpPublicKey::from_sec1_bytes(bytes.as_slice()).map_err(|_| {
            D::Error::invalid_length(bytes.len(), &"valid secp256k1 public key bytes")
        })?;
        Ok(L2Account(pk))
    }
}

impl CandidType for L2Account {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> core::result::Result<(), S::Error>
    where
        S: Serializer,
    {
        let encoded = self.0.to_encoded_point(false); // false for uncompressed
        serializer.serialize_blob(encoded.as_bytes())
    }
}

impl CandidType for ChannelId {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> core::result::Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&self.0)
    }
}

impl CandidType for Nonce {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> core::result::Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&self.0)
    }
}

impl Default for L2Account {
    fn default() -> Self {
        // 33-byte compressed public key of all zeros
        let zero_pk_bytes = [0u8; 33];
        let zero_pk = SecpPublicKey::from_sec1_bytes(&zero_pk_bytes)
            .expect("Hardcoded valid zero public key");
        L2Account(zero_pk)
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce([0; 32])
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        Nonce(self.0.clone())
    }
}

impl State {
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

impl Params {
    pub fn id(&self) -> ChannelId {
        let mut params_bytes = Vec::new();
        params_bytes.extend_from_slice(&self.nonce.0);

        for participant in &self.participants {
            // Serialize using to_encoded_point and get bytes
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

// RegisteredState

impl RegisteredState {
    pub fn settled(&self, now: Timestamp) -> bool {
        self.state.finalized || now >= self.timeout
    }
}

// Funding

impl Funding {
    pub fn new_channel(channel: ChannelId, participant: L2Account) -> Self {
        Funding::Channel(ChannelFunding {
            // amount,
            channel,
            participant,
        })
    }

    pub fn new_pool(pubkey_l1: Vec<u8>, depositor: L1Account, ts: u64, asset: PoolAsset) -> Self {
        Funding::Pool(PoolFunding {
            pubkey_l1,
            depositor,
            timestamp: ts,
            asset,
        })
    }

    pub fn memo(&self) -> Memo {
        match self {
            Funding::Channel(c) => {
                let mut data = Vec::new();
                data.extend_from_slice(&c.channel.0);
                data.extend_from_slice(c.participant.0.to_encoded_point(false).as_bytes());
                let h = Hash::digest(&data);
                let arr: [u8; 8] = [
                    h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7],
                ];
                Memo::from(arr.to_vec())
            }
            Funding::Pool(p) => {
                let mut data = Vec::new();
                // For PoolFunding, combine depositor and participant info.
                data.extend_from_slice(p.depositor.0.as_ref());
                // data.extend_from_slice(p.pubkey_l1.0.to_encoded_point(false).as_bytes());
                data.extend_from_slice(&p.pubkey_l1);
                let h = Hash::digest(&data);
                let arr: [u8; 8] = [
                    h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7],
                ];
                Memo::from(arr.to_vec())
            }
        }
    }
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
    pub direction: SwapDirection,
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
/// the funding redeemscript for sighash computation.
#[derive(Clone, Debug, CandidType, Deserialize)]
pub struct RegisterChannelInfoRequest {
    /// Channel identifier (32 bytes)
    pub channel_keys_id: Vec<u8>,
    /// Counterparty's funding public key (33 bytes compressed)
    pub counterparty_funding_pubkey: Vec<u8>,
}
