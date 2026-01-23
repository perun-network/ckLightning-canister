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
pub const DEVNET_CKBTC_LEDGER: &str = "u6s2n-gx777-77774-qaaba-cai";
pub const DEVNET_CKBTC_MINTER: &str = "be2us-64aaa-aaaaa-qaabq-cai";
pub const DEVNET_BASIC_BITCOIN: &str = "vpyes-67777-77774-qaaeq-cai";
pub const DEFAULT_CKBTC_FEE: u64 = 1000;

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
