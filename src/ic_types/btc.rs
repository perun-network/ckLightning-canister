use candid::{CandidType, Deserialize, Nat, Principal};
use icrc_ledger_types::icrc1::account::Subaccount;
use std::collections::HashMap;


// =============================================================================
// BTC Address & Purpose Types
// =============================================================================

#[derive(CandidType, Deserialize, Clone, PartialEq, Eq, Hash, Debug)]
pub enum BtcPurpose {
    LiquidityDepositor(Principal), // User's personal BTC address: ["btc", "liq_deposit", principal]
    LiquidityPoolUser(Principal),  // Per-user LP deposit address: ["btc", "lp_user", principal]
    LnInvoiceDeposit,              // SINGLE: ["btc", "ln_invoice"]
    LiquidityPoolShared,           // SINGLE: ["btc", "lp_shared"] - internal change address
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
            BtcPurpose::LiquidityPoolUser(principal) => {
                vec![
                    b"btc".to_vec(),
                    b"lp_user".to_vec(),
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub enum BtcAddressType {
    P2WPKH, //Native SegWit (Pay-to-Witness-PubKey-Hash). This address uses a compressed ECDSA public key and is encoded in Bech32 (BIP-173)
    P2PKH,  //(Pay-to-PubKey-Hash). This address is encoded in the legacy Base58 format.
    P2TR, //Pay-to-Taproot. This address does not commit to a script path (it commits to an unspendable path per BIP-341)
}

// =============================================================================
// BTC Address Request/Response Types
// =============================================================================

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct SetBtcAddressResponse {
    pub address: String,
    pub msg: SetBtcAddressMsg,
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

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct GetBtcBalancesResponse {
    pub balances: HashMap<Principal, Option<u64>>, // None if address missing
    pub msg: SetBtcAddressMsg,                     // Overall status, e.g. BtcAddressNotSet if none
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct GetBtcBalanceArgs {
    pub address: String, // specify which address type to get balance for
    pub confirmations: Option<u64>,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct QueryBtcAddressResponse {
    pub msg: SetBtcAddressMsg,
    pub addresses: Option<HashMap<BtcAddressType, String>>,
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

// =============================================================================
// BTC Send/Transaction Types
// =============================================================================

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Debug)]
pub struct SendBtcTxResponse {
    pub balances: HashMap<BtcAddressType, Option<u64>>, // None if address missing
    pub msg: SetBtcAddressMsg, // Overall status, e.g. BtcAddressNotSet if none
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

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
pub struct SendFromP2pkhAddressArgs {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

/// Bitcoin transaction outpoint (txid + output index)
#[derive(Clone, Debug, PartialEq, Eq, Hash, CandidType, Deserialize)]
pub struct BtcOutpoint {
    /// Transaction ID (32 bytes, little-endian)
    pub txid: Vec<u8>,
    /// Output index in the transaction
    pub vout: u32,
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

// =============================================================================
// Invoice Types
// =============================================================================

#[derive(CandidType, Deserialize, Clone)]
pub struct LnInvoiceRequest {
    pub caller_principal: Principal, // for derivation
    pub btc_address: String,         // deposit address verification
    pub amount_msat: u64,            // invoice amount
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
    pub signature: Vec<u8>,  // Invoice signature bytes
}
