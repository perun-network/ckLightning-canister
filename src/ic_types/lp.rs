use candid::{CandidType, Deserialize, Nat};
use icrc_ledger_types::icrc1::transfer::Memo;

use super::constants::Amount;
use super::primitives::*;

// =============================================================================
// Pool Asset & Funding Types
// =============================================================================

#[derive(Clone, Debug, Eq, Hash, PartialEq, Deserialize, CandidType)]
pub enum PoolAsset {
    CkBTC,
    BTC,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash, Debug)]
pub struct PoolFunding {
    pub pubkey_l1: Vec<u8>,
    /// The layer-1 identity to send the funds to.
    pub depositor: L1Account,
    pub timestamp: u64,
    pub asset: PoolAsset,
}

impl PoolFunding {
    pub fn get_depositor(&self) -> &L1Account {
        &self.depositor
    }

    pub fn get_asset(&self) -> &PoolAsset {
        &self.asset
    }

    pub fn get_pubkey(&self) -> &Vec<u8> {
        &self.pubkey_l1
    }

    pub fn new(pubkey_l1: Vec<u8>, depositor: L1Account, ts: u64, asset: PoolAsset) -> Self {
        PoolFunding {
            pubkey_l1,
            depositor,
            timestamp: ts,
            asset,
        }
    }

    pub fn memo(&self) -> Memo {
        let mut data = Vec::new();
        data.extend_from_slice(self.depositor.0.as_ref());
        data.extend_from_slice(&self.pubkey_l1);
        let h = Hash::digest(&data);
        let arr: [u8; 8] = [
            h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7],
        ];
        Memo::from(arr.to_vec())
    }
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
pub struct NotifyArgs {
    pub block_height: u64,
    pub amount: u64,
    pub funding: PoolFunding,
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

#[derive(Deserialize, CandidType, Clone)]
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

// =============================================================================
// Depositor Info
// =============================================================================

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
#[derive(Default)]
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
// Channel Funding Types
// =============================================================================

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
