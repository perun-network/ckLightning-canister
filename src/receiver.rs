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
use crate::ic_types::{Amount, CKBTC_LEDGER_PRINCIPAL, Funding, ICP_LEDGER_PRINCIPAL};
use async_trait::async_trait;
pub use candid::{
    CandidType, Deserialize, Int, Nat, Principal,
    types::{Serializer, Type},
};
use ic_cdk::call::Call;
use ic_ledger_types::BlockIndex;
use ic_ledger_types::{AccountIdentifier, DEFAULT_SUBACCOUNT};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Transaction as ICRCTransaction;
use num_traits::cast::ToPrimitive;

use icrc_ledger_types;
use icrc_ledger_types::icrc3::blocks::{BlockWithId, GetBlocksRequest, GetBlocksResult};
use std::collections::{BTreeMap, BTreeSet};
pub type PerunMemo = u64;
pub type BlockHeight = u64;
/// ICP token handling errors.
#[derive(PartialEq, Eq, CandidType, Deserialize, Debug)]
pub enum ICPReceiverError {
    TransactionType,
    TxNotFound,
    TxMapNotFound,
    TxFromNotFound,
    TxToNotFound,
    TxAmountNotFound,
    Recipient,
    DuplicateTransaction,
    FailedToQuery,
}

impl std::fmt::Display for ICPReceiverError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

/// ICP transaction receiver for receiving and tracking payments for separate purposes.
pub struct Receiver<Q: TXQuerier> {
    tx_querier: Q,
    my_account: AccountIdentifier,
    known_txs: BTreeSet<BlockHeight>,
    unspent: BTreeMap<Memo, Amount>,
}

fn extract_blob_bytes(map: &BTreeMap<String, ICRC3Value>, key: &str) -> Option<Vec<u8>> {
    map.get(key).and_then(|v| match v {
        ICRC3Value::Blob(blob) => Some(blob.clone().into_vec()),
        _ => None,
    })
}

fn extract_nat_u64(map: &BTreeMap<String, ICRC3Value>, key: &str) -> Option<u64> {
    map.get(key).and_then(|v| match v {
        ICRC3Value::Nat(nat) => u64::try_from(nat.0.clone()).ok(),
        _ => None,
    })
}

fn extract_array_blob_first(map: &BTreeMap<String, ICRC3Value>, key: &str) -> Option<Vec<u8>> {
    map.get(key).and_then(|v| match v {
        ICRC3Value::Array(arr) => arr.get(0).and_then(|icv| match icv {
            ICRC3Value::Blob(blob) => Some(blob.clone().into_vec()),
            _ => None,
        }),
        _ => None,
    })
}

pub fn icrc3value_map_to_transaction(
    tx_map: &BTreeMap<String, ICRC3Value>,
    ts: Option<u64>,
) -> Result<TransactionICRCNotification, ICPReceiverError> {
    // Extract 'from' bytes and convert using from_slice
    let from_bytes =
        extract_array_blob_first(tx_map, "from").ok_or(ICPReceiverError::TxFromNotFound)?;

    let from = Principal::from_slice(from_bytes.as_slice());

    let acct_id = AccountIdentifier::new(&from, &DEFAULT_SUBACCOUNT);
    // Extract 'to' bytes and convert using from_slice

    let to_bytes = extract_array_blob_first(tx_map, "to").ok_or(ICPReceiverError::TxToNotFound)?;
    let to = Principal::from_slice(to_bytes.as_slice());

    let to_acct_id = AccountIdentifier::new(&to, &DEFAULT_SUBACCOUNT);

    // Extract amount as u64
    let amount = extract_nat_u64(tx_map, "amt").ok_or(ICPReceiverError::TxAmountNotFound)?;

    // Extract memo blob or fallback to empty
    let memo =
        extract_blob_bytes(tx_map, "memo").map_or_else(|| Memo::from(vec![]), |b| Memo::from(b));

    Ok(TransactionICRCNotification {
        to: to_acct_id,
        from: acct_id,
        amount,
        memo,
        timestamp: ts,
    })
}

/// ICP transaction querier.
#[async_trait]
pub trait TXQuerier {
    async fn query_icrc_tx(
        &self,
        block_height: BlockHeight,
        amount: u64,
    ) -> Result<TransactionICRCNotification, ICPReceiverError>;
}
//     }
// }

/// Real ICP transaction querier using inter-canister calls to the ICP ledger.
#[allow(dead_code)]
pub struct CanisterTXQuerier {
    ledger: Principal,
}

#[async_trait]
impl TXQuerier for CanisterTXQuerier {
    async fn query_icrc_tx(
        &self,
        block_height: BlockHeight,
        _amount: u64,
    ) -> Result<TransactionICRCNotification, ICPReceiverError> {
        if let Some(block_with_id) = self.get_blocks_from_ic_ledger(block_height).await {
            match &block_with_id.block {
                ICRC3Value::Map(block_map) => {
                    // Extract the timestamp at the block level here:
                    let timestamp_opt = match block_map.get("ts") {
                        Some(ICRC3Value::Nat(nat)) => Some(nat.0.to_u64().unwrap_or_default()), // safely convert Nat to u64
                        _ => None,
                    };

                    match block_map.get("tx") {
                        Some(ICRC3Value::Map(tx_map)) => {
                            // Pass timestamp as Option<u64> to your transaction function
                            icrc3value_map_to_transaction(tx_map, timestamp_opt)
                        }
                        _ => Err(ICPReceiverError::TxMapNotFound),
                    }
                }
                _ => Err(ICPReceiverError::TxNotFound),
            }
        } else {
            Err(ICPReceiverError::FailedToQuery)
        }
    }
}

impl CanisterTXQuerier {
    pub fn new(ledger: Principal) -> Self {
        Self { ledger: ledger }
    }

    /// Constructs a new canister TX querier targeting the mainnet ICP ledger canister.
    pub fn for_mainnet() -> Self {
        Self {
            ledger: *ICP_LEDGER_PRINCIPAL,
        }
    }
    pub fn for_ckbtc_devnet() -> Self {
        Self {
            ledger: *CKBTC_LEDGER_PRINCIPAL,
        }
    }

    async fn get_blocks_from_ic_ledger(&self, block_height: BlockIndex) -> Option<BlockWithId> {
        use candid::Nat;
        use num_traits::cast::ToPrimitive;

        let args = vec![GetBlocksRequest {
            start: Nat::from(block_height),
            length: Nat::from(2000u64),
        }];

        let ledger_id = *CKBTC_LEDGER_PRINCIPAL;

        let call_result: Result<(GetBlocksResult,), _> = Call::unbounded_wait(ledger_id, "icrc3_get_blocks")
            .with_args(&(args.clone(),))
            .await
            .map_err(ic_cdk::call::Error::from)
            .and_then(|r| r.candid_tuple().map_err(Into::into));

        if let Ok((result,)) = call_result {
            if !result.blocks.is_empty() {
                return result.blocks.first().cloned();
            }

            for archive in result.archived_blocks.iter() {
                for req in &archive.args {
                    let start: u64 = match req.start.clone().0.to_u64() {
                        Some(v) => v,
                        None => continue, // Skip this archive entry if Nat overflows u64
                    };
                    let len: u64 = match req.length.clone().0.to_u64() {
                        Some(v) => v,
                        None => continue,
                    };

                    if start <= block_height && block_height < start + len {
                        let archived_result: Result<(GetBlocksResult,), _> = Call::unbounded_wait(
                            archive.callback.canister_id,
                            &archive.callback.method,
                        )
                        .with_args(&(req.clone(),))
                        .await
                        .map_err(ic_cdk::call::Error::from)
                        .and_then(|r| r.candid_tuple().map_err(Into::into));

                        if let Ok((archived_blocks_result,)) = archived_result {
                            if !archived_blocks_result.blocks.is_empty() {
                                let idx = (block_height - start) as usize;
                                return archived_blocks_result.blocks.get(idx).cloned();
                            }
                        }
                    }
                }
            }
        }

        None
    }
}

impl<Q> Receiver<Q>
where
    Q: TXQuerier,
{
    /// Creates a new transaction receiver for the specified canister principal.
    pub fn new(q: Q, my_principal: Principal) -> Self {
        Self {
            tx_querier: q,
            my_account: AccountIdentifier::new(&my_principal, &DEFAULT_SUBACCOUNT),
            known_txs: Default::default(),
            unspent: Default::default(),
        }
    }

    /// Returns a clone of known transaction block heights (for snapshot persistence).
    pub fn get_known_txs(&self) -> BTreeSet<BlockHeight> {
        self.known_txs.clone()
    }

    /// Restores known transaction block heights from a snapshot.
    pub fn set_known_txs(&mut self, txs: BTreeSet<BlockHeight>) {
        self.known_txs = txs;
    }

    /// Verifies a transaction, and if it's valid and new, tracks its funds and
    /// returns its amount.
    pub async fn verify_icrc(
        &mut self,
        block_height: BlockHeight,
        amount: u64,
        funding: Funding,
    ) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
        if self.known_txs.contains(&block_height) {
            return Err(ICPReceiverError::DuplicateTransaction);
        }

        match self.tx_querier.query_icrc_tx(block_height, amount).await {
            Ok(tx) => {
                if tx.to != self.my_account {
                    return Err(ICPReceiverError::Recipient);
                }
                *self.unspent.entry(funding.memo()).or_insert(0u64.into()) += amount;
                // Only mark as known AFTER successful credit
                if !self.known_txs.insert(block_height) {
                    return Err(ICPReceiverError::DuplicateTransaction);
                }
                Ok(tx)
            }
            Err(e) => Err(e),
        }
    }

    /// Withdraws all funds from the requested memo.
    pub fn drain(&mut self, memo: Memo) -> Amount {
        return self.unspent.remove(&memo).unwrap_or(0u64.into()).into();
    }

    /// Withdraws all funds from the requested memo if it is above a threshold.
    pub fn drain_if_at_least(&mut self, memo: Memo, amount: Amount) -> Option<Amount> {
        if let Some(sum) = self.unspent.get(&memo) {
            if sum >= &amount {
                return self.unspent.remove(&memo);
            }
        }
        None
    }
}

/// Contents of a received transaction.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct TransactionICRCNotification {
    pub to: AccountIdentifier,
    pub from: AccountIdentifier,
    pub amount: u64,
    pub memo: Memo,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct TransactionNotification {
    pub to: AccountIdentifier,
    pub amount: u64,
    pub memo: Memo,
}

impl TransactionICRCNotification {
    /// Creates a transaction notification from an ICP ledger transaction. If the transaction is neither a transfer nor a mint, returns nothing.

    pub fn from_icrc_tx(tx: ICRCTransaction) -> Option<Self> {
        // Get the inner Transfer struct, if it exists
        let transfer = tx.transfer.as_ref()?;

        // Derive the AccountIdentifier from `transfer.to`

        let to_identifier = AccountIdentifier::new(&transfer.to.owner, &DEFAULT_SUBACCOUNT);
        let from_identifier = AccountIdentifier::new(&transfer.from.owner, &DEFAULT_SUBACCOUNT);

        // Convert Nat to u64 (if possible)
        let amount = transfer.amount.0.to_u64().unwrap_or(0);

        // Get the Memo, if present — return None if no memo
        let memo = transfer.memo.clone()?;

        Some(Self {
            to: to_identifier,
            from: from_identifier,
            amount,
            memo,
            timestamp: None,
        })
    }

    /// Returns the transaction's amount.
    pub fn get_amount(&self) -> Amount {
        self.amount.into()
    }
}

impl TransactionNotification {
    /// Returns the transaction's amount.
    pub fn get_amount(&self) -> Amount {
        self.amount.into()
    }
}
