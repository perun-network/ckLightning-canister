//  Copyright 2025 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writiing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
use crate::ic_types::{Amount, DEVNET_CKBTC_LEDGER, Funding, MAINNET_ICP_LEDGER};
use async_trait::async_trait;
pub use candid::{
    CandidType, Deserialize, Int, Nat, Principal,
    types::{Serializer, Type},
};
use ic_cdk::api::call::CallResult;
use ic_ledger_types::BlockIndex;
use ic_ledger_types::{
    AccountIdentifier, Block, DEFAULT_SUBACCOUNT, GetBlocksArgs, Operation, Transaction,
    query_archived_blocks, query_blocks,
};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::transfer::Memo;
use icrc_ledger_types::icrc3::transactions::Transfer;
use icrc_ledger_types::icrc3::transactions::{
    GetTransactionsRequest, GetTransactionsResponse, Transaction as ICRCTransaction,
};
use num_traits::cast::ToPrimitive;
use serde_bytes::ByteBuf;

use icrc_ledger_types;
use icrc_ledger_types::icrc3::blocks::{BlockWithId, GetBlocksRequest, GetBlocksResult};
use std::collections::{BTreeMap, BTreeSet};
pub type PerunMemo = u64;
pub type BlockHeight = u64;
type TxIndex = Nat;
/// ICP token handling errors.
#[derive(PartialEq, Eq, CandidType, Deserialize, Debug)]
pub enum ICPReceiverError {
    TransactionType,
    TxNotFound,
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
    known_txs: BTreeSet<BlockHeight>,     // set of block heights
    unspent: BTreeMap<PerunMemo, Amount>, // received tokens per memo
}

fn parse_transaction(value: &ICRC3Value) -> Result<ICRCTransaction, String> {
    let candid_bytes = candid::encode_one(value).map_err(|e| e.to_string())?;
    let transaction =
        candid::decode_one::<ICRCTransaction>(&candid_bytes).map_err(|e| e.to_string())?;
    Ok(transaction)
}

/// ICP transaction querier.
#[async_trait]
pub trait TXQuerier {
    async fn query_tx(
        &self,
        block_height: BlockHeight,
    ) -> Result<TransactionNotification, ICPReceiverError>;

    async fn query_icrc_tx(
        &self,
        block_height: BlockHeight,
        amount: u64,
    ) -> Result<TransactionNotification, ICPReceiverError>;
}

// impl<Q: TXQuerier + Clone> Clone for Receiver<Q> {
//     fn clone(&self) -> Self {
//         Self {
//             tx_querier: self.tx_querier.clone(),
//             my_account: self.my_account.clone(),
//             known_txs: self.known_txs.clone(),
//             unspent: self.unspent.clone(),
//         }
//     }
// }

/// Mocked ICP transaction querier for simulation and testing purposes.
#[derive(Default)]
pub struct MockTXQuerier {
    txs: BTreeMap<BlockHeight, TransactionNotification>,
}

// #[async_trait]
// impl TXQuerier for MockTXQuerier {
//     async fn query_tx(&self, block_height: BlockHeight) -> Result<TransactionNotification, u64> {
//         self.txs
//             .get(&block_height)
//             .cloned()
//             .ok_or(ICPReceiverError::FailedToQuery)
//     }
// }

// impl MockTXQuerier {
//     /// Inserts a transaction so that it can be read via query_tx().
//     pub fn register_tx(&mut self, block_height: BlockHeight, tx: TransactionNotification) {
//         self.txs.insert(block_height, tx);
//     }
// }

/// Real ICP transaction querier using inter-canister calls to the ICP ledger.
pub struct CanisterTXQuerier {
    ledger: Principal,
}

#[async_trait]
impl TXQuerier for CanisterTXQuerier {
    async fn query_tx(
        &self,
        block_height: BlockHeight,
    ) -> Result<TransactionNotification, ICPReceiverError> {
        if let Some(block) = self.get_block_from_ledger(block_height).await {
            if let Some(tx) = TransactionNotification::from_tx(block.transaction) {
                return Ok(tx);
            } else {
                return Err(ICPReceiverError::TransactionType);
            }
        }
        Err(ICPReceiverError::FailedToQuery)
    }

    async fn query_icrc_tx(
        &self,
        block_height: BlockHeight,
        amount: u64,
    ) -> Result<TransactionNotification, ICPReceiverError> {
        if let Some(block_with_id) = self.get_blocks_from_ic_ledger(block_height).await {
            // Attempt to extract the "transaction" field from the generic block map
            if let ICRC3Value::Map(map) = &block_with_id.block {
                // The key should be "transaction"
                if let Some(transaction_value) = map.get("transaction") {
                    // Parse ICRC3Value into your Transaction type
                    match parse_transaction(transaction_value) {
                        Ok(transaction) => {
                            // Convert to TransactionNotification as before
                            if let Some(tx_notification) =
                                TransactionNotification::from_icrc_tx(transaction)
                            {
                                return Ok(tx_notification);
                            } else {
                                return Err(ICPReceiverError::TransactionType);
                            }
                        }
                        Err(_) => return Err(ICPReceiverError::TxNotFound),
                    }
                }
            }
        }
        Err(ICPReceiverError::FailedToQuery)
    }
}

impl CanisterTXQuerier {
    pub fn new(ledger: Principal) -> Self {
        Self { ledger: ledger }
    }

    /// Constructs a new canister TX querier targeting the mainnet ICP ledger canister.
    pub fn for_mainnet() -> Self {
        Self {
            ledger: Principal::from_text(MAINNET_ICP_LEDGER).unwrap(),
        }
    }
    pub fn for_ckbtc_devnet() -> Self {
        Self {
            ledger: Principal::from_text(DEVNET_CKBTC_LEDGER).unwrap(),
        }
    }

    async fn get_blocks_from_ic_ledger(&self, block_height: BlockIndex) -> Option<BlockWithId> {
        use candid::Nat;
        use num_traits::cast::ToPrimitive;

        let args = GetBlocksRequest {
            start: Nat::from(block_height),
            length: Nat::from(1_u64),
        };

        let ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

        let call_result: CallResult<(GetBlocksResult,)> =
            ic_cdk::call(ledger_id, "icrc3_get_blocks", (args.clone(),)).await;

        if let Ok((result,)) = call_result {
            if !result.blocks.is_empty() {
                return result.blocks.first().cloned();
            }

            for archive in result.archived_blocks.iter() {
                for req in &archive.args {
                    let start: u64 = req.start.clone().0.to_u64().unwrap();
                    let len: u64 = req.length.clone().0.to_u64().unwrap();

                    if start <= block_height && block_height < start + len {
                        let archived_result: CallResult<(GetBlocksResult,)> = ic_cdk::call(
                            archive.callback.canister_id,
                            &archive.callback.method,
                            (req.clone(),),
                        )
                        .await;

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

    /// Queries a block from the ICP ledger's internal blockchain.
    async fn get_block_from_ledger(&self, block_height: BlockHeight) -> Option<Block> {
        let args = GetBlocksArgs {
            start: block_height,
            length: 1,
        };
        if let Ok(result) = query_blocks(self.ledger, &args.clone()).await {
            if result.blocks.len() != 0 {
                return result.blocks.first().cloned();
            }
            if let Some(b) = result
                .archived_blocks
                .into_iter()
                .find(|b| (b.start <= block_height && (block_height - b.start) < b.length))
            {
                if let Ok(Ok(range)) = query_archived_blocks(&b.callback, &args).await {
                    return range.blocks.get((block_height - b.start) as usize).cloned();
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

    /// Verifies a transaction, and if it's valid and new, tracks its funds and
    /// returns its amount.
    pub async fn verify_icrc(
        &mut self,
        block_height: BlockHeight,
        amount: u64,
        funding: Funding,
    ) -> std::result::Result<Amount, ICPReceiverError> {
        if self.known_txs.contains(&block_height) {
            return Err(ICPReceiverError::DuplicateTransaction);
        }

        match self.tx_querier.query_icrc_tx(block_height, amount).await {
            Ok(tx) => {
                if !self.known_txs.insert(block_height) {
                    return Err(ICPReceiverError::DuplicateTransaction);
                }
                if tx.to != self.my_account {
                    return Err(ICPReceiverError::Recipient);
                }
                *self.unspent.entry(funding.memo()).or_insert(0u64.into()) += amount;

                Ok(Amount::from(amount))
            }
            Err(e) => Err(e),
        }
    }

    pub async fn verify(
        &mut self,
        block_height: BlockHeight,
    ) -> std::result::Result<Amount, ICPReceiverError> {
        if self.known_txs.contains(&block_height) {
            return Err(ICPReceiverError::DuplicateTransaction);
        }

        match self.tx_querier.query_tx(block_height).await {
            Ok(tx) => {
                if !self.known_txs.insert(block_height) {
                    return Err(ICPReceiverError::DuplicateTransaction);
                }
                if tx.to != self.my_account {
                    return Err(ICPReceiverError::Recipient);
                }
                *self.unspent.entry(tx.memo).or_insert(0u64.into()) += tx.get_amount();

                Ok(tx.get_amount())
            }
            Err(e) => Err(e),
        }
    }

    /// Withdraws all funds from the requested memo.
    pub fn drain(&mut self, memo: PerunMemo) -> Amount {
        return self.unspent.remove(&memo).unwrap_or(0u64.into()).into();
    }

    /// Withdraws all funds from the requested memo if it is above a threshold.
    pub fn drain_if_at_least(&mut self, memo: PerunMemo, amount: Amount) -> Option<Amount> {
        if let Some(sum) = self.unspent.get(&memo) {
            if sum >= &amount {
                return self.unspent.remove(&memo).unwrap().into();
            }
        }
        None
    }
}

/// Contents of a received transaction.
#[derive(Clone, Debug, PartialEq, Eq, CandidType, Deserialize)]
pub struct TransactionNotification {
    pub to: AccountIdentifier,
    pub amount: u64,
    pub memo: PerunMemo,
}

impl TransactionNotification {
    /// Creates a transaction notification from an ICP ledger transaction. If the transaction is neither a transfer nor a mint, returns nothing.
    pub fn from_tx(tx: Transaction) -> Option<Self> {
        if tx.operation.is_none() {
            return None;
        }

        match tx.operation.unwrap() {
            Operation::Transfer { to, amount, .. } => {
                return Some(Self {
                    to: to,
                    amount: amount.e8s(),
                    memo: tx.memo.0,
                });
            }
            Operation::Mint { to, amount, .. } => {
                return Some(Self {
                    to: to,
                    amount: amount.e8s(),
                    memo: tx.memo.0,
                });
            }
            _ => (),
        }
        None
    }

    pub fn from_icrc_tx(tx: ICRCTransaction) -> Option<Self> {
        // Get the inner Transfer struct, if it exists
        let transfer = tx.transfer.as_ref()?;

        // Derive the AccountIdentifier from `transfer.to`

        let to_identifier = AccountIdentifier::new(&transfer.to.owner, &DEFAULT_SUBACCOUNT);

        // let to_identifier = AccountIdentifier::from_account(&transfer.to);

        // Convert Nat to u64 (if possible)
        let amount = transfer.amount.0.to_u64().unwrap_or(0);

        // Get the Memo, if present
        let memo = memo_to_u64(transfer.memo.clone());

        Some(Self {
            to: to_identifier,
            amount,
            memo,
        })
    }

    /// Returns the transaction's amount.
    pub fn get_amount(&self) -> Amount {
        self.amount.into()
    }
}
fn memo_to_u64(memo_opt: Option<Memo>) -> u64 {
    if let Some(memo) = memo_opt {
        let bytes = &memo.0[..];
        if bytes.len() >= 8 {
            let arr: [u8; 8] = bytes[0..8].try_into().unwrap_or([0; 8]);
            u64::from_be_bytes(arr)
        } else {
            0u64 // default if bytes too short
        }
    } else {
        0u64 // default if None
    }
}
