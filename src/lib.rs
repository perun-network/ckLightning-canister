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

pub mod error;
pub mod events;
use crate::events::Event;
use crate::events::EventRegisterer;
use candid::{Principal, candid_method};
use ic_cdk::query;
use ic_cdk::update;
pub mod icp;
pub mod types;
use error::*;

// #[cfg(not(target_family = "wasm"))]
use ic_cdk::api::time as blocktime;

use ic_ledger_types::{
    AccountIdentifier, DEFAULT_FEE, DEFAULT_SUBACCOUNT, Memo, Tokens, TransferArgs,
};

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;
use types::*;

lazy_static! {
    static ref STATE: RwLock<CanisterState<icp::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            icp::CanisterTXQuerier::new(
                Principal::from_text("bkyz2-fmaaa-aaaaa-qaaaq-cai").expect("parsing principal")
            ),
            ic_cdk::id(),
        ));
}

/// The canister's state. Contains all currently registered channels, as well as
/// all deposits and withdrawable balances.
pub struct CanisterState<Q: icp::TXQuerier> {
    icp_receiver: icp::Receiver<Q>,
    /// Tracks all deposits for unregistered channels. For registered channels,
    /// tracks withdrawable balances instead.
    user_holdings: HashMap<Funding, Amount>,
    /// Tracks all registered channels.
    channels: HashMap<ChannelId, RegisteredState>,
    // ckBTC liquidity pools can be operated, in principle, by multiple key holders
    liq_pool_holdings: HashMap<L1Account, Amount>,
}

// #[candid::candid_method]
#[candid_method(update)]

/// The user needs to call this with his transaction.
async fn transaction_notification(block_height: u64) -> Option<Amount> {
    STATE.write().unwrap().process_icp_tx(block_height).await
}

#[query]
#[candid_method(query)]

/// Returns the funding specific for a channel's participant.
/// this function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_funding_only(funding: Funding) -> Option<Funding> {
    Some(funding.clone())
}

#[query]
#[candid::candid_method(query)]
/// Returns only the memo specific for a channel.
/// this function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_memo(mem: i32) -> Option<i32> {
    Some(mem)
}

#[query]
#[candid_method(query)]
/// Returns the funds deposited for a channel's specified participant, if any.
/// this function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_holdings(funding: Funding) -> Option<Amount> {
    STATE.read().unwrap().query_holdings(funding)
}

#[update]
#[candid_method(update)]

async fn deposit(funding: Funding) -> Option<Error> {
    STATE
        .write()
        .unwrap()
        .deposit_icp(blocktime(), funding)
        .await
        .err()
}

#[update]
#[candid_method(update)]

/// Only used for tests.
fn deposit_mocked(funding: Funding, amount: Amount) -> Option<Error> {
    STATE.write().unwrap().deposit(funding, amount).err()
}

#[query]
#[candid_method(query)]
/// Returns the latest registered state for a given channel and its dispute
/// timeout. This function should be used to check for registered disputes.
fn query_state(id: ChannelId) -> Option<RegisteredState> {
    STATE.read().unwrap().state(&id)
}

impl<Q> CanisterState<Q>
where
    Q: icp::TXQuerier,
{
    pub fn new(q: Q, my_principal: Principal) -> Self {
        Self {
            icp_receiver: icp::Receiver::new(q, my_principal),
            user_holdings: Default::default(),
            channels: Default::default(),
            liq_pool_holdings: Default::default(),
        }
    }
    pub fn deposit(&mut self, funding: Funding, amount: Amount) -> Result<()> {
        *self
            .user_holdings
            .entry(funding)
            .or_insert(Default::default()) += amount;
        Ok(())
    }

    pub fn deposit_liq_pool(
        &mut self,
        funding: PoolFunding,
        amount: Amount,
        depositor: L1Account,
    ) -> Result<()> {
        *self
            .liq_pool_holdings
            .entry(depositor.clone())
            .or_insert(Default::default()) += amount;
        Ok(())
    }

    /// Call this to access funds deposited and previously registered.
    pub async fn deposit_icp(&mut self, time: Timestamp, funding: Funding) -> Result<()> {
        let memo = funding.memo();
        let amount = self.icp_receiver.drain(memo);
        self.deposit(funding.clone(), amount)?;
        events::STATE
            .write()
            .unwrap()
            .register_event(
                time,
                funding.channel.clone(),
                Event::Funded {
                    who: funding.participant.clone(),
                    total: self.user_holdings.get(&funding).cloned().unwrap(),
                    timestamp: time,
                },
            )
            .await;
        Ok(())
    }

    /// Call this to process an ICP transaction and register the funds for
    /// further use.
    pub async fn process_icp_tx(&mut self, tx: icp::BlockHeight) -> Option<Amount> {
        match self.icp_receiver.verify(tx).await {
            Ok(v) => Some(v),
            Err(_e) => None, //Err(Error::ReceiverError(e)),
        }
    }

    pub fn query_holdings(&self, funding: Funding) -> Option<Amount> {
        self.user_holdings.get(&funding).cloned()
    }

    pub fn query_liq_holdings(&self, depositor: L1Account) -> Option<Amount> {
        self.liq_pool_holdings.get(&depositor).cloned()
    }

    /// Queries a registered state.
    pub fn state(&self, id: &ChannelId) -> Option<RegisteredState> {
        self.channels.get(&id).cloned()
    }

    /// Updates the holdings associated with a channel to the outcome of the
    /// supplied state, then registers the state. If the state is the channel's
    /// initial state, the holdings are not updated, as initial states are
    /// allowed to be under-funded and are otherwise expected to match the
    /// deposit distribution exactly if fully funded.
    fn register_channel(&mut self, params: &Params, state: RegisteredState) -> Result<()> {
        let total = &self.holdings_total(&params);
        if total < &state.state.total() {
            require!(state.state.may_be_underfunded(), InsufficientFunding);
        } else {
            self.update_holdings(&params, &state.state);
        }

        self.channels.insert(state.state.channel.clone(), state);
        Ok(())
    }

    /// Pushes a state's funding allocation into the channel's holdings mapping
    /// in the canister.
    fn update_holdings(&mut self, params: &Params, state: &State) {
        for (i, outcome) in state.allocation.iter().enumerate() {
            self.user_holdings.insert(
                Funding::new(
                    state.channel.clone(),
                    params.participants[i].clone(),
                    // state.l1_accounts[i].clone(),
                ),
                outcome.clone(),
            );
        }
    }

    /// Calculates the total funds held in a channel. If the channel is unknown
    /// and there are no deposited funds for the channel, returns 0.
    pub fn holdings_total(&self, params: &Params) -> Amount {
        let mut acc = Amount::default();
        for pk in params.participants.iter() {
            let funding = Funding::new(params.id(), pk.clone());
            acc += self
                .user_holdings
                .get(&funding)
                .unwrap_or(&Amount::default())
                .clone();
        }
        acc
    }

    pub async fn withdraw_from_liq_pool(
        &mut self,
        req: WithdrawalRequest,
        l1_acc: L1Account,
        amount: Amount,
    ) -> Result<Amount> {
        // Phase 1: Calculate required deductions (without modifying state)
        let (total_deducted, to_deduct) = self.calculate_required_deductions(&amount)?;

        // Phase 2: Execute ledger transfer
        self.execute_ledger_transfer(&req, total_deducted).await?;

        // Phase 3: Apply successful deductions to state
        self.apply_deductions(to_deduct);

        Ok(amount)
    }

    // Helper 1: Calculate required deductions
    fn calculate_required_deductions(&self, amount: &Nat) -> Result<(u64, Vec<(L1Account, Nat)>)> {
        let mut needed = amount.clone();
        let mut to_deduct = Vec::new();
        let zero = Nat::from(0u32);

        // Collect deduction plan
        for (acc, available) in &self.liq_pool_holdings {
            if needed == zero {
                break;
            }

            let take = available.min(&needed);
            if *take > zero {
                to_deduct.push((acc.clone(), take.clone()));
                needed -= take.clone();
            }
        }

        if needed > zero {
            return Err(Error::InsufficientLiquidity);
        }

        // Convert total to u64 for ledger
        let total = amount.clone() - needed;
        let total_u64 = total.0.to_u64_digits()[0]; //.ok_or(Error::AmountTooLarge)?;

        Ok((total_u64, to_deduct))
    }

    // Helper 2: Execute ledger transfer
    async fn execute_ledger_transfer(
        &self,
        req: &WithdrawalRequest,
        amount_u64: u64,
    ) -> Result<()> {
        let receiver = req.receiver.clone();
        let prince = receiver.0;

        let transfer_result = ic_ledger_types::transfer(
            prince,
            TransferArgs {
                memo: Memo(0),
                amount: Tokens::from_e8s(amount_u64),
                fee: DEFAULT_FEE,
                from_subaccount: None,
                to: AccountIdentifier::new(&prince, &DEFAULT_SUBACCOUNT),
                created_at_time: None,
            },
        )
        .await;

        match transfer_result {
            Ok(Ok(_block)) => Ok(()),
            _ => Err(Error::LedgerError),
        }
    }

    // Helper 3: Apply deductions after successful transfer
    fn apply_deductions(&mut self, to_deduct: Vec<(L1Account, Nat)>) {
        let zero = Nat::from(0u32);

        for (acc, take) in to_deduct {
            if let Some(entry) = self.liq_pool_holdings.get_mut(&acc) {
                *entry -= take;
                if *entry == zero {
                    self.liq_pool_holdings.remove(&acc);
                }
            }
        }
    }

    pub fn withdraw(&mut self, req: WithdrawalRequest, l1_acc: L1Account) -> Result<Amount> {
        // let auth = req.signature.clone();
        let now = req.time.clone();
        // req.validate_sig(&auth)?;
        let funding = Funding::new(req.funding.channel.clone(), req.participant.clone());
        match self.state(&req.funding.channel) {
            None => Err(Error::NotFinalized),
            Some(state) => {
                require!(state.settled(now), NotFinalized);
                Ok(self.user_holdings.remove(&funding).unwrap_or_default())
            }
        }
    }
}
