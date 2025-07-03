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

pub mod bus;
use crate::receiver::DEFAULT_CKBTC_FEE;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
pub mod error;
pub mod events;
use crate::events::ChannelTime;
use crate::events::Event;
use crate::events::RegEvent;
use candid::{Principal, candid_method};
use ic_cdk::api::call::CallResult;
use ic_cdk::query;
use ic_cdk::update;
pub mod receiver;
pub mod types;
use candid::export_service;
use error::*;
use ic_cdk::api::time as blocktime;

use ic_ledger_types::{AccountIdentifier, DEFAULT_SUBACCOUNT, Tokens};

use receiver::DEVNET_CKBTC_LEDGER;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;
use types::*;

#[query(name = "__get_candid_interface_tmp_hack")]
fn export_candid() -> String {
    export_service!();
    __export_service()
}

lazy_static! {
    static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal") // //bkyz2-fmaaa-aaaaa-qaaaq-cai
            ),
            ic_cdk::id(),
        ));
}

/// The canister's state. Contains all currently registered channels, as well as
/// all deposits and withdrawable balances.
pub struct CanisterState<Q: receiver::TXQuerier> {
    icrc_receiver: receiver::Receiver<Q>,
    /// Tracks all deposits for unregistered channels. For registered channels,
    /// tracks withdrawable balances instead.
    user_holdings: HashMap<Funding, Amount>,
    /// Tracks all registered channels.
    channels: HashMap<ChannelId, RegisteredState>,
    // ckBTC liquidity pools can be operated, in principle, by multiple key holders
    liq_pool_holdings: HashMap<L1Account, Amount>,
}

#[update]
#[candid_method(update)]

/// The user needs to call this with his transaction.
async fn transaction_notification(notify_args: NotifyArgs) -> Option<Amount> {
    STATE
        .write()
        .unwrap()
        .process_icrc_tx(
            notify_args.block_height,
            notify_args.amount,
            notify_args.funding,
        )
        .await
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
        .deposit_icrc(blocktime(), funding)
        .await
        .err()
}

#[query]
#[candid_method(query)]
/// Returns the latest registered state for a given channel and its dispute
/// timeout. This function should be used to check for registered disputes.
fn query_state(id: ChannelId) -> Option<RegisteredState> {
    STATE.read().unwrap().state(&id)
}

#[update]
#[candid::candid_method]
async fn simple_withdraw(req: WithdrawalReq) -> Nat {
    let receiver = req.receiver;
    let amount_nat = req.amount;

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: receiver,
            subaccount: None,
        },
        amount: amount_nat.clone(),
        fee: Some(Nat(1000u64.into())), // ckBTC fee
        memo: None,
        created_at_time: None,
    };

    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let call_result: CallResult<(
        std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_height) => Nat::from(block_height),
            Err(e) => match e {
                icrc_ledger_types::icrc1::transfer::TransferError::BadFee { expected_fee } => {
                    ic_cdk::println!("BadFee: expected_fee = {:?}", expected_fee);
                    Nat::from(111u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::BadBurn { min_burn_amount } => {
                    ic_cdk::println!("BadBurn: min_burn_amount = {:?}", min_burn_amount);
                    Nat::from(112u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::InsufficientFunds {
                    balance,
                } => {
                    ic_cdk::println!("InsufficientFunds: balance = {:?}", balance);
                    Nat::from(222u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::TooOld => Nat::from(333u32),
                icrc_ledger_types::icrc1::transfer::TransferError::CreatedInFuture {
                    ledger_time,
                } => {
                    ic_cdk::println!("CreatedInFuture: ledger_time = {:?}", ledger_time);
                    Nat::from(444u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::TemporarilyUnavailable => {
                    ic_cdk::println!("TemporarilyUnavailable");
                    Nat::from(666u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::Duplicate { duplicate_of } => {
                    ic_cdk::println!("Duplicate: duplicate_of = {:?}", duplicate_of);
                    Nat::from(555u32)
                }
                icrc_ledger_types::icrc1::transfer::TransferError::GenericError {
                    error_code,
                    message,
                } => {
                    ic_cdk::println!(
                        "GenericError: code = {:?}, message = {}",
                        error_code,
                        message
                    );
                    Nat::from(777u32)
                }
            },
        },
        Err(e) => {
            ic_cdk::println!("CallResult error: {:?}", e);
            Nat::from(999u32) // Generic call error
        }
    }
}

#[update]
#[candid::candid_method]
async fn trigger_withdraw(req: WithdrawalReq) -> std::result::Result<candid::Nat, error::Error> {
    STATE.write().unwrap().withdraw_from_liq_pool(req).await
}

impl<Q> CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    pub fn new(q: Q, my_principal: Principal) -> Self {
        Self {
            icrc_receiver: receiver::Receiver::new(q, my_principal),
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
        funding: u64, //PoolFunding,
        amount: Amount,
        depositor: L1Account,
    ) -> Result<()> {
        *self
            .liq_pool_holdings
            .entry(depositor.clone())
            .or_insert(Default::default()) += amount;
        Ok(())
    }

    pub async fn deposit_icrc(&mut self, time: Timestamp, funding: Funding) -> Result<()> {
        let memo = funding.memo();
        let amount = self.icrc_receiver.drain(memo);

        self.deposit(funding.clone(), amount)?;
        // events::STATE
        //     .write()
        //     .unwrap()
        //     .register_event(
        //         time,
        //         funding.channel.clone(),
        //         Event::Funded {
        //             who: funding.participant.clone(),
        //             total: self.user_holdings.get(&funding).cloned().unwrap(),
        //             timestamp: time,
        //         },
        //     )
        //     .await;
        Ok(())
    }

    pub async fn process_icrc_tx(
        &mut self,
        tx: receiver::BlockHeight,
        amount: u64,
        funding: Funding,
    ) -> Option<Nat> {
        match self.icrc_receiver.verify_icrc(tx, amount, funding).await {
            Ok(v) => Some(v),
            Err(_e) => None,
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
        req: WithdrawalReq,
    ) -> std::result::Result<Nat, Error> {
        let amount = req.amount.clone();

        let (total_deducted, to_deduct) = match self.calculate_required_deductions(&amount) {
            Ok(res) => res,
            Err(_) => {
                return Err(Error::InsufficientLiquidity);
            }
        };

        let transfer_result = self.execute_ledger_transfer(&req, total_deducted).await;

        match transfer_result {
            Ok(block_height) => {
                self.apply_deductions(to_deduct);
                Ok(block_height)
            }
            Err(error_msg) => Err(error_msg),
        }
    }

    fn calculate_required_deductions(
        &self,
        amount: &Nat,
    ) -> std::result::Result<(u64, Vec<(Funding, Nat)>), Error> {
        let mut needed = amount.clone();
        let mut to_deduct = Vec::new();
        let zero = Nat::from(0u32);

        for (acc, available) in &self.user_holdings {
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

        let total = amount.clone() - needed;
        let total_u64 = total.0.to_u64_digits()[0];
        Ok((total_u64, to_deduct))
    }

    async fn execute_ledger_transfer(
        &self,
        req: &WithdrawalReq,
        amount_u64: u64,
    ) -> std::result::Result<Nat, Error> {
        let receiver = req.receiver;

        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: receiver,
                subaccount: None,
            },
            amount: Nat(amount_u64.into()),
            fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
            memo: None,
            created_at_time: None,
        };

        let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

        let call_result: CallResult<(
            std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
        )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

        match call_result {
            Ok((inner_result,)) => match inner_result {
                Ok(block_height) => Ok(block_height),
                Err(_e) => Err(Error::LedgerError),
            },
            Err((_code, _msg)) => Err(Error::LedgerError),
        }
    }

    fn apply_deductions(&mut self, to_deduct: Vec<(Funding, Nat)>) {
        let zero = Nat(0u64.into());

        for (acc, take) in to_deduct {
            if let Some(entry) = self.user_holdings.get_mut(&acc) {
                *entry -= take;
                if *entry == zero {
                    self.user_holdings.remove(&acc);
                }
            }
        }
    }
}

#[derive(CandidType)]
pub struct ckAccount {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}
