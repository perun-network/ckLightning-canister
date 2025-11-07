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
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use ic_cdk::api::call::CallResult;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

use crate::canister_state::{
    deposit_channel_impl, deposit_lp_impl, query_state_impl, query_user_lp_holdings_impl,
    set_btc_address_impl, transaction_notification_impl, trigger_withdraw_impl, withdraw_lp_impl,
};

use crate::error::{BtcError, CklError};
use crate::ic_types::{
    ChannelFunding, ChannelId, DEVNET_CKBTC_LEDGER, FundingLPArgs, FundingLPQueryArgs,
    HoldingsResponse, NotifyArgs, RegisteredState, SetBtcAddressArgs, SetBtcAddressResponse,
    WithdrawalLPArgs, WithdrawalReq,
};
use candid::{Nat, Principal, candid_method};
use ic_cdk::query;
use ic_cdk::update;

#[update]
#[candid_method(update)]
async fn set_btc_address(
    set_btc_address_args: SetBtcAddressArgs,
) -> std::result::Result<SetBtcAddressResponse, BtcError> {
    set_btc_address_impl(set_btc_address_args).await
}

#[update]
#[candid_method(update)]
async fn transaction_notification(
    notify_args: NotifyArgs,
) -> Result<TransactionICRCNotification, ICPReceiverError> {
    transaction_notification_impl(notify_args).await
}

#[query]
#[candid_method(query)]
/// Returns the funds deposited for a channel's specified participant, if any.
/// this function should be used to check whether all participants have
/// deposited their owed funds into a channel to ensure it is fully funded.
fn query_user_lp_holdings(
    funding: FundingLPQueryArgs,
) -> std::result::Result<HoldingsResponse, CklError> {
    query_user_lp_holdings_impl(funding)
}

#[update]
#[candid_method(update)]
fn deposit_channel(funding: ChannelFunding, signature_bytes: Vec<u8>) -> Result<(), CklError> {
    deposit_channel_impl(funding, &signature_bytes)
}

#[update]
#[candid_method(update)]
async fn withdraw_lp(withdrawal: WithdrawalLPArgs) -> Result<(), CklError> {
    let sig_withdrawal = withdrawal.signature.clone();

    withdraw_lp_impl(withdrawal, sig_withdrawal).await
}

#[update]
#[candid_method(update)]
fn deposit_lp(funding: FundingLPArgs) -> Result<(), CklError> {
    let signature_bytes = funding.signature.clone();

    deposit_lp_impl(funding, &signature_bytes)
}

#[query]
#[candid_method(query)]
fn query_state(id: ChannelId) -> Option<RegisteredState> {
    query_state_impl(id)
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
async fn trigger_withdraw(req: WithdrawalReq) -> Result<Nat, CklError> {
    trigger_withdraw_impl(req).await
}
