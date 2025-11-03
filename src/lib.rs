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

pub mod canister;
pub mod canister_state;
pub mod deq;
pub mod error;
pub mod events;
pub mod ic_types;
pub mod liquidity_pool;
use crate::ic_types::ChannelFunding;
pub mod msg;
pub mod receiver;
use crate::error::CklError;
use crate::events::{ChannelTime, Event, RegEvent};
use crate::ic_types::{
    Amount, ChannelId, Funding, FundingLPArgs, FundingLPQueryArgs, HoldingsResponse, NotifyArgs,
    PoolFunding, PoolWithdrawal, RegisteredState, Timestamp, WithdrawalLPArgs, WithdrawalReq,
};
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use candid::Nat;

// This generates the cklightning.did file
// candid-extractor target/wasm32-unknown-unknown/release/cklightning.wasm > cklightning.did
ic_cdk::export_candid!();
