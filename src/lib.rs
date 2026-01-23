//  Copyright 2026 PolyCrypt GmbH
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
use crate::ic_types::SetLiquidityBtcAddressResponse;
pub mod canister;
pub mod canister_state;
pub mod deq;
pub mod error;
pub mod events;
pub mod htlc;
pub mod ic_types;
pub mod liquidity_pool;
use crate::ic_types::ChannelFunding;
pub mod btc;
use crate::ic_types::LnInvoiceRequest;
pub mod msg;
pub mod receiver;
use crate::error::ResultBtc;
use crate::error::{BtcError, CklError};
use crate::events::{ChannelTime, Event, RegEvent};
use crate::ic_types::GetBtcBalancesResponse;
use crate::ic_types::{
    BtcPurpose, ChannelId, CompleteSwapRequest, CompleteSwapResponse, FundingLPArgs,
    FundingLPQueryArgs, HoldingsResponse, NotifyArgs, RegisterSwapRequest, RegisterSwapResponse,
    RegisteredState, SendBtcTxArgs, SendBtcTxMsg, SetBtcAddressArgs, SetBtcAddressResponse,
    SignedCandidInvoice, Timestamp, WithdrawalLPArgs, WithdrawalReq,
};
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use candid::Nat;
use ic_cdk::bitcoin_canister::Network;

use ic_cdk::{init, post_upgrade};
use std::cell::Cell;

/// Runtime configuration shared across all Bitcoin-related operations.
///
/// This struct carries network-specific context:
/// - `network`: The ICP Bitcoin API network enum.
/// - `bitcoin_network`: The corresponding network enum from the `bitcoin` crate, used
///   for address formatting and transaction construction.
/// - `key_name`: The global ECDSA key name used when requesting derived keys or making
///   signatures. Different key names are used locally and when deployed on the IC.
///
/// Note: Both `network` and `bitcoin_network` are needed because ICP and the
/// Bitcoin library use distinct network enum types.
#[derive(Clone, Copy)]
pub struct BitcoinContext {
    pub network: Network,
    pub bitcoin_network: bitcoin::Network,
    pub key_name: &'static str,
}

// Global, thread-local instance of the Bitcoin context.
// This is initialized at smart contract init/upgrade time and reused across all API calls.
thread_local! {
    static BTC_CONTEXT: Cell<BitcoinContext> = const {
        Cell::new(BitcoinContext {
            network: Network::Regtest,
            bitcoin_network: bitcoin::Network::Regtest,
            key_name: "test_key_1",
        })
    };
}

// Internal shared init logic used both by init and post-upgrade hooks.
fn init_upgrade(network: Network) {
    let key_name = match network {
        Network::Regtest => "dfx_test_key",
        Network::Mainnet | Network::Testnet => "test_key_1",
    };

    let bitcoin_network = match network {
        Network::Mainnet => bitcoin::Network::Bitcoin,
        Network::Testnet => bitcoin::Network::Testnet,
        Network::Regtest => bitcoin::Network::Regtest,
    };

    BTC_CONTEXT.with(|ctx| {
        ctx.set(BitcoinContext {
            network,
            bitcoin_network,
            key_name,
        })
    });
}

// Smart contract init hook.
// Sets up the BitcoinContext based on the given IC Bitcoin network.
#[init]
pub fn init(network: Network) {
    init_upgrade(network);
}

// Post-upgrade hook.
// Reinitializes the BitcoinContext with the same logic as `init`.
#[post_upgrade]
fn upgrade(network: Network) {
    init_upgrade(network);
}

/// Input structure for sending Bitcoin.
/// Used across P2PKH, P2WPKH, and P2TR transfer endpoints.
#[derive(candid::CandidType, candid::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

// This generates the cklightning.did file
// candid-extractor target/wasm32-unknown-unknown/release/cklightning.wasm > cklightning.did
ic_cdk::export_candid!();
