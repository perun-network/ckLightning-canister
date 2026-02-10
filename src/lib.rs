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
pub mod helpers;
pub mod htlc;
pub mod ic_types;
pub mod liquidity_pool;
use crate::ic_types::ChannelFunding;
pub mod btc;
use crate::ic_types::LnInvoiceRequest;
pub mod msg;
pub mod receiver;
pub mod stableswap;
use crate::error::ResultBtc;
use crate::error::{BtcError, CklError};
use crate::events::{ChannelTime, Event, RegEvent};
use crate::ic_types::GetBtcBalancesResponse;
use crate::ic_types::{
    BtcPurpose, ChannelId, CompleteSwapRequest, CompleteSwapResponse, FundingLPArgs,
    FundingLPQueryArgs, HoldingsResponse, LnChannelInfo, LnFundingPubkeyResponse, LnSignRequest,
    LnSignResponse, LpBalanceResponse, LpDepositResponse, LpWithdrawResponse, NotifyArgs,
    QueryLnChannelRequest, QueryLnChannelsResponse, RegisterLnChannelRequest,
    RegisterLnChannelResponse, RegisterSwapRequest, RegisterSwapResponse, RegisteredState,
    SendBtcTxArgs, SendBtcTxMsg, SetBtcAddressArgs, SetBtcAddressResponse, SignedCandidInvoice,
    Timestamp, TotalLpBalanceResponse, VerifyLnChannelResponse, WithdrawalLPArgs, WithdrawalReq,
    // BTC LP types
    LpBtcAddressResponse, LpBtcDepositRequest, LpBtcDepositResponse,
    LpBtcWithdrawRequest, LpBtcWithdrawResponse,
    FundChannelRequest, FundChannelResponse,
    // User BTC operations
    SendFromDepositorRequest, SendFromDepositorResponse, DepositorBtcBalanceResponse,
    // Onramp invoice request types
    OnrampInvoiceRequest, OnrampInvoiceResponse, OnrampRequestState, PendingInvoiceRequest,
    SubmitInvoiceRequest, SubmitInvoiceResponse, GetInvoiceResponse,
    // Offramp types (ckBTC → Lightning)
    OfframpRequest, OfframpResponse, OfframpRequestState, PendingOfframpRequest,
    CompleteOfframpRequest, CompleteOfframpResponse, FailOfframpRequest, FailOfframpResponse,
    GetOfframpStatusResponse, OfframpRequestInfo,
    // LP Liquidity types
    LpBtcUtxo, GetFundingUtxosRequest, GetFundingUtxosResponse,
    UpdateChannelBalanceRequest, UpdateChannelBalanceResponse,
    LpLiquidityStatus, LnChannelBalance,
    // HTLC types
    CreateHtlcRequest, CreateHtlcResponse,
    FulfillHtlcRequest, FulfillHtlcResponse,
    TimeoutHtlcRequest, TimeoutHtlcResponse,
    HtlcInfo,
    // Channel secrets types
    ChannelSecretsInfo,
    // HTLC signing types (Phase 2)
    CreateHtlcWithTxDetailsRequest, CreateHtlcWithTxDetailsResponse,
    SignHtlcSuccessRequest, SignHtlcTimeoutRequest, SignHtlcResponse,
    // Channel secret generation types (Phase 3)
    GenerateChannelSecretsRequest, GenerateChannelSecretsResponse,
    GetPerCommitmentPointRequest, GetPerCommitmentPointResponse,
    ReleaseCommitmentSecretRequest, ReleaseCommitmentSecretResponse,
    RegisterChannelInfoRequest,
    // Commitment/justice/HTLC signing types (Phase 3 + 4)
    SignCounterpartyCommitmentRequest, SignCounterpartyCommitmentResponse,
    SignHolderCommitmentRequest, SignHolderCommitmentResponse,
    SignClosingTxRequest,
    SignJusticeTxRequest, SignHtlcTxRequest,
    // Relay registration types
    RegisterRelayRequest, RegisterRelayResponse, GetRelayInfoResponse,
    // Rate limiting types
    RateLimitStatus,
    // StableSwap types
    StableSwapConfig, SwapDirection,
    UpdateStableSwapConfigRequest, UpdateStableSwapConfigResponse,
    SwapQuoteRequest, SwapQuoteResponse,
    WithdrawProtocolFeesResponse,
    SetIcpDdosFeeResponse, WithdrawIcpFeesResponse,
};
use crate::receiver::{ICPReceiverError, TransactionICRCNotification};
use candid::{Nat, Principal};
use ic_cdk::bitcoin_canister::Network;

use ic_cdk::{init, post_upgrade, pre_upgrade};
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

// Pre-upgrade hook.
// Serializes canister state to stable memory before the Wasm module is replaced.
#[pre_upgrade]
fn pre_upgrade() {
    let state = canister_state::STATE.read().unwrap();
    let snapshot = state.to_snapshot();
    let bytes = match candid::encode_one(&snapshot) {
        Ok(b) => b,
        Err(e) => {
            ic_cdk::trap(&format!("pre_upgrade: failed to encode state: {}", e));
        }
    };

    let len = bytes.len() as u64;
    let pages_needed = (len + 8 + 65535) / 65536;
    let current_pages = ic_cdk::stable::stable_size();
    if current_pages < pages_needed {
        if ic_cdk::stable::stable_grow(pages_needed - current_pages).is_err() {
            ic_cdk::trap("pre_upgrade: failed to grow stable memory");
        }
    }
    ic_cdk::stable::stable_write(0, &len.to_le_bytes());
    ic_cdk::stable::stable_write(8, &bytes);
}

// Post-upgrade hook.
// Reinitializes the BitcoinContext and restores canister state from stable memory.
#[post_upgrade]
fn upgrade(network: Network) {
    init_upgrade(network);

    // Restore state from stable memory
    if ic_cdk::stable::stable_size() > 0 {
        let mut len_bytes = [0u8; 8];
        ic_cdk::stable::stable_read(0, &mut len_bytes);
        let len = u64::from_le_bytes(len_bytes) as usize;

        if len > 0 {
            let mut bytes = vec![0u8; len];
            ic_cdk::stable::stable_read(8, &mut bytes);
            let snapshot: canister_state::CanisterStateSnapshot = match candid::decode_one(&bytes) {
                Ok(s) => s,
                Err(e) => {
                    ic_cdk::trap(&format!("post_upgrade: failed to decode state: {}", e));
                }
            };

            let mut state = canister_state::STATE.write().unwrap();
            state.restore_from_snapshot(snapshot);
        }
    }
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
