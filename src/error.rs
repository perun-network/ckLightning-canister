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
pub use candid::{
    CandidType, Deserialize, Nat,
    types::{Serializer, Type},
};
use serde::Serialize;

#[derive(PartialEq, Eq, CandidType, Deserialize, Debug)]
/// Contains all errors that can occur during canister operations.
pub enum CklError {
    NoHoldingsFound,
    UnauthorizedCaller,
    /// When there is not enough liquidity in the pool to perform a withdrawal of ckBTC
    InsufficientLiquidity,
    /// Error while interaction with the ledger.
    LedgerError,
    Other(String),
}
impl std::fmt::Display for CklError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
/// Canister operation result type.
pub type ResultCkl<T> = core::result::Result<T, CklError>;
pub type ResultBtc<T> = core::result::Result<T, BtcError>;

#[macro_export]
macro_rules! require {
    ($cond:expr, $err:ident) => {
        if !($cond) {
            return Err($err);
        }
    };
    ($cond:expr, $err:expr) => {
        if !($cond) {
            return Err($err);
        }
    };
}
#[derive(Debug, CandidType, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BtcError {
    BtcAddressFetchError(String), // Carry error message here
    Other(String),
    BtcCouldNotFetchBalance,
}
impl std::fmt::Display for BtcError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BtcError::BtcAddressFetchError(msg) => write!(f, "BTC address fetch error: {msg}"),
            BtcError::Other(msg) => write!(f, "Other BTC error: {msg}"),
            BtcError::BtcCouldNotFetchBalance => {
                write!(f, "Could not fetch BTC balance for the given address")
            }
        }
    }
}
impl std::error::Error for BtcError {}
