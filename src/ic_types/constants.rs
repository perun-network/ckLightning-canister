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

use candid::Principal;
use lazy_static::lazy_static;

pub const MAINNET_ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const DEVNET_ICP_LEDGER: &str = "ryjl3-tyaaa-aaaaa-aaaba-cai";
pub const DEVNET_CKBTC_LEDGER: &str = "mc6ru-gyaaa-aaaar-qaaaq-cai";
pub const DEVNET_CKBTC_MINTER: &str = "ml52i-qqaaa-aaaar-qaaba-cai";
pub const DEVNET_BASIC_BITCOIN: &str = "g4xu7-jiaaa-aaaan-aaaaq-cai";
pub const DEFAULT_CKBTC_FEE: u64 = 1000;

lazy_static! {
    pub static ref CKBTC_LEDGER_PRINCIPAL: Principal =
        Principal::from_text(DEVNET_CKBTC_LEDGER).expect("DEVNET_CKBTC_LEDGER is not a valid principal");
    pub static ref ICP_LEDGER_PRINCIPAL: Principal =
        Principal::from_text(DEVNET_ICP_LEDGER).expect("DEVNET_ICP_LEDGER is not a valid principal");
}

// Anti-DDoS ICP fee constants
pub const ICP_DDOS_FEE_E8S: u64 = 100_000_000; // 1 ICP in e8s (default; configurable via admin endpoint)
pub const ICP_TRANSFER_FEE_E8S: u64 = 10_000;     // 0.0001 ICP in e8s

// Swap timeout constants (in nanoseconds)
pub const ONRAMP_TIMEOUT_NS: u64 = 30 * 60 * 1_000_000_000;  // 30 minutes
pub const OFFRAMP_TIMEOUT_NS: u64 = 10 * 60 * 1_000_000_000; // 10 minutes

// Rate limiting constants
pub const RATE_LIMIT_WINDOW_NS: u64 = 60 * 60 * 1_000_000_000; // 1 hour window
pub const MAX_ONRAMP_REQUESTS_PER_WINDOW: u32 = 10;  // 10 onramp requests per hour
pub const MAX_OFFRAMP_REQUESTS_PER_WINDOW: u32 = 10; // 10 offramp requests per hour

// Re-export StableSwap types from the math module
pub use crate::stableswap::{StableSwapConfig, SwapDirection};

/// An amount of a currency.
pub type Amount = candid::Nat;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardcoded_principals_are_valid() {
        Principal::from_text(MAINNET_ICP_LEDGER)
            .expect("MAINNET_ICP_LEDGER is not a valid principal");
        Principal::from_text(DEVNET_ICP_LEDGER)
            .expect("DEVNET_ICP_LEDGER is not a valid principal");
        Principal::from_text(DEVNET_CKBTC_LEDGER)
            .expect("DEVNET_CKBTC_LEDGER is not a valid principal");
        Principal::from_text(DEVNET_CKBTC_MINTER)
            .expect("DEVNET_CKBTC_MINTER is not a valid principal");
        Principal::from_text(DEVNET_BASIC_BITCOIN)
            .expect("DEVNET_BASIC_BITCOIN is not a valid principal");
    }
}
