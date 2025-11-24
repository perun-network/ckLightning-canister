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
use crate::error::{CklError, ResultCkl};
use crate::ic_types::{Amount, DepositorInfo, L1Account, PoolAsset};
use candid::Nat;
use std::collections::HashMap;

pub struct LiquidityPool {
    // Map depositor account to their liquidity balance
    pub holdings_total: HashMap<PoolAsset, Amount>,
    pub holdings_locked: HashMap<PoolAsset, Amount>,
    pub depositors: HashMap<L1Account, DepositorInfo>,
}

pub struct Holdings {
    pub asset: PoolAsset,
    pub total: Amount,
}

impl LiquidityPool {
    pub fn new() -> Self {
        let mut holdings_total = HashMap::new();
        holdings_total.insert(PoolAsset::BTC, Default::default());
        holdings_total.insert(PoolAsset::CkBTC, Default::default());

        let mut holdings_locked = HashMap::new();
        holdings_locked.insert(PoolAsset::BTC, Default::default());
        holdings_locked.insert(PoolAsset::CkBTC, Default::default());

        Self {
            holdings_total,
            holdings_locked,
            depositors: HashMap::new(),
        }
    }
}
fn check_and_update_liq_pool(amount_req: &Nat, amount_avail: &Nat) -> ResultCkl<Nat> {
    if amount_req > amount_avail {
        return Err(CklError::InsufficientLiquidity);
    }
    // Use the overloaded Sub operator for Nat.
    let updated = amount_avail.clone() - amount_req.clone();
    Ok(updated)
}
