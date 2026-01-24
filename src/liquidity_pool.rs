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
use crate::ic_types::{Amount, PoolAsset};
use candid::{Nat, Principal};
use std::collections::HashMap;

/// Simplified depositor info - just tracks balances per principal
#[derive(Clone, Debug, Default)]
pub struct DepositorBalance {
    pub ckbtc_amount: Amount,
    pub btc_amount: Amount,
}

pub struct LiquidityPool {
    /// Total holdings per asset (sum of all depositors)
    pub holdings_total: HashMap<PoolAsset, Amount>,
    /// Locked holdings (reserved for pending operations)
    pub holdings_locked: HashMap<PoolAsset, Amount>,
    /// Per-depositor balances, keyed by Principal
    pub depositors: HashMap<Principal, DepositorBalance>,
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

    /// Deposit amount for a principal
    pub fn deposit(&mut self, depositor: Principal, asset: PoolAsset, amount: Amount) {
        // Update depositor's balance
        let balance = self.depositors.entry(depositor).or_default();
        match asset {
            PoolAsset::CkBTC => balance.ckbtc_amount += amount.clone(),
            PoolAsset::BTC => balance.btc_amount += amount.clone(),
        }
        // Update total holdings
        *self.holdings_total.get_mut(&asset).unwrap() += amount;
    }

    /// Withdraw amount for a principal
    pub fn withdraw(&mut self, depositor: Principal, asset: PoolAsset, amount: Amount) -> ResultCkl<()> {
        let balance = self.depositors.get_mut(&depositor)
            .ok_or(CklError::InsufficientLiquidity)?;

        let depositor_amount = match asset {
            PoolAsset::CkBTC => &mut balance.ckbtc_amount,
            PoolAsset::BTC => &mut balance.btc_amount,
        };

        if *depositor_amount < amount {
            return Err(CklError::InsufficientLiquidity);
        }

        *depositor_amount -= amount.clone();
        *self.holdings_total.get_mut(&asset).unwrap() -= amount;
        Ok(())
    }

    /// Deduct from total pool (for swaps) - doesn't affect individual depositor balances
    /// This is because swaps use fungible pool liquidity
    pub fn deduct_from_pool(&mut self, asset: PoolAsset, amount: Amount) -> ResultCkl<()> {
        let total = self.holdings_total.get_mut(&asset)
            .ok_or(CklError::InsufficientLiquidity)?;

        if *total < amount {
            return Err(CklError::InsufficientLiquidity);
        }

        *total -= amount;
        Ok(())
    }

    /// Get depositor's balance for an asset
    pub fn get_balance(&self, depositor: &Principal, asset: &PoolAsset) -> Amount {
        self.depositors.get(depositor)
            .map(|b| match asset {
                PoolAsset::CkBTC => b.ckbtc_amount.clone(),
                PoolAsset::BTC => b.btc_amount.clone(),
            })
            .unwrap_or_default()
    }

    /// Get total pool balance for an asset
    pub fn get_total(&self, asset: &PoolAsset) -> Amount {
        self.holdings_total.get(asset).cloned().unwrap_or_default()
    }
}
