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
use candid::{CandidType, Deserialize, Nat, Principal};
use std::collections::HashMap;

/// Simplified depositor info - just tracks balances per principal
#[derive(Clone, Debug, Default, CandidType, Deserialize)]
pub struct DepositorBalance {
    pub ckbtc_amount: Amount,
    pub btc_amount: Amount,
}

#[derive(Clone, Debug, CandidType, Deserialize)]
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

    /// Deduct from pool proportionally from all depositors
    ///
    /// When a swap happens, liquidity is taken proportionally from all depositors
    /// based on their share of the total pool. For example:
    /// - User1 has 25,000 sats (25% of 100,000 total)
    /// - User2 has 75,000 sats (75% of 100,000 total)
    /// - A 10,000 sat swap deducts 2,500 from User1 and 7,500 from User2
    pub fn deduct_proportional(&mut self, asset: PoolAsset, amount: Amount) -> ResultCkl<()> {
        let total = self.holdings_total.get(&asset)
            .cloned()
            .ok_or(CklError::InsufficientLiquidity)?;

        if total < amount {
            return Err(CklError::InsufficientLiquidity);
        }

        // Convert to u128 for calculation
        let amount_u128: u128 = amount.0.clone().try_into().unwrap_or(0);
        let total_u128: u128 = total.0.clone().try_into().unwrap_or(1);

        if total_u128 == 0 {
            return Err(CklError::InsufficientLiquidity);
        }

        // Calculate and deduct proportional amounts from each depositor
        let mut total_deducted = Nat::from(0u64);
        let depositor_keys: Vec<Principal> = self.depositors.keys().cloned().collect();

        for depositor in depositor_keys {
            if let Some(balance) = self.depositors.get_mut(&depositor) {
                let depositor_balance = match asset {
                    PoolAsset::CkBTC => &mut balance.ckbtc_amount,
                    PoolAsset::BTC => &mut balance.btc_amount,
                };

                let depositor_u128: u128 = depositor_balance.0.clone().try_into().unwrap_or(0);

                if depositor_u128 > 0 {
                    // Calculate proportional deduction: amount * (depositor_balance / total)
                    // Use integer math: (amount * depositor_balance) / total
                    let deduction = (amount_u128 * depositor_u128) / total_u128;
                    let deduction_nat = Nat::from(deduction);

                    if *depositor_balance >= deduction_nat {
                        *depositor_balance -= deduction_nat.clone();
                        total_deducted += deduction_nat;
                    }
                }
            }
        }

        // Deduct total from holdings (use actual deducted amount to handle rounding)
        if let Some(holdings) = self.holdings_total.get_mut(&asset) {
            *holdings -= total_deducted;
        }

        Ok(())
    }

    /// Credit pool proportionally to all depositors (inverse of deduct_proportional).
    ///
    /// Distributes the given amount to all depositors based on their share of the total pool.
    /// Returns the number of depositors that received a share.
    pub fn credit_proportional(&mut self, asset: PoolAsset, amount: Amount) -> usize {
        let total = self.holdings_total.get(&asset)
            .cloned()
            .unwrap_or_default();

        let amount_u128: u128 = amount.0.clone().try_into().unwrap_or(0);
        let total_u128: u128 = total.0.clone().try_into().unwrap_or(0);

        if amount_u128 == 0 {
            return 0;
        }

        // If pool is empty, nothing to distribute to
        if total_u128 == 0 {
            return 0;
        }

        let mut total_credited = Nat::from(0u64);
        let mut recipients = 0usize;
        let depositor_keys: Vec<Principal> = self.depositors.keys().cloned().collect();

        for depositor in depositor_keys {
            if let Some(balance) = self.depositors.get_mut(&depositor) {
                let depositor_balance = match asset {
                    PoolAsset::CkBTC => &mut balance.ckbtc_amount,
                    PoolAsset::BTC => &mut balance.btc_amount,
                };

                let depositor_u128: u128 = depositor_balance.0.clone().try_into().unwrap_or(0);

                if depositor_u128 > 0 {
                    let credit = (amount_u128 * depositor_u128) / total_u128;
                    let credit_nat = Nat::from(credit);
                    *depositor_balance += credit_nat.clone();
                    total_credited += credit_nat;
                    recipients += 1;
                }
            }
        }

        // Update total holdings
        if let Some(holdings) = self.holdings_total.get_mut(&asset) {
            *holdings += total_credited;
        }

        recipients
    }

    /// Deduct from total pool only (legacy - doesn't affect individual balances)
    #[allow(dead_code)]
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
