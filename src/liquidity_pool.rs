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

#[cfg(test)]
mod tests {
    use super::*;

    fn lp1() -> Principal {
        Principal::from_slice(&[1u8; 10])
    }

    fn lp2() -> Principal {
        Principal::from_slice(&[2u8; 10])
    }

    fn nat(v: u64) -> Nat {
        Nat::from(v)
    }

    fn to_u64(n: &Nat) -> u64 {
        n.0.clone().try_into().unwrap_or(0)
    }

    #[test]
    fn test_proportional_deduction_80_20_split() {
        let mut pool = LiquidityPool::new();
        // LP1 deposits 80k, LP2 deposits 20k → total 100k BTC
        pool.deposit(lp1(), PoolAsset::BTC, nat(80_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(20_000));
        assert_eq!(to_u64(&pool.get_total(&PoolAsset::BTC)), 100_000);

        // Fund a 100k channel → deduct proportionally
        pool.deduct_proportional(PoolAsset::BTC, nat(100_000)).unwrap();

        // LP1 loses 80k (80%), LP2 loses 20k (20%)
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 0);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 0);
        assert_eq!(to_u64(&pool.get_total(&PoolAsset::BTC)), 0);
    }

    #[test]
    fn test_proportional_deduction_partial() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(80_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(20_000));

        // Fund a 50k channel (half the pool)
        pool.deduct_proportional(PoolAsset::BTC, nat(50_000)).unwrap();

        // LP1: 80k - (50k * 80k/100k) = 80k - 40k = 40k
        // LP2: 20k - (50k * 20k/100k) = 20k - 10k = 10k
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 40_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 10_000);
        assert_eq!(to_u64(&pool.get_total(&PoolAsset::BTC)), 50_000);
    }

    #[test]
    fn test_proportional_credit_after_channel_close() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(80_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(20_000));

        // Channel open: deduct 100k
        pool.deduct_proportional(PoolAsset::BTC, nat(100_000)).unwrap();
        assert_eq!(to_u64(&pool.get_total(&PoolAsset::BTC)), 0);

        // Channel close: credit back 95k (5k lost to outbound payments)
        let recipients = pool.credit_proportional(PoolAsset::BTC, nat(95_000));
        // credit_proportional distributes based on current share, but pool is 0
        // so nobody gets anything (edge case: pool empty)
        assert_eq!(recipients, 0);
    }

    #[test]
    fn test_proportional_credit_with_remaining_balance() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(80_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(20_000));

        // Fund 50k channel (deduct half)
        pool.deduct_proportional(PoolAsset::BTC, nat(50_000)).unwrap();
        // Now: LP1=40k, LP2=10k, total=50k

        // Channel closes with 45k returned (5k lost)
        let recipients = pool.credit_proportional(PoolAsset::BTC, nat(45_000));
        assert_eq!(recipients, 2);

        // LP1 gets 45k * 40k/50k = 36k → 40k + 36k = 76k
        // LP2 gets 45k * 10k/50k = 9k → 10k + 9k = 19k
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 76_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 19_000);
        assert_eq!(to_u64(&pool.get_total(&PoolAsset::BTC)), 95_000);
    }

    #[test]
    fn test_net_loss_tracking() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(80_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(20_000));

        // Fund 100k channel
        pool.deduct_proportional(PoolAsset::BTC, nat(100_000)).unwrap();

        // LP1 deposits more BTC while channel is open
        pool.deposit(lp1(), PoolAsset::BTC, nat(50_000));
        // Now: LP1=50k, LP2=0, total=50k

        // Channel closes with 80k returned
        let recipients = pool.credit_proportional(PoolAsset::BTC, nat(80_000));
        assert_eq!(recipients, 1); // Only LP1 has balance

        // LP1: 50k + (80k * 50k/50k) = 50k + 80k = 130k
        // LP2: 0 + 0 = 0 (had no share when credit happened)
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 130_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 0);
    }

    #[test]
    fn test_multiple_channels() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(100_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(100_000));

        // Open first channel: 80k
        pool.deduct_proportional(PoolAsset::BTC, nat(80_000)).unwrap();
        // LP1: 100k - 40k = 60k, LP2: 100k - 40k = 60k, total=120k
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 60_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 60_000);

        // Open second channel: 60k
        pool.deduct_proportional(PoolAsset::BTC, nat(60_000)).unwrap();
        // LP1: 60k - 30k = 30k, LP2: 60k - 30k = 30k, total=60k
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 30_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 30_000);

        // Close first channel with 75k returned (lost 5k)
        pool.credit_proportional(PoolAsset::BTC, nat(75_000));
        // Each gets 75k * 30k/60k = 37.5k → 37500 due to integer math
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 67_500);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 67_500);
    }

    #[test]
    fn test_withdrawal_after_channel_open() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(100_000));
        pool.deposit(lp2(), PoolAsset::BTC, nat(50_000));

        // Fund 60k channel
        pool.deduct_proportional(PoolAsset::BTC, nat(60_000)).unwrap();
        // LP1: 100k - (60k * 100k/150k) = 100k - 40k = 60k
        // LP2: 50k - (60k * 50k/150k) = 50k - 20k = 30k
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 60_000);
        assert_eq!(to_u64(&pool.get_balance(&lp2(), &PoolAsset::BTC)), 30_000);

        // LP1 can withdraw their remaining 60k
        pool.withdraw(lp1(), PoolAsset::BTC, nat(60_000)).unwrap();
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 0);

        // LP1 cannot withdraw more than they have
        assert!(pool.withdraw(lp1(), PoolAsset::BTC, nat(1)).is_err());
    }

    #[test]
    fn test_deduct_insufficient_pool() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(50_000));

        // Cannot deduct more than pool has
        assert!(pool.deduct_proportional(PoolAsset::BTC, nat(100_000)).is_err());
        // Balance unchanged
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 50_000);
    }

    #[test]
    fn test_ckbtc_not_affected_by_btc_channel_ops() {
        let mut pool = LiquidityPool::new();
        pool.deposit(lp1(), PoolAsset::BTC, nat(100_000));
        pool.deposit(lp1(), PoolAsset::CkBTC, nat(50_000));

        // Fund BTC channel
        pool.deduct_proportional(PoolAsset::BTC, nat(100_000)).unwrap();

        // ckBTC balance unaffected
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::CkBTC)), 50_000);
        assert_eq!(to_u64(&pool.get_balance(&lp1(), &PoolAsset::BTC)), 0);
    }
}
