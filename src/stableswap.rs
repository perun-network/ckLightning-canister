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

//! StableSwap AMM pricing for BTC/ckBTC conversions.
//!
//! Implements Curve-style StableSwap invariant for 2 assets:
//!   4A(x+y) + D = 4AD + D³/(4xy)
//!
//! Pure math module — no IC dependencies. All u128 integer arithmetic
//! with checked operations.

use candid::{CandidType, Deserialize};

/// Maximum Newton iterations before declaring convergence failure.
const MAX_ITERATIONS: u32 = 256;

/// Convergence threshold: iteration stops when |D_{n+1} - D_n| <= 1.
const CONVERGENCE_THRESHOLD: u128 = 1;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct StableSwapConfig {
    /// Amplification coefficient (A). Higher = flatter curve near balance.
    pub amplification: u64,
    /// Total swap fee in basis points (1 bps = 0.01%).
    pub fee_bps: u64,
    /// Share of the total fee that goes to the protocol, in basis points.
    /// e.g. 5000 = 50% of total fee goes to protocol, rest stays in pool for LPs.
    pub protocol_fee_share_bps: u64,
    /// Maximum allowed price impact in basis points. 0 = disabled (no slippage check).
    /// If a swap's price impact exceeds this, the swap is rejected.
    pub max_slippage_bps: u64,
    /// Fee at maximum imbalance, in basis points. Must be >= fee_bps.
    /// The effective fee interpolates between fee_bps (balanced pool) and
    /// imbalance_fee_bps (fully imbalanced pool).
    pub imbalance_fee_bps: u64,
    /// Maximum rebate at full rebalance, in basis points. 0 = disabled.
    /// When a swap moves the pool closer to balance, the user receives a rebate
    /// (negative fee) that scales with how much the swap improves balance.
    pub rebate_bps: u64,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub enum SwapDirection {
    BtcToCkbtc,
    CkbtcToBtc,
}

#[derive(Clone, Debug, CandidType, Deserialize, PartialEq, Eq)]
pub struct SwapResult {
    /// Amount the user receives after fees.
    pub output_amount: u64,
    /// Total fee charged (lp_fee + protocol_fee).
    pub total_fee: u64,
    /// Portion of fee that stays in the pool (for LPs).
    pub lp_fee: u64,
    /// Portion of fee that goes to the protocol.
    pub protocol_fee: u64,
    /// Price impact in basis points.
    pub price_impact_bps: u64,
    /// Rebate amount (when swap rebalances the pool and rebate_bps > 0).
    /// This amount is already included in output_amount.
    pub rebate_amount: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StableSwapError {
    EmptyPool,
    ConvergenceFailure,
    ZeroInput,
    InputTooLarge,
    Overflow,
    ZeroAmplification,
    SlippageExceeded { price_impact_bps: u64, max_slippage_bps: u64 },
}

impl std::fmt::Display for StableSwapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StableSwapError::EmptyPool => write!(f, "Pool is empty"),
            StableSwapError::ConvergenceFailure => write!(f, "Newton iteration did not converge"),
            StableSwapError::ZeroInput => write!(f, "Input amount is zero"),
            StableSwapError::InputTooLarge => write!(f, "Input amount exceeds pool capacity"),
            StableSwapError::Overflow => write!(f, "Arithmetic overflow"),
            StableSwapError::ZeroAmplification => write!(f, "Amplification must be > 0"),
            StableSwapError::SlippageExceeded { price_impact_bps, max_slippage_bps } => {
                write!(f, "Slippage exceeded: price impact {} bps > max {} bps", price_impact_bps, max_slippage_bps)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Core math
// ---------------------------------------------------------------------------

/// Compute the StableSwap invariant D for two assets.
///
/// Solves: 4A(x+y) + D = 4AD + D³/(4xy)
///
/// Newton iteration:
///   D_{n+1} = (4A·S + 2·D_p) · D_n / ((4A-1)·D_n + 3·D_p)
/// where D_p = D³/(4xy), S = x + y
///
/// Overflow-safe approach: compute D_p as (D/2x) * (D/2y) * D
/// to avoid D³ overflow for realistic pool sizes.
pub fn compute_d(x: u128, y: u128, amp: u128) -> Result<u128, StableSwapError> {
    if x == 0 && y == 0 {
        return Ok(0);
    }
    if amp == 0 {
        return Err(StableSwapError::ZeroAmplification);
    }

    let s = x.checked_add(y).ok_or(StableSwapError::Overflow)?;

    // Initial guess: D = S
    let mut d = s;
    let a4 = amp.checked_mul(4).ok_or(StableSwapError::Overflow)?;

    for _ in 0..MAX_ITERATIONS {
        // D_p = D³ / (4xy)
        // To avoid overflow: D_p = (D * D / (2*x)) * D / (2*y)
        // Guard against zero denominators
        if x == 0 || y == 0 {
            return Err(StableSwapError::EmptyPool);
        }

        let d_p = d
            .checked_mul(d)
            .ok_or(StableSwapError::Overflow)?
            .checked_div(x.checked_mul(2).ok_or(StableSwapError::Overflow)?)
            .ok_or(StableSwapError::Overflow)?
            .checked_mul(d)
            .ok_or(StableSwapError::Overflow)?
            .checked_div(y.checked_mul(2).ok_or(StableSwapError::Overflow)?)
            .ok_or(StableSwapError::Overflow)?;

        let d_prev = d;

        // Numerator: (4A * S + 2 * D_p) * D
        let num_a = a4.checked_mul(s).ok_or(StableSwapError::Overflow)?;
        let num_b = d_p.checked_mul(2).ok_or(StableSwapError::Overflow)?;
        let numerator = num_a
            .checked_add(num_b)
            .ok_or(StableSwapError::Overflow)?
            .checked_mul(d)
            .ok_or(StableSwapError::Overflow)?;

        // Denominator: (4A - 1) * D + 3 * D_p
        let denom_a = a4
            .checked_sub(1)
            .ok_or(StableSwapError::Overflow)?
            .checked_mul(d)
            .ok_or(StableSwapError::Overflow)?;
        let denom_b = d_p.checked_mul(3).ok_or(StableSwapError::Overflow)?;
        let denominator = denom_a
            .checked_add(denom_b)
            .ok_or(StableSwapError::Overflow)?;

        if denominator == 0 {
            return Err(StableSwapError::ConvergenceFailure);
        }

        d = numerator / denominator;

        // Check convergence
        let diff = if d > d_prev { d - d_prev } else { d_prev - d };
        if diff <= CONVERGENCE_THRESHOLD {
            return Ok(d);
        }
    }

    Err(StableSwapError::ConvergenceFailure)
}

/// Given x_new and D, solve for y such that the invariant holds.
///
/// Newton iteration for y:
///   y_{n+1} = (y² + c) / (2y + b - D)
/// where c = D³/(4 · 4A · x_new), b = x_new + D/(4A)
pub fn compute_y(x_new: u128, d: u128, amp: u128) -> Result<u128, StableSwapError> {
    if amp == 0 {
        return Err(StableSwapError::ZeroAmplification);
    }
    if d == 0 {
        return Ok(0);
    }

    let a4 = amp.checked_mul(4).ok_or(StableSwapError::Overflow)?;

    // c = D³ / (4 · 4A · x_new)
    // Overflow-safe: c = (D * D / (4A * x_new)) * D / 4
    let a4_x = a4
        .checked_mul(x_new)
        .ok_or(StableSwapError::Overflow)?;
    if a4_x == 0 {
        return Err(StableSwapError::EmptyPool);
    }

    let c = d
        .checked_mul(d)
        .ok_or(StableSwapError::Overflow)?
        .checked_div(a4_x)
        .ok_or(StableSwapError::Overflow)?
        .checked_mul(d)
        .ok_or(StableSwapError::Overflow)?
        .checked_div(4)
        .ok_or(StableSwapError::Overflow)?;

    // b = x_new + D / (4A)
    let b = x_new
        .checked_add(d / a4)
        .ok_or(StableSwapError::Overflow)?;

    // Initial guess: y = D
    let mut y = d;

    for _ in 0..MAX_ITERATIONS {
        let y_prev = y;

        // Numerator: y² + c
        let numerator = y
            .checked_mul(y)
            .ok_or(StableSwapError::Overflow)?
            .checked_add(c)
            .ok_or(StableSwapError::Overflow)?;

        // Denominator: 2y + b - D
        let denom = y
            .checked_mul(2)
            .ok_or(StableSwapError::Overflow)?
            .checked_add(b)
            .ok_or(StableSwapError::Overflow)?
            .checked_sub(d)
            .ok_or(StableSwapError::Overflow)?;

        if denom == 0 {
            return Err(StableSwapError::ConvergenceFailure);
        }

        y = numerator / denom;

        let diff = if y > y_prev { y - y_prev } else { y_prev - y };
        if diff <= CONVERGENCE_THRESHOLD {
            return Ok(y);
        }
    }

    Err(StableSwapError::ConvergenceFailure)
}

// ---------------------------------------------------------------------------
// Dynamic fee
// ---------------------------------------------------------------------------

/// Compute the effective fee in basis points, interpolating between
/// `fee_bps` (balanced pool) and `imbalance_fee_bps` (fully imbalanced pool).
///
/// This is the legacy direction-unaware version used for initial estimates.
/// For the full direction-aware computation, use `compute_effective_fee`.
///
/// Capped at 10,000 bps (100%).
pub fn compute_effective_fee_bps(config: &StableSwapConfig, x: u128, y: u128) -> u64 {
    let base = config.fee_bps as u128;
    let max_fee = config.imbalance_fee_bps as u128;

    // No dynamic effect when imbalance_fee_bps <= fee_bps
    if max_fee <= base {
        return config.fee_bps;
    }

    let sum = x.saturating_add(y);
    if sum == 0 {
        return config.fee_bps;
    }

    let diff = if x > y { x - y } else { y - x };
    let spread = max_fee - base; // guaranteed > 0

    // effective = base + spread * diff / sum
    let dynamic = spread.saturating_mul(diff) / sum;
    let effective = base.saturating_add(dynamic);

    // Cap at 10,000 bps
    std::cmp::min(effective, 10_000) as u64
}

/// Direction-aware fee computation that accounts for pool rebalancing.
///
/// Uses pre-swap and post-swap balances to determine if the swap improves
/// or worsens pool balance:
///
/// - **Imbalancing** (pool gets worse): fee scales from `fee_bps` up to
///   `imbalance_fee_bps` based on post-swap imbalance.
/// - **Rebalancing** (pool gets better): fee scales from `fee_bps` down to
///   `-rebate_bps` based on improvement ratio. Negative = rebate to user.
///
/// Returns signed bps: positive = fee, negative = rebate.
pub fn compute_effective_fee(
    config: &StableSwapConfig,
    x_before: u128,
    y_before: u128,
    x_after: u128,
    y_after: u128,
) -> i64 {
    let base = config.fee_bps as i128;
    let max_fee = config.imbalance_fee_bps as i128;
    let rebate = config.rebate_bps as i128;

    let sum_before = x_before.saturating_add(y_before);
    let sum_after = x_after.saturating_add(y_after);

    if sum_before == 0 || sum_after == 0 {
        return config.fee_bps as i64;
    }

    // Imbalance in bps (0..10000)
    let diff_before = if x_before > y_before { x_before - y_before } else { y_before - x_before };
    let diff_after = if x_after > y_after { x_after - y_after } else { y_after - x_after };

    let imb_before = (diff_before * 10_000 / sum_before) as i128;
    let imb_after = (diff_after * 10_000 / sum_after) as i128;

    if imb_after >= imb_before {
        // Pool got worse (imbalancing) — charge higher fee based on post-swap imbalance
        let effective = if max_fee <= base {
            base
        } else {
            base + (max_fee - base) * imb_after / 10_000
        };
        std::cmp::min(effective, 10_000) as i64
    } else {
        // Pool got better (rebalancing) — apply rebate if enabled
        if rebate == 0 {
            return config.fee_bps as i64;
        }

        // improvement = how much of the imbalance was removed, 0..10000
        let improvement = if imb_before == 0 {
            0i128
        } else {
            (imb_before - imb_after) * 10_000 / imb_before
        };

        // Linear interpolation: fee_bps at improvement=0, -rebate_bps at improvement=10000
        // effective = fee_bps - (fee_bps + rebate_bps) * improvement / 10000
        let effective = base - (base + rebate) * improvement / 10_000;

        // Clamp to [-rebate_bps, fee_bps]
        let clamped = effective.max(-(rebate)).min(base);
        clamped as i64
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compute swap output given an input amount and direction.
///
/// Returns the output amount after fees, with fee breakdown.
pub fn get_swap_output(
    config: &StableSwapConfig,
    btc_balance: u64,
    ckbtc_balance: u64,
    input_amount: u64,
    direction: &SwapDirection,
) -> Result<SwapResult, StableSwapError> {
    if input_amount == 0 {
        return Err(StableSwapError::ZeroInput);
    }
    if config.amplification == 0 {
        return Err(StableSwapError::ZeroAmplification);
    }

    let x: u128;
    let y: u128;

    match direction {
        SwapDirection::BtcToCkbtc => {
            // User sends BTC, receives ckBTC
            // x = BTC pool, y = ckBTC pool
            x = btc_balance as u128;
            y = ckbtc_balance as u128;
        }
        SwapDirection::CkbtcToBtc => {
            // User sends ckBTC, receives BTC
            // x = ckBTC pool, y = BTC pool
            x = ckbtc_balance as u128;
            y = btc_balance as u128;
        }
    }

    if x == 0 || y == 0 {
        return Err(StableSwapError::EmptyPool);
    }

    let input = input_amount as u128;
    let amp = config.amplification as u128;

    // Current invariant
    let d = compute_d(x, y, amp)?;

    // New x after adding input
    let x_new = x.checked_add(input).ok_or(StableSwapError::Overflow)?;

    // Solve for new y
    let y_new = compute_y(x_new, d, amp)?;

    // Raw output (before fees)
    let raw_output = y.checked_sub(y_new).ok_or(StableSwapError::Overflow)?;
    if raw_output == 0 {
        return Err(StableSwapError::InputTooLarge);
    }

    // Direction-aware fee: uses pre-swap and post-swap balances
    let effective_fee_signed = compute_effective_fee(config, x, y, x_new, y_new);

    let (output_after_fee, total_fee, protocol_fee, lp_fee, rebate_amount) = if effective_fee_signed >= 0 {
        // Positive fee path (normal or imbalancing swap)
        let fee_bps = effective_fee_signed as u128;
        let total_fee = raw_output
            .checked_mul(fee_bps)
            .ok_or(StableSwapError::Overflow)?
            / 10_000;

        let output_after_fee = raw_output
            .checked_sub(total_fee)
            .ok_or(StableSwapError::Overflow)?;

        // Split fee between LP and protocol
        let protocol_share_bps = config.protocol_fee_share_bps as u128;
        let protocol_fee = total_fee
            .checked_mul(protocol_share_bps)
            .ok_or(StableSwapError::Overflow)?
            / 10_000;
        let lp_fee = total_fee
            .checked_sub(protocol_fee)
            .ok_or(StableSwapError::Overflow)?;

        (output_after_fee, total_fee, protocol_fee, lp_fee, 0u128)
    } else {
        // Negative fee path (rebate — user gets MORE than raw AMM output)
        let rebate_bps = (-effective_fee_signed) as u128;
        let rebate = raw_output
            .checked_mul(rebate_bps)
            .ok_or(StableSwapError::Overflow)?
            / 10_000;

        let output_with_rebate = raw_output
            .checked_add(rebate)
            .ok_or(StableSwapError::Overflow)?;

        // No fees when rebate is active — rebate is paid by LPs
        (output_with_rebate, 0u128, 0u128, 0u128, rebate)
    };

    // Price impact: compare effective rate vs 1:1
    // price_impact_bps = (1 - output/input) * 10000
    // Using integer math: (input - output_after_fee) * 10000 / input
    let price_impact_bps = if input > 0 && output_after_fee <= input {
        (input - output_after_fee)
            .checked_mul(10_000)
            .ok_or(StableSwapError::Overflow)?
            / input
    } else if output_after_fee > input {
        // Output > input means favorable rate (pool rebalancing incentive)
        0
    } else {
        0
    };

    // Slippage check (0 = disabled)
    let impact = price_impact_bps as u64;
    if config.max_slippage_bps > 0 && impact > config.max_slippage_bps {
        return Err(StableSwapError::SlippageExceeded {
            price_impact_bps: impact,
            max_slippage_bps: config.max_slippage_bps,
        });
    }

    Ok(SwapResult {
        output_amount: output_after_fee as u64,
        total_fee: total_fee as u64,
        lp_fee: lp_fee as u64,
        protocol_fee: protocol_fee as u64,
        price_impact_bps: impact,
        rebate_amount: rebate_amount as u64,
    })
}

/// Reverse computation: given a desired output amount, compute the required input.
///
/// Used for offramp where the user specifies how much BTC they want to receive
/// via Lightning, and we need to calculate how much ckBTC to charge.
pub fn get_swap_input(
    config: &StableSwapConfig,
    btc_balance: u64,
    ckbtc_balance: u64,
    desired_output: u64,
    direction: &SwapDirection,
) -> Result<SwapResult, StableSwapError> {
    if desired_output == 0 {
        return Err(StableSwapError::ZeroInput);
    }
    if config.amplification == 0 {
        return Err(StableSwapError::ZeroAmplification);
    }

    let x: u128;
    let y: u128;

    match direction {
        SwapDirection::BtcToCkbtc => {
            x = btc_balance as u128;
            y = ckbtc_balance as u128;
        }
        SwapDirection::CkbtcToBtc => {
            x = ckbtc_balance as u128;
            y = btc_balance as u128;
        }
    }

    if x == 0 || y == 0 {
        return Err(StableSwapError::EmptyPool);
    }

    let output = desired_output as u128;
    let amp = config.amplification as u128;

    // Step 1: Initial estimate using pre-swap fee (direction-unaware)
    let initial_fee_bps = compute_effective_fee_bps(config, x, y) as i128;

    // For initial estimate, check if pool is imbalanced and swap direction helps
    // We'll iterate to refine with actual post-swap balances
    let est_raw_output = if initial_fee_bps > 0 {
        // raw_output = output * 10000 / (10000 - fee)
        let denom = 10_000i128 - initial_fee_bps;
        if denom <= 0 {
            return Err(StableSwapError::Overflow);
        }
        (output as i128 * 10_000 + denom - 1) as u128 / denom as u128
    } else {
        output
    };

    if est_raw_output >= y {
        return Err(StableSwapError::InputTooLarge);
    }

    // Step 2: Compute actual post-swap balances and refine
    let d = compute_d(x, y, amp)?;

    let y_new_est = y.checked_sub(est_raw_output).ok_or(StableSwapError::Overflow)?;
    let x_new_est = compute_y(y_new_est, d, amp)?;

    // Now compute direction-aware fee with actual post-swap balances
    let effective_fee_signed = compute_effective_fee(config, x, y, x_new_est, y_new_est);

    // Recompute raw_output with the refined fee
    let (raw_output, rebate_amount) = if effective_fee_signed >= 0 {
        // Positive fee: raw_output = output * 10000 / (10000 - fee)
        let fee_bps = effective_fee_signed as u128;
        let denom = 10_000u128.checked_sub(fee_bps).ok_or(StableSwapError::Overflow)?;
        if denom == 0 {
            return Err(StableSwapError::Overflow);
        }
        let raw = output
            .checked_mul(10_000)
            .ok_or(StableSwapError::Overflow)?
            .checked_add(denom - 1)
            .ok_or(StableSwapError::Overflow)?
            / denom;
        (raw, 0u128)
    } else {
        // Negative fee (rebate): user gets output = raw_output + rebate
        // output = raw_output * (10000 + |fee|) / 10000
        // raw_output = output * 10000 / (10000 + |fee|)
        let rebate_bps = (-effective_fee_signed) as u128;
        let denom = 10_000u128.checked_add(rebate_bps).ok_or(StableSwapError::Overflow)?;
        let raw = output
            .checked_mul(10_000)
            .ok_or(StableSwapError::Overflow)?
            .checked_add(denom - 1)
            .ok_or(StableSwapError::Overflow)?
            / denom;
        let rebate = output.saturating_sub(raw);
        (raw, rebate)
    };

    if raw_output >= y {
        return Err(StableSwapError::InputTooLarge);
    }

    // y_new = y - raw_output
    let y_new = y.checked_sub(raw_output).ok_or(StableSwapError::Overflow)?;

    // Solve for x_new given y_new and D
    let x_new = compute_y(y_new, d, amp)?;

    // Required input
    let input = x_new.checked_sub(x).ok_or(StableSwapError::Overflow)?;
    if input == 0 {
        return Err(StableSwapError::ZeroInput);
    }

    // Compute actual fees
    let (total_fee, protocol_fee, lp_fee) = if effective_fee_signed >= 0 {
        let total_fee = raw_output.checked_sub(output).ok_or(StableSwapError::Overflow)?;
        let protocol_share_bps = config.protocol_fee_share_bps as u128;
        let protocol_fee = total_fee
            .checked_mul(protocol_share_bps)
            .ok_or(StableSwapError::Overflow)?
            / 10_000;
        let lp_fee = total_fee.checked_sub(protocol_fee).ok_or(StableSwapError::Overflow)?;
        (total_fee, protocol_fee, lp_fee)
    } else {
        // Rebate: no fees
        (0u128, 0u128, 0u128)
    };

    // Price impact
    let price_impact_bps = if input > 0 && output <= input {
        (input - output)
            .checked_mul(10_000)
            .ok_or(StableSwapError::Overflow)?
            / input
    } else {
        0
    };

    // Slippage check (0 = disabled)
    let impact = price_impact_bps as u64;
    if config.max_slippage_bps > 0 && impact > config.max_slippage_bps {
        return Err(StableSwapError::SlippageExceeded {
            price_impact_bps: impact,
            max_slippage_bps: config.max_slippage_bps,
        });
    }

    Ok(SwapResult {
        output_amount: input as u64, // For get_swap_input, output_amount is the required input
        total_fee: total_fee as u64,
        lp_fee: lp_fee as u64,
        protocol_fee: protocol_fee as u64,
        price_impact_bps: impact,
        rebate_amount: rebate_amount as u64,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> StableSwapConfig {
        StableSwapConfig {
            amplification: 200,
            fee_bps: 10,               // 0.1%
            protocol_fee_share_bps: 5000, // 50% of fee to protocol
            max_slippage_bps: 500,     // 5% — reject swaps with extreme price impact
            imbalance_fee_bps: 100,    // 1% at full imbalance (10x base fee)
            rebate_bps: 0,             // disabled by default
        }
    }

    #[test]
    fn test_compute_d_balanced_pool() {
        // Balanced pool: x = y = 1_000_000 sats (0.01 BTC each side)
        let d = compute_d(1_000_000, 1_000_000, 200).unwrap();
        // D should equal 2 * balance for a balanced pool
        assert_eq!(d, 2_000_000);
    }

    #[test]
    fn test_compute_d_imbalanced_pool() {
        let d = compute_d(2_000_000, 1_000_000, 200).unwrap();
        // D should be between 2_000_000 and 3_000_000
        assert!(d > 2_000_000);
        assert!(d < 3_000_000);
    }

    #[test]
    fn test_compute_d_empty_pool() {
        let d = compute_d(0, 0, 200).unwrap();
        assert_eq!(d, 0);
    }

    #[test]
    fn test_compute_d_one_side_empty() {
        let result = compute_d(1_000_000, 0, 200);
        assert_eq!(result, Err(StableSwapError::EmptyPool));
    }

    #[test]
    fn test_compute_d_zero_amp() {
        let result = compute_d(1_000_000, 1_000_000, 0);
        assert_eq!(result, Err(StableSwapError::ZeroAmplification));
    }

    #[test]
    fn test_compute_y_roundtrip() {
        // If we compute D from (x, y) and then solve for y given x, we should get y back
        let x = 1_000_000u128;
        let y = 1_000_000u128;
        let amp = 200u128;
        let d = compute_d(x, y, amp).unwrap();
        let y_computed = compute_y(x, d, amp).unwrap();
        // Should be within 1 due to rounding
        assert!((y_computed as i128 - y as i128).unsigned_abs() <= 1);
    }

    #[test]
    fn test_balanced_pool_near_one_to_one() {
        let config = default_config();
        // Balanced pool: 100 BTC each side
        let btc_bal = 10_000_000_000u64; // 100 BTC in sats
        let ckbtc_bal = 10_000_000_000u64;
        let input = 100_000u64; // 0.001 BTC — small relative to pool

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // With balanced pool and small swap, output ≈ input minus fee
        // Fee = 0.1% = 100 sats, so output ≈ 99,900
        let expected_fee = input as u64 * 10 / 10_000; // ~100
        assert!(result.output_amount > input - expected_fee - 10); // within 10 sats
        assert!(result.output_amount < input);
        assert!(result.total_fee > 0);
        assert_eq!(result.total_fee, result.lp_fee + result.protocol_fee);
    }

    #[test]
    fn test_imbalanced_pool_price_impact() {
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 0, // No fee, isolate AMM effect
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };

        // Imbalanced: lots of BTC, less ckBTC
        let btc_bal = 2_000_000u64;   // 0.02 BTC
        let ckbtc_bal = 500_000u64;   // 0.005 BTC

        // Swap BTC → ckBTC (adding to the already large BTC side)
        let input = 100_000u64;
        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Should get less than 1:1 since ckBTC is scarce
        assert!(result.output_amount < input);
        assert!(result.price_impact_bps > 0);
    }

    #[test]
    fn test_imbalanced_pool_favorable_direction() {
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };

        // Imbalanced: lots of ckBTC, less BTC
        let btc_bal = 500_000u64;
        let ckbtc_bal = 2_000_000u64;

        // Swap BTC → ckBTC (adding to scarce BTC side — rebalancing)
        let input = 100_000u64;
        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Should get more than 1:1 since we're rebalancing
        assert!(result.output_amount > input);
    }

    #[test]
    fn test_fee_split() {
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 100,              // 1% fee
            protocol_fee_share_bps: 3000, // 30% of fee to protocol
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,    // same as fee_bps
            rebate_bps: 0,
        };

        let btc_bal = 10_000_000u64;
        let ckbtc_bal = 10_000_000u64;
        let input = 1_000_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Total fee ≈ 1% of raw output ≈ 10,000
        assert!(result.total_fee > 9_000 && result.total_fee < 11_000);
        // Protocol fee ≈ 30% of total ≈ 3,000
        assert_eq!(result.total_fee, result.lp_fee + result.protocol_fee);
        // Protocol should be ~30% of total
        let expected_protocol = result.total_fee * 3000 / 10_000;
        assert!((result.protocol_fee as i64 - expected_protocol as i64).unsigned_abs() <= 1);
    }

    #[test]
    fn test_invariant_preservation() {
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };

        let btc_bal = 5_000_000u64;
        let ckbtc_bal = 5_000_000u64;
        let input = 500_000u64;
        let amp = 200u128;

        let d_before = compute_d(btc_bal as u128, ckbtc_bal as u128, amp).unwrap();

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        let new_btc = btc_bal as u128 + input as u128;
        let new_ckbtc = ckbtc_bal as u128 - result.output_amount as u128;
        let d_after = compute_d(new_btc, new_ckbtc, amp).unwrap();

        // With no fees and integer rounding, D should be preserved within small tolerance
        let diff = if d_after > d_before { d_after - d_before } else { d_before - d_after };
        assert!(diff <= 2, "D changed by {}: before={}, after={}", diff, d_before, d_after);
    }

    #[test]
    fn test_zero_input() {
        let config = default_config();
        let result = get_swap_output(&config, 1_000_000, 1_000_000, 0, &SwapDirection::BtcToCkbtc);
        assert_eq!(result, Err(StableSwapError::ZeroInput));
    }

    #[test]
    fn test_empty_pool() {
        let config = default_config();
        let result = get_swap_output(&config, 0, 0, 1000, &SwapDirection::BtcToCkbtc);
        assert_eq!(result, Err(StableSwapError::EmptyPool));
    }

    #[test]
    fn test_get_swap_input_basic() {
        let config = default_config();
        let btc_bal = 10_000_000u64;
        let ckbtc_bal = 10_000_000u64;
        let desired_output = 100_000u64;

        let result = get_swap_input(
            &config, btc_bal, ckbtc_bal, desired_output, &SwapDirection::CkbtcToBtc,
        ).unwrap();

        // For CkbtcToBtc: user sends ckBTC, wants BTC
        // Required input should be slightly more than desired output (due to fees)
        assert!(result.output_amount > desired_output);
        assert!(result.total_fee > 0);
    }

    #[test]
    fn test_get_swap_input_zero() {
        let config = default_config();
        let result = get_swap_input(&config, 1_000_000, 1_000_000, 0, &SwapDirection::CkbtcToBtc);
        assert_eq!(result, Err(StableSwapError::ZeroInput));
    }

    #[test]
    fn test_get_swap_input_exceeds_pool() {
        let config = default_config();
        let result = get_swap_input(
            &config, 1_000_000, 1_000_000, 2_000_000, &SwapDirection::CkbtcToBtc,
        );
        assert_eq!(result, Err(StableSwapError::InputTooLarge));
    }

    #[test]
    fn test_large_pool() {
        // Test with realistic pool size: 21 BTC each side
        let config = default_config();
        let btc_bal = 2_100_000_000u64; // 21 BTC
        let ckbtc_bal = 2_100_000_000u64;
        let input = 100_000_000u64; // 1 BTC

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Should be close to 1:1 for balanced pool
        assert!(result.output_amount > 99_000_000); // > 0.99 BTC
        assert!(result.output_amount < 100_000_000); // < 1.0 BTC (fees)
    }

    #[test]
    fn test_symmetry() {
        // Swapping BTC→ckBTC and ckBTC→BTC with balanced pool should be symmetric
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };
        let bal = 5_000_000u64;
        let input = 100_000u64;

        let result_btc_to_ckbtc = get_swap_output(&config, bal, bal, input, &SwapDirection::BtcToCkbtc).unwrap();
        let result_ckbtc_to_btc = get_swap_output(&config, bal, bal, input, &SwapDirection::CkbtcToBtc).unwrap();

        assert_eq!(result_btc_to_ckbtc.output_amount, result_ckbtc_to_btc.output_amount);
    }

    #[test]
    fn test_high_amplification_flatter_curve() {
        let low_amp = StableSwapConfig {
            amplification: 10,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };
        let high_amp = StableSwapConfig {
            amplification: 1000,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };

        // Imbalanced pool
        let btc_bal = 2_000_000u64;
        let ckbtc_bal = 1_000_000u64;
        let input = 100_000u64;

        let result_low = get_swap_output(&low_amp, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();
        let result_high = get_swap_output(&high_amp, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Higher amplification should give closer to 1:1 (more output for same input on imbalanced pool)
        assert!(result_high.output_amount > result_low.output_amount,
            "High amp {} should give more than low amp {}", result_high.output_amount, result_low.output_amount);
    }

    // -----------------------------------------------------------------------
    // New tests: slippage check, dynamic fee, LP-price update verification
    // -----------------------------------------------------------------------

    #[test]
    fn test_max_slippage_rejects_high_impact() {
        // Imbalanced pool with tight slippage limit → should reject
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 5,      // very tight: 0.05%
            imbalance_fee_bps: 10,
            rebate_bps: 0,
        };
        // Heavily imbalanced pool
        let btc_bal = 2_000_000u64;
        let ckbtc_bal = 500_000u64;
        let input = 100_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc);
        match result {
            Err(StableSwapError::SlippageExceeded { price_impact_bps, max_slippage_bps }) => {
                assert!(price_impact_bps > 5);
                assert_eq!(max_slippage_bps, 5);
            }
            other => panic!("Expected SlippageExceeded, got {:?}", other),
        }
    }

    #[test]
    fn test_max_slippage_allows_within_limit() {
        // Balanced pool, small swap → price impact is tiny, should pass
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 50,      // 0.5% limit
            imbalance_fee_bps: 10,
            rebate_bps: 0,
        };
        let btc_bal = 10_000_000u64;
        let ckbtc_bal = 10_000_000u64;
        let input = 10_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc);
        assert!(result.is_ok(), "Should succeed within slippage limit, got {:?}", result);
        assert!(result.unwrap().price_impact_bps <= 50);
    }

    #[test]
    fn test_max_slippage_disabled_when_zero() {
        // max_slippage_bps=0 → never rejects even with huge impact
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 0,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,       // disabled
            imbalance_fee_bps: 0,
            rebate_bps: 0,
        };
        // Very imbalanced pool
        let btc_bal = 5_000_000u64;
        let ckbtc_bal = 100_000u64;
        let input = 200_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc);
        assert!(result.is_ok(), "Should never reject when max_slippage_bps=0, got {:?}", result);
        assert!(result.unwrap().price_impact_bps > 0);
    }

    #[test]
    fn test_dynamic_fee_increases_with_imbalance() {
        // Same config, balanced vs imbalanced pool → higher effective fee on imbalanced
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,               // 0.1% base
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,    // 1% at max imbalance
            rebate_bps: 0,
        };

        // Balanced pool
        let result_balanced = get_swap_output(
            &config, 5_000_000, 5_000_000, 100_000, &SwapDirection::BtcToCkbtc,
        ).unwrap();

        // Imbalanced pool (same total liquidity)
        let result_imbalanced = get_swap_output(
            &config, 8_000_000, 2_000_000, 100_000, &SwapDirection::BtcToCkbtc,
        ).unwrap();

        // Imbalanced pool should charge higher fees
        assert!(result_imbalanced.total_fee > result_balanced.total_fee,
            "Imbalanced fee {} should be > balanced fee {}", result_imbalanced.total_fee, result_balanced.total_fee);
    }

    #[test]
    fn test_dynamic_fee_uses_base_fee_when_balanced() {
        // Balanced pool should use exactly fee_bps, not imbalance_fee_bps
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 500,    // very high at max imbalance
            rebate_bps: 0,
        };

        let effective = compute_effective_fee_bps(&config, 1_000_000, 1_000_000);
        assert_eq!(effective, 10, "Balanced pool should use base fee_bps");
    }

    #[test]
    fn test_no_dynamic_fee_when_equal() {
        // imbalance_fee_bps == fee_bps → no dynamic effect regardless of pool balance
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 30,     // same as fee_bps
            rebate_bps: 0,
        };

        let effective_balanced = compute_effective_fee_bps(&config, 5_000_000, 5_000_000);
        let effective_imbalanced = compute_effective_fee_bps(&config, 9_000_000, 1_000_000);
        assert_eq!(effective_balanced, 30);
        assert_eq!(effective_imbalanced, 30);
    }

    #[test]
    fn test_get_swap_input_with_dynamic_fee() {
        // Reverse computation should work correctly with dynamic fees
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 50,
            rebate_bps: 0,
        };
        let btc_bal = 5_000_000u64;
        let ckbtc_bal = 5_000_000u64;
        let desired_output = 100_000u64;

        let result = get_swap_input(
            &config, btc_bal, ckbtc_bal, desired_output, &SwapDirection::CkbtcToBtc,
        );
        assert!(result.is_ok(), "get_swap_input with dynamic fee should succeed, got {:?}", result);
        let r = result.unwrap();
        // Required input should be more than desired output (fees + curve)
        assert!(r.output_amount > desired_output);
        assert!(r.total_fee > 0);
    }

    #[test]
    fn test_prices_update_after_lp_changes() {
        // Different pool balances should produce different quotes.
        // Use a config without dynamic fee to isolate AMM curve behavior.
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,       // disabled for this test
            imbalance_fee_bps: 10,     // same as fee_bps → no dynamic effect
            rebate_bps: 0,
        };
        let input = 10_000u64;

        // Pool state A: balanced 1M/1M
        let result_a = get_swap_output(&config, 1_000_000, 1_000_000, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Pool state B: after ckBTC deposit (1M BTC / 2M ckBTC)
        let result_b = get_swap_output(&config, 1_000_000, 2_000_000, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Pool state C: after ckBTC withdrawal (1M BTC / 500k ckBTC)
        let result_c = get_swap_output(&config, 1_000_000, 500_000, input, &SwapDirection::BtcToCkbtc).unwrap();

        // All three should give different outputs
        assert_ne!(result_a.output_amount, result_b.output_amount,
            "Quote should change after ckBTC deposit");
        assert_ne!(result_a.output_amount, result_c.output_amount,
            "Quote should change after ckBTC withdrawal");
        assert_ne!(result_b.output_amount, result_c.output_amount,
            "Different pool states should give different quotes");

        // More ckBTC available → better rate for BtcToCkbtc
        assert!(result_b.output_amount > result_a.output_amount,
            "More ckBTC should give better BTC→ckBTC rate");
        // Less ckBTC available → worse rate for BtcToCkbtc
        assert!(result_c.output_amount < result_a.output_amount,
            "Less ckBTC should give worse BTC→ckBTC rate");
    }

    #[test]
    fn test_compute_effective_fee_bps() {
        // Direct unit tests of the helper function
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 110,     // 1.1% at max imbalance
            rebate_bps: 0,
        };

        // Balanced: effective = fee_bps = 10
        assert_eq!(compute_effective_fee_bps(&config, 1_000, 1_000), 10);

        // Fully imbalanced (one side zero): x=1000, y=0 → sum=1000, diff=1000
        // effective = 10 + 100 * 1000/1000 = 110
        assert_eq!(compute_effective_fee_bps(&config, 1_000, 0), 110);

        // Half imbalanced: x=1500, y=500 → diff=1000, sum=2000
        // effective = 10 + 100 * 1000/2000 = 10 + 50 = 60
        assert_eq!(compute_effective_fee_bps(&config, 1_500, 500), 60);

        // 80/20 split: x=800, y=200 → diff=600, sum=1000
        // effective = 10 + 100 * 600/1000 = 10 + 60 = 70
        assert_eq!(compute_effective_fee_bps(&config, 800, 200), 70);

        // Both zero: returns base fee
        assert_eq!(compute_effective_fee_bps(&config, 0, 0), 10);

        // imbalance_fee_bps < fee_bps: returns base fee regardless
        let config_no_dynamic = StableSwapConfig {
            amplification: 200,
            fee_bps: 50,
            protocol_fee_share_bps: 0,
            max_slippage_bps: 0,
            imbalance_fee_bps: 30,     // less than fee_bps
            rebate_bps: 0,
        };
        assert_eq!(compute_effective_fee_bps(&config_no_dynamic, 9_000, 1_000), 50);
    }

    // -----------------------------------------------------------------------
    // Rebate tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_rebate_rebalancing_swap_gets_bonus() {
        // Pool is heavily imbalanced: lots of ckBTC, very little BTC
        // Large swap BTC → ckBTC that significantly rebalances the pool
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 10,               // 0.1% base fee
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,            // 0.2% max rebate
        };

        // Very imbalanced: 100k BTC / 2M ckBTC
        // A large swap that strongly rebalances
        let btc_bal = 100_000u64;
        let ckbtc_bal = 2_000_000u64;
        let input = 900_000u64; // huge rebalance — brings pool close to 1M/1M

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // With a strong rebalancing swap, the improvement ratio should be high enough
        // to push effective_fee negative, resulting in a rebate
        assert!(result.rebate_amount > 0,
            "Strong rebalancing swap should get rebate, got rebate_amount={}", result.rebate_amount);
        // Fees should be zero when rebate is active
        assert_eq!(result.total_fee, 0, "No fee when rebate is active");
        assert_eq!(result.protocol_fee, 0);
        assert_eq!(result.lp_fee, 0);
    }

    #[test]
    fn test_rebate_imbalancing_swap_gets_higher_fee() {
        // Pool is imbalanced: lots of ckBTC, less BTC
        // Swapping ckBTC → BTC (adding to oversupplied ckBTC side) should get higher fee
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,
        };

        // Imbalanced: 500k BTC / 2M ckBTC
        let btc_bal = 500_000u64;
        let ckbtc_bal = 2_000_000u64;
        let input = 100_000u64;

        // ckBTC → BTC: making imbalance worse
        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::CkbtcToBtc).unwrap();

        // Should have positive fee (no rebate)
        assert!(result.total_fee > 0, "Imbalancing swap should have fee");
        assert_eq!(result.rebate_amount, 0, "No rebate for imbalancing swap");
        // Fee should be higher than base fee (30 bps on input)
        let base_fee_approx = input as u64 * 30 / 10_000;
        assert!(result.total_fee > base_fee_approx,
            "Fee {} should be > base fee {}", result.total_fee, base_fee_approx);
    }

    #[test]
    fn test_rebate_balanced_pool_gets_base_fee() {
        // Balanced pool — swap makes it slightly imbalanced, should get base fee
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,
        };

        // Balanced: 5M / 5M
        let btc_bal = 5_000_000u64;
        let ckbtc_bal = 5_000_000u64;
        let input = 100_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Balanced → any swap makes it slightly imbalanced → should get positive fee
        assert!(result.total_fee > 0, "Balanced pool swap should have positive fee");
        assert_eq!(result.rebate_amount, 0, "No rebate when pool starts balanced");
    }

    #[test]
    fn test_rebate_disabled_when_zero() {
        // rebate_bps = 0 → no rebate even for rebalancing swaps
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 0,            // disabled
        };

        // Imbalanced: 500k BTC / 2M ckBTC, swap BTC → ckBTC (rebalancing)
        let btc_bal = 500_000u64;
        let ckbtc_bal = 2_000_000u64;
        let input = 100_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc).unwrap();

        // Should have positive fee even though swap rebalances
        assert!(result.total_fee > 0, "Should charge fee when rebate disabled");
        assert_eq!(result.rebate_amount, 0, "No rebate when rebate_bps=0");
    }

    #[test]
    fn test_rebate_overshoot_partial_improvement() {
        // Swap that overshoots balance (starts imbalanced one way, ends imbalanced the other)
        // Should still get partial rebate based on improvement
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,
        };

        // Heavily imbalanced: 200k BTC / 2M ckBTC
        let btc_bal = 200_000u64;
        let ckbtc_bal = 2_000_000u64;

        // Large swap that will overshoot and make BTC > ckBTC
        // With enough input to cross the balance point
        let input = 1_500_000u64;

        let result = get_swap_output(&config, btc_bal, ckbtc_bal, input, &SwapDirection::BtcToCkbtc);
        // Should succeed regardless (may or may not have rebate depending on net improvement)
        assert!(result.is_ok(), "Overshoot swap should succeed, got {:?}", result);
    }

    #[test]
    fn test_get_swap_input_with_rebate() {
        // Reverse computation should work with rebate — should require LESS input
        let config_with_rebate = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,
        };
        let config_no_rebate = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 0,
        };

        // Imbalanced: 500k BTC / 2M ckBTC, reverse swap BTC → ckBTC (rebalancing)
        let btc_bal = 500_000u64;
        let ckbtc_bal = 2_000_000u64;
        let desired_output = 50_000u64;

        let result_rebate = get_swap_input(
            &config_with_rebate, btc_bal, ckbtc_bal, desired_output, &SwapDirection::BtcToCkbtc,
        ).unwrap();
        let result_no_rebate = get_swap_input(
            &config_no_rebate, btc_bal, ckbtc_bal, desired_output, &SwapDirection::BtcToCkbtc,
        ).unwrap();

        // With rebate, required input should be less (user gets bonus output)
        assert!(result_rebate.output_amount <= result_no_rebate.output_amount,
            "Rebate should reduce required input: {} vs {}",
            result_rebate.output_amount, result_no_rebate.output_amount);
    }

    #[test]
    fn test_compute_effective_fee_direction_aware() {
        let config = StableSwapConfig {
            amplification: 200,
            fee_bps: 30,
            protocol_fee_share_bps: 5000,
            max_slippage_bps: 0,
            imbalance_fee_bps: 100,
            rebate_bps: 20,
        };

        // Rebalancing: pool goes from imbalanced to more balanced
        let fee_rebalance = compute_effective_fee(&config, 500, 2000, 600, 1900);
        assert!(fee_rebalance < 30,
            "Rebalancing should get fee < base ({}), got {}", 30, fee_rebalance);

        // Imbalancing: pool goes from balanced to imbalanced
        let fee_imbalance = compute_effective_fee(&config, 1000, 1000, 1100, 900);
        assert!(fee_imbalance >= 30,
            "Imbalancing should get fee >= base ({}), got {}", 30, fee_imbalance);

        // Strong rebalancing: pool goes from very imbalanced to nearly balanced
        let fee_strong = compute_effective_fee(&config, 100, 1900, 1000, 1000);
        assert!(fee_strong < 0,
            "Strong rebalancing should get negative fee (rebate), got {}", fee_strong);
        assert!(fee_strong >= -20,
            "Rebate should not exceed rebate_bps ({}), got {}", -20, fee_strong);
    }
}
