// =============================================================================
// Simplified Liquidity Pool Implementation (ckBTC)
// =============================================================================

use super::STATE;
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    CKBTC_LEDGER_PRINCIPAL, DEFAULT_CKBTC_FEE,
    LpBalanceResponse, LpDepositResponse, LpWithdrawResponse, TotalLpBalanceResponse,
};

use candid::Nat;
use ic_cdk::call::Call;
use ic_cdk::api::msg_caller;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;

/// Deposit ckBTC into the liquidity pool
///
/// The caller must have approved the canister to spend their ckBTC first via ICRC-2.
/// This function pulls ckBTC from the caller and credits their LP balance.
pub async fn deposit_ckbtc_impl(amount: Nat) -> LpDepositResponse {
    let caller = msg_caller();
    let canister_id = ic_cdk::api::canister_self();

    if amount == 0u64 {
        return LpDepositResponse {
            success: false,
            new_balance: Nat::from(0u64),
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Pull ckBTC from caller using ICRC-2 transfer_from
    let ckbtc_ledger_id = *CKBTC_LEDGER_PRINCIPAL;

    let transfer_from_args = icrc_ledger_types::icrc2::transfer_from::TransferFromArgs {
        spender_subaccount: None,
        from: Account {
            owner: caller,
            subaccount: None,
        },
        to: Account {
            owner: canister_id,
            subaccount: None,
        },
        amount: amount.clone(),
        fee: None, // Use default fee
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:lp_deposit".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(ckbtc_ledger_id, "icrc2_transfer_from")
        .with_args(&(transfer_from_args,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc2::transfer_from::TransferFromError>,)>().map_err(Into::into))
    {
        Ok((inner_result,)) => match inner_result {
            Ok(_block_index) => {
                // Credit the caller's LP balance
                let mut state = STATE.write().expect("STATE lock: deposit_ckbtc write");
                state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());

                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpDepositResponse {
                    success: true,
                    new_balance,
                    error: None,
                }
            }
            Err(e) => LpDepositResponse {
                success: false,
                new_balance: Nat::from(0u64),
                error: Some(format!("ICRC-2 transfer_from failed: {e:?}")),
            },
        },
        Err(e) => LpDepositResponse {
            success: false,
            new_balance: Nat::from(0u64),
            error: Some(format!("Canister call failed: {e}")),
        },
    }
}

/// Withdraw ckBTC from the liquidity pool
///
/// Checks the caller's LP balance and transfers ckBTC back to them.
/// Additionally, checks that the requested amount doesn't exceed available ckBTC
/// (total LP ckBTC minus ckBTC reserved for pending onramp requests).
pub async fn withdraw_ckbtc_impl(amount: Nat) -> LpWithdrawResponse {
    let caller = msg_caller();

    if amount == 0u64 {
        return LpWithdrawResponse {
            success: false,
            amount_withdrawn: Nat::from(0u64),
            new_balance: Nat::from(0u64),
            block_index: None,
            error: Some("Amount must be greater than 0".to_string()),
        };
    }

    // Check available ckBTC (not reserved for pending swaps) and deduct from LP balance
    {
        let mut state = STATE.write().expect("STATE lock: withdraw_ckbtc write");

        // Use running counter for reserved ckBTC (maintained on request create/complete/expire)
        let reserved_for_onramps = state.reserved_ckbtc_sats;

        // Calculate available ckBTC = total LP ckBTC - reserved for pending swaps
        let total_lp_ckbtc: u64 = state.liq_pool.get_total(&PoolAsset::CkBTC)
            .0.clone().try_into().unwrap_or(0);
        let available_ckbtc = total_lp_ckbtc.saturating_sub(reserved_for_onramps);

        let amount_u64: u64 = amount.0.clone().try_into().unwrap_or(u64::MAX);
        if amount_u64 > available_ckbtc {
            let current_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);
            return LpWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_balance: current_balance,
                block_index: None,
                error: Some(format!(
                    "Insufficient available ckBTC: {amount_u64} sats requested but only {available_ckbtc} sats available (total {total_lp_ckbtc} sats, {reserved_for_onramps} sats reserved for pending swaps)"
                )),
            };
        }

        if let Err(e) = state.liq_pool.withdraw(caller, PoolAsset::CkBTC, amount.clone()) {
            let current_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);
            return LpWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_balance: current_balance,
                block_index: None,
                error: Some(format!("Insufficient balance: {e:?}")),
            };
        }
    }

    // Transfer ckBTC to caller
    let ckbtc_ledger_id = *CKBTC_LEDGER_PRINCIPAL;

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: caller,
            subaccount: None,
        },
        amount: amount.clone(),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:lp_withdraw".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    match Call::unbounded_wait(ckbtc_ledger_id, "icrc1_transfer")
        .with_args(&(transfer_arg,))
        .await
        .map_err(ic_cdk::call::Error::from)
        .and_then(|r| r.candid_tuple::<(Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,)>().map_err(Into::into))
    {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                let state = STATE.read().expect("STATE lock: withdraw_ckbtc read");
                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpWithdrawResponse {
                    success: true,
                    amount_withdrawn: amount,
                    new_balance,
                    block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Transfer failed - restore the LP balance
                let mut state = STATE.write().expect("STATE lock: withdraw_ckbtc write 2");
                state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());
                let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

                LpWithdrawResponse {
                    success: false,
                    amount_withdrawn: Nat::from(0u64),
                    new_balance,
                    block_index: None,
                    error: Some(format!("ckBTC transfer failed: {e:?}")),
                }
            }
        },
        Err(e) => {
            // Call failed - restore the LP balance
            let mut state = STATE.write().expect("STATE lock: withdraw_ckbtc write 3");
            state.liq_pool.deposit(caller, PoolAsset::CkBTC, amount.clone());
            let new_balance = state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC);

            LpWithdrawResponse {
                success: false,
                amount_withdrawn: Nat::from(0u64),
                new_balance,
                block_index: None,
                error: Some(format!("Canister call failed: {e}")),
            }
        }
    }
}

/// Get the caller's LP balance
pub fn get_my_lp_balance_impl() -> LpBalanceResponse {
    let caller = msg_caller();
    let state = STATE.read().expect("STATE lock: get_my_lp_balance");

    LpBalanceResponse {
        ckbtc_balance: state.liq_pool.get_balance(&caller, &PoolAsset::CkBTC),
        btc_balance: state.liq_pool.get_balance(&caller, &PoolAsset::BTC),
    }
}

/// Get the total LP balance across all depositors
pub fn get_total_lp_balance_impl() -> TotalLpBalanceResponse {
    let state = STATE.read().expect("STATE lock: get_total_lp_balance");

    TotalLpBalanceResponse {
        total_ckbtc: state.liq_pool.get_total(&PoolAsset::CkBTC),
        total_btc: state.liq_pool.get_total(&PoolAsset::BTC),
        num_depositors: state.liq_pool.depositors.len() as u64,
    }
}
