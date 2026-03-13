//  Copyright 2025 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writiing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.
use crate::helpers::id::create_identity;
use k256::sha2::{Digest, Sha256};

pub use candid::{
    Deserialize, Int, Nat, Principal,
    types::{Serializer, Type, TypeInner, TypeInner::Nat8},
};
use cklightning::ic_types::{
    Funding, FundingLPQuery, L1Account, PoolAsset, PoolFunding, PoolWithdrawal,
};
use cklightning::receiver::icrc3value_map_to_transaction;
use ic_agent::AgentError;
use ic_agent::Identity;

use ic_ledger_types::{AccountIdentifier, Subaccount};
use num_traits::cast::ToPrimitive;
mod helpers;
use candid::{Decode, Encode};
use helpers::agent::{ICAgent, TransferIcrc1};
use helpers::id::{
    BTC_LEDGER_DEFAULT_FEE, BTC_LEDGER_ID, CKLIGHTNING_LEDGER_ID, PEM_NODE_ACC_PATH,
    PEM_USER_ACC_PATH, str_home_from_path,
};
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferError;

async fn create_and_check_client(pem_path: Option<&str>) -> Result<(), AgentError> {
    let client = ICAgent::new_from_pem_file(pem_path.map(str_home_from_path))?;
    client.fetch_root_key().await?;
    client.agent.status().await?;
    Ok(())
}

async fn get_balance(
    client: &ICAgent,
    ledger_id: &Principal,
    owner: Principal,
) -> Result<Nat, AgentError> {
    let resp = client
        .agent
        .query(ledger_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;
    let balance_opt = Decode!(&resp, Option<Nat>).unwrap();
    Ok(balance_opt.unwrap_or_else(|| Nat(0u64.into())))
}

#[tokio::test]
async fn test_ckbtc_balance_node_and_user() -> Result<(), AgentError> {
    let nat_amount = Nat(10000u64.into());
    println!("\nTransfer {nat_amount:?} msat from Lightning node to Lightning user\n");

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let ledger_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

    // Load identities
    let usr_node_pr = create_identity(Some(&str_home_from_path(PEM_NODE_ACC_PATH)))
        .sender()
        .unwrap();
    let usr_user_pr = create_identity(Some(&str_home_from_path(PEM_USER_ACC_PATH)))
        .sender()
        .unwrap();

    // Fetch balances before transfer
    let balance_node_before = get_balance(&client, &ledger_id, usr_node_pr).await?;
    let balance_user_before = get_balance(&client, &ledger_id, usr_user_pr).await?;

    println!("Balance of node before tx: {balance_node_before:?}");
    println!("Balance of user before tx: {balance_user_before:?}");

    let tx_args = TransferIcrc1 {
        from: Account {
            owner: usr_node_pr,
            subaccount: None,
        },
        to: Account {
            owner: usr_user_pr,
            subaccount: None,
        },
        amount: nat_amount,
        fee: 1000u64.into(),
        memo: 0u64.to_be_bytes().to_vec(),
        created_at_time: None,
    };

    // Perform the transfer
    let transfer_resp = client
        .agent
        .update(&ledger_id, "icrc1_transfer")
        .with_arg(Encode!(&tx_args).unwrap())
        .call_and_wait()
        .await?;

    let transfer_result = Decode!(&transfer_resp, Result<Nat, TransferError>).unwrap();
    println!("Transfer result: {transfer_result:?}");

    // Fetch balances after transfer
    let balance_node_after = get_balance(&client, &ledger_id, usr_node_pr).await?;
    let balance_user_after = get_balance(&client, &ledger_id, usr_user_pr).await?;

    println!("Balance of node after tx: {balance_node_after:?}");
    println!("Balance of user after tx: {balance_user_after:?}");

    Ok(())
}

#[tokio::test]
async fn test_ic_minter_client_creation() -> Result<(), AgentError> {
    create_and_check_client(None).await
}

#[tokio::test]
async fn test_ic_user_client_creation() -> Result<(), AgentError> {
    create_and_check_client(Some(PEM_USER_ACC_PATH)).await
}

#[tokio::test]
async fn test_ic_operator_client_creation() -> Result<(), AgentError> {
    create_and_check_client(Some(PEM_NODE_ACC_PATH)).await
}

#[tokio::test]
async fn test_ckbtc_deposit_lp_with_auth_cklightning_contract() -> Result<(), AgentError> {
    let amount_u64 = 10000u64 + 2 * BTC_LEDGER_DEFAULT_FEE;
    let nat_amount = Nat(amount_u64.into());

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID).unwrap();
    println!("\nckLightning Ledger Canister ID: {can_ckl_id:?}");
    let str_user = str_home_from_path(PEM_USER_ACC_PATH);
    let usr_user_id = create_identity(Some(&str_user));

    let usr_user_pr = usr_user_id.sender().unwrap();
    println!("\nUser Principal: {usr_user_pr:?}");

    let zero_subaccount = Subaccount([0; 32]);

    let usr_acc_id = AccountIdentifier::new(&usr_user_pr, &zero_subaccount);
    println!("\nUser Account ID: {usr_acc_id:?}");

    // Query user's ckBTC balance

    let resp_user_balance = client
        .icrc1_balance_of(usr_user_pr)
        .await
        .map_err(|e| AgentError::MessageError(format!("Failed to get user balance: {e}")))?;
    let resp_contract_balance = client
        .icrc1_balance_of(can_ckl_id)
        .await
        .map_err(|e| AgentError::MessageError(format!("Failed to get contract balance: {e}")))?;

    println!("\nUser ckBTC Balance in Wallet: {resp_user_balance:?}");
    println!("\nContract ckBTC Balance: {resp_contract_balance:?}");

    let funding_pool = PoolFunding {
        pubkey_l1: client.signer.public_key().unwrap(),
        depositor: L1Account(usr_user_pr),
        asset: PoolAsset::CkBTC,
        timestamp: 0,
    };

    let funding = Funding::Pool(funding_pool.clone());
    let memo_transfer_bytes = funding.memo().0.to_vec();

    println!("\nMemo for transfer: {memo_transfer_bytes:?}");

    let transfer_some_tx_decoded = client
        .tx_icrc1_transfer(
            can_ckl_id,
            usr_user_pr,
            amount_u64,
            memo_transfer_bytes,
        )
        .await
        .map_err(|e| AgentError::MessageError(format!("Failed to get user balance: {e}")))?;

    println!("\nUser -> ckLightning icrc1_transfer in Block: {transfer_some_tx_decoded:?} with amount: {nat_amount:?}");

    let block_idx = transfer_some_tx_decoded.clone();

    let resp_contract_balance2 = client.icrc1_balance_of(can_ckl_id).await.map_err(|e| {
        AgentError::MessageError(format!("Failed to get contract balance after transfer: {e}"))
    })?;
    println!("\nContract ckBTC Balance after transfer: {resp_contract_balance2:?}");

    //query blocks

    let blocks_result = client
        .query_block(BTC_LEDGER_ID, block_idx)
        .await
        .map_err(|e| AgentError::MessageError(format!("Failed to query block: {e}")))?;

    println!("\nQueried Block ID from BTC Ledger: {blocks_result:?}");

    let first_block = blocks_result
        .blocks
        .first()
        .ok_or_else(|| AgentError::MessageError("No blocks found in query result".into()))?;

    if let ICRC3Value::Map(block_map) = &first_block.block {
        let timestamp_opt = match block_map.get("ts") {
            Some(ICRC3Value::Nat(nat)) => Some(nat.0.to_u64().unwrap_or_default()),
            _ => None,
        };

        let tx_map = block_map
            .get("tx")
            .ok_or_else(|| AgentError::MessageError("No 'tx' field found in block map".into()))?;

        if let ICRC3Value::Map(tx_map) = tx_map {
            icrc3value_map_to_transaction(tx_map, timestamp_opt).map_err(|e| {
                AgentError::MessageError(format!("Failed to decode transaction: {e}"))
            })?;
        } else {
            return Err(AgentError::MessageError(
                "'tx' field in block map is not a Map".into(),
            ));
        }
    } else {
        return Err(AgentError::MessageError(
            "Block candid value is not a Map".into(),
        ));
    }
    // Notify contract of receipt
    let block = transfer_some_tx_decoded.clone();
    let blocku64 = block.0.to_u64_digits()[0];

    client
        .transaction_notification(funding.clone(), blocku64, amount_u64)
        .await
        .map(|amount| println!("Notification Result OK: {amount:?}"))
        .map_err(|e| AgentError::MessageError(format!("Notification error: {e}")))?;

    let funding_deserialized = Encode!(&funding.clone()).unwrap();
    let funding_hash = Sha256::digest(&funding_deserialized);

    let signed_funding = client.signer.sign_arbitrary(&funding_hash);
    let res_sig = signed_funding.clone().unwrap();
    let sig_bytes = res_sig.signature.unwrap();
    let resp_contract_deposit = client.deposit(funding.clone(), sig_bytes).await;

    println!("\nDeposit Response: {resp_contract_deposit:?}");

    // Query user's balance after deposit

    let resp_user_after_tx = client.icrc1_balance_of(usr_user_pr).await.map_err(|e| {
        AgentError::MessageError(format!("Failed to get user balance after deposit: {e}"))
    })?;

    println!("\nUser ckBTC balance after deposit: {resp_user_after_tx:?}");

    let funding_lp_query = FundingLPQuery {
        asset: PoolAsset::CkBTC,
        pubkey_l1: client.signer.public_key().unwrap(),
        address: L1Account(usr_user_pr),
    };

    let sig_funding_lp_query = {
        let funding_deserialized = Encode!(&funding_lp_query.clone()).unwrap();
        let hash = Sha256::digest(&funding_deserialized);
        let signed_funding = client.signer.sign_arbitrary(&hash);
        let res_sig = signed_funding.clone().unwrap();
        res_sig.signature.unwrap()
    };

    let user_contract_balance_after = client
        .query_user_lp_holdings(funding_lp_query.clone(), sig_funding_lp_query)
        .await
        .map_err(|e| {
            AgentError::MessageError(format!("Failed to query user LP holdings: {e}"))
        })?;

    println!("\nUser contract balance after deposit: {user_contract_balance_after:?}");

    // User balance before withdrawal

    let user_balance_before_withdrawal =
        client.icrc1_balance_of(usr_user_pr).await.map_err(|e| {
            AgentError::MessageError(format!(
                "Failed to get user balance before withdrawal: {e}"
            ))
        })?;

    println!("User ckBTC balance before withdrawal: {user_balance_before_withdrawal:?}");

    // // Trigger withdraw

    ////////////////////// new from here with auth ///////////////////////

    let pubkey = client.signer.public_key().unwrap();

    let pr = client.agent.get_principal().unwrap();

    let pool_withdrawal = PoolWithdrawal {
        amount: Nat(200u64.into()),
        asset: PoolAsset::CkBTC,
        depositor: L1Account(pr),
        pubkey_l1: pubkey,
    };

    let sig_pool_withdrawal = {
        let pw_deserialized = Encode!(&pool_withdrawal).unwrap();
        let withdrawal_hash = Sha256::digest(&pw_deserialized);
        let signed_pw = client.signer.sign_arbitrary(&withdrawal_hash);
        let res_pw_sig = signed_pw.clone().unwrap();
        res_pw_sig.signature.unwrap()
    };

    let withdraw_lp_tx = client
        .withdraw_lp(pool_withdrawal.clone(), sig_pool_withdrawal, usr_user_pr)
        .await
        .map_err(|e| AgentError::MessageError(format!("Failed to trigger LP withdrawal: {e}")))?;

    println!("withdraw_lp_tx decoded: {withdraw_lp_tx:?}");

    let resp_user_after_withdrawal = client.icrc1_balance_of(usr_user_pr).await.map_err(|e| {
        AgentError::MessageError(format!("Failed to get user balance after withdrawal: {e}"))
    })?;

    println!("\nUser's ckBTC balance after withdrawal: {resp_user_after_withdrawal:?}");

    // Final contract holdings
    let funding_lp_query = FundingLPQuery {
        asset: PoolAsset::CkBTC,
        pubkey_l1: client.signer.public_key().unwrap(),
        address: L1Account(usr_user_pr),
    };

    let sig_funding_lp_query = {
        let funding_deserialized = Encode!(&funding_lp_query.clone()).unwrap();
        let hash = Sha256::digest(&funding_deserialized);
        let signed_funding = client.signer.sign_arbitrary(&hash);
        let res_sig = signed_funding.clone().unwrap();
        res_sig.signature.unwrap()
    };
    let resp_user_after_withdrawal_query_tx = client
        .query_user_lp_holdings(funding_lp_query.clone(), sig_funding_lp_query)
        .await
        .map_err(|e| {
            AgentError::MessageError(format!(
                "Failed to query user LP holdings after withdrawal: {e}"
            ))
        })?;

    println!("\nFinal User holdings in Contract: {resp_user_after_withdrawal_query_tx:?}");

    let resp_contract_final_query_tx = client.icrc1_balance_of(can_ckl_id).await.map_err(|e| {
        AgentError::MessageError(format!("Failed to get final contract balance: {e}"))
    })?;

    println!("Contract final ckBTC Balance in ckLightning Canister: {resp_contract_final_query_tx:?}");

    Ok(())
}
