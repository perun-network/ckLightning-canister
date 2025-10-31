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
    ChannelFunding, ChannelId, Funding, FundingLPQuery, L1Account, L2Account, PoolAsset,
    PoolFunding, PoolWithdrawal,
};
use cklightning::receiver::icrc3value_map_to_transaction;
use ic_agent::AgentError;
use ic_agent::Identity;

use ic_ledger_types::{AccountIdentifier, Subaccount};
use num_traits::cast::ToPrimitive;
mod helpers;
// use crate::helpers::agent::ChannelId;
// use crate::helpers::agent::Funding;
// use crate::helpers::agent::L2Account;
use candid::{Decode, Encode};
use helpers::agent::{ICAgent, TransferIcrc1};
use helpers::id::{
    BTC_LEDGER_DEFAULT_FEE, BTC_LEDGER_ID, CKLIGHTNING_LEDGER_ID, PEM_NODE_ACC_PATH,
    PEM_USER_ACC_PATH, create_keypair, str_home_from_path,
};
// use ic_agent::Identity;
use icrc_ledger_types::icrc::generic_value::ICRC3Value;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferError;
#[tokio::test]

async fn test_ic_minter_client_creation() -> Result<(), AgentError> {
    let client = ICAgent::new_from_pem_file(None)?;
    client.fetch_root_key().await?;
    client.agent.status().await?;
    Ok(())
}

// #[tokio::test]
// async fn test_ic_user_client_creation() -> Result<(), AgentError> {
//     let str_home = id::str_home_from_path(PEM_USER_ACC_PATH); // returns String
//     let client = ICAgent::new_from_pem_file(Some(str_home))?;
//     client.fetch_root_key().await?;
//     client.agent.status().await?;
//     Ok(())
// }

// #[tokio::test]
// async fn test_ic_operator_client_creation() -> Result<(), AgentError> {
//     let str_home = id::str_home_from_path(PEM_NODE_ACC_PATH);
//     let client = ICAgent::new_from_pem_file(Some(str_home))?;
//     client.fetch_root_key().await?;
//     client.agent.status().await?;

//     Ok(())
// }

// #[tokio::test]

// async fn test_ic_minter_client_creation() -> Result<(), AgentError> {
//     let client = ICAgent::new_from_pem_file(None)?;
//     client.fetch_root_key().await?;
//     client.agent.status().await?;
//     Ok(())
// }
#[tokio::test]
async fn test_ic_user_client_creation() -> Result<(), AgentError> {
    let str_home = str_home_from_path(PEM_USER_ACC_PATH);
    let client = ICAgent::new_from_pem_file(Some(str_home))?;
    client.fetch_root_key().await?;
    client.agent.status().await?;

    Ok(())
}

#[tokio::test]
async fn test_ic_operator_client_creation() -> Result<(), AgentError> {
    let str_home = str_home_from_path(PEM_NODE_ACC_PATH);
    let client = ICAgent::new_from_pem_file(Some(str_home))?;
    client.fetch_root_key().await?;
    client.agent.status().await?;

    Ok(())
}

#[tokio::test]
async fn test_ckbtc_balance_lnpd_l1() -> Result<(), AgentError> {
    let nat_amount = Nat(5000u64.into());

    println!(
        "\nTransfer {:?} msat from Lightning user to Lightning node\n",
        nat_amount
    );

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

    let str_node = str_home_from_path(PEM_NODE_ACC_PATH);
    let str_user = str_home_from_path(PEM_USER_ACC_PATH);

    let usr_node_id = create_identity(Some(&str_node));
    let usr_user_id = create_identity(Some(&str_user));

    let usr_node_pr = usr_node_id.sender().unwrap();
    let usr_user_pr = usr_user_id.sender().unwrap();

    let resp_node = client
        .agent
        .query(&can_btcldg_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_node_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;

    let resp_user = client
        .agent
        .query(&can_btcldg_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_user_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;

    let res_user = Decode!(&resp_user, Option<Nat>).unwrap();
    let res_node = Decode!(&resp_node, Option<Nat>).unwrap();

    println!("Balance of node before tx: {:?}", res_node.unwrap());
    println!("Balance of user before tx: {:?}", res_user.unwrap());

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
        fee: 10u64.into(),
        memo: 0u64.to_be_bytes().to_vec(),
        created_at_time: None,
    };

    let transfer_some_tx = client
        .agent
        .update(&can_btcldg_id, "icrc1_transfer")
        .with_arg(Encode!(&tx_args).unwrap())
        .call_and_wait()
        .await?;

    let resp_user_after_tx = client
        .agent
        .query(&can_btcldg_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_user_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;

    let resp_user_after_tx_dec = Decode!(&resp_user_after_tx, Option<Nat>).unwrap();

    let resp_node_after_tx = client
        .agent
        .query(&can_btcldg_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_node_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;
    let resp_node_after_tx_dec = Decode!(&resp_node_after_tx, Option<Nat>).unwrap();

    println!(
        "Balance of node after tx: {:?}",
        resp_node_after_tx_dec.unwrap()
    );
    println!(
        "Balance of user after tx: {:?}",
        resp_user_after_tx_dec.unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_ckbtc_balance_cklightning_l1() -> Result<(), AgentError> {
    let nat_amount = Nat(10000u64.into());

    println!(
        "\nTransfer {:?} msat from Lightning user to Lightning node\n",
        nat_amount
    );

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let can_ckl_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

    let str_user = str_home_from_path(PEM_USER_ACC_PATH);
    let usr_user_id = create_identity(Some(&str_user));

    let usr_user_pr = usr_user_id.sender().unwrap();

    let (signingkey, verifyingkey) = create_keypair();

    let pk: k256::PublicKey = verifyingkey.into(); // Convert VerifyingKey to PublicKey

    let channel_funding = ChannelFunding {
        channel: ChannelId([0; 32]),
        participant: L2Account(pk.clone()),
    };

    let funding = Funding::Channel(channel_funding.clone());
    // let funding = Funding::Channel(channel_funding.clone());

    // let funding = Funding {
    //     channel: ChannelId([0; 32]), // Use a dummy channel ID for this test
    //     participant: L2Account(pk.clone()),
    // };

    let resp_user = client
        .agent
        .query(&can_ckl_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_user_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;

    let res_user = Decode!(&resp_user, Option<Nat>).unwrap();
    println!("Balance of user before tx: {:?}", res_user.unwrap());

    let tx_args = TransferIcrc1 {
        from: Account {
            owner: can_ckl_id,
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

    let transfer_some_tx = client
        .agent
        .update(&can_ckl_id, "icrc1_transfer")
        .with_arg(Encode!(&tx_args).unwrap())
        .call_and_wait()
        .await?;

    let transfer_some_tx_decoded = Decode!(&transfer_some_tx, Result<Nat,TransferError>).unwrap();
    println!("Transfer result: {:?}", transfer_some_tx_decoded);

    let resp_user_after_tx = client
        .agent
        .query(&can_ckl_id, "icrc1_balance_of")
        .with_arg(
            Encode!(&Account {
                owner: usr_user_pr,
                subaccount: None
            })
            .unwrap(),
        )
        .call()
        .await?;

    let resp_user_after_tx_dec = Decode!(&resp_user_after_tx, Option<Nat>).unwrap();

    println!(
        "Balance of user after tx: {:?}",
        resp_user_after_tx_dec.unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_ckbtc_deposit_cklightning_contract() -> Result<(), AgentError> {
    let mut amount_u64 = 10000u64;
    amount_u64 += 2 * BTC_LEDGER_DEFAULT_FEE;
    let nat_amount = Nat(amount_u64.into());

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    client.fetch_root_key().await?;

    // let idd = client.agent.identity();

    let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID).unwrap();
    println!("\nckLightning Ledger Canister ID: {:?}", can_ckl_id);
    let str_user = str_home_from_path(PEM_USER_ACC_PATH);
    let usr_user_id = create_identity(Some(&str_user));

    let usr_user_pr = usr_user_id.sender().unwrap();
    println!("\nUser Principal: {:?}", usr_user_pr);

    let zero_subaccount = Subaccount([0; 32]);

    let usr_acc_id = AccountIdentifier::new(&usr_user_pr, &zero_subaccount);
    println!("\nUser Account ID: {:?}", usr_acc_id);

    // Query user's ckBTC balance

    let resp_user_balance_result = client.icrc1_balance_of(usr_user_pr).await;
    let resp_contract_balance_result = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance = resp_contract_balance_result.unwrap();

    let resp_user_balance = resp_user_balance_result.unwrap();

    println!("\nUser ckBTC Balance in Wallet: {:?}", resp_user_balance);
    println!("\nContract ckBTC Balance: {:?}", resp_contract_balance);

    // Prepare funding and deposit to contract
    let (_, verifyingkey) = create_keypair();
    let pk: k256::PublicKey = verifyingkey.into(); // Convert VerifyingKey to PublicKey

    let channel_funding = ChannelFunding {
        channel: ChannelId([0; 32]),
        participant: L2Account(pk.clone()),
    };

    let funding = Funding::Channel(channel_funding.clone());

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

    let resp_user_before_deposit_query_tx = client
        .query_user_lp_holdings(funding_lp_query, sig_funding_lp_query)
        .await;

    let resp_user_before_deposit_tx = resp_user_before_deposit_query_tx.unwrap();

    println!(
        "\nUser ckBTC Balance in ckLightning Canister: {:?}",
        resp_user_before_deposit_tx
    );

    let memo_transfer = funding.memo();

    // let memo_bytes = memo_transfer.clone().to_be_bytes().to_vec();
    let memo_transfer_bytes = memo_transfer.0.to_vec(); //..clone(); //.to_be_bytes().to_vec();

    println!("\nMemo for transfer: {:?}", memo_transfer_bytes.clone());

    let transfer_some_tx_decoded = client
        .tx_icrc1_transfer(
            can_ckl_id,
            usr_user_pr,
            amount_u64.clone(),
            memo_transfer_bytes,
        )
        .await
        .map_err(|e| format!("Failed to get user balance: {}", e));

    println!(
        "\nUser -> ckLightning icrc1_transfer in Block: {:?} with amount: {:?}",
        transfer_some_tx_decoded.clone().unwrap(),
        nat_amount.clone()
    );

    let block_idx = transfer_some_tx_decoded.clone().unwrap();

    let resp_contract_balance_result2 = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance2 = resp_contract_balance_result2.unwrap();
    println!(
        "\nContract ckBTC Balance after transfer: {:?}",
        resp_contract_balance2
    );

    //query blocks

    let query_block_result = client
        .query_block(&BTC_LEDGER_ID, block_idx)
        .await
        .map_err(|e| format!("Failed to query block: {}", e));

    println!(
        "\nQueried Block ID from BTC Ledger: {:?}",
        query_block_result
    );
    if let Ok(blocks_result) = query_block_result {
        if let Some(first_block) = blocks_result.blocks.first() {
            let block_candid = &first_block.block;
            if let ICRC3Value::Map(block_map) = block_candid {
                // Extract the timestamp at the block map level as Option<u64>
                let timestamp_opt = match block_map.get("ts") {
                    Some(ICRC3Value::Nat(nat)) => Some(nat.0.to_u64().unwrap_or_default()),
                    _ => None,
                };

                if let Some(ICRC3Value::Map(tx_map)) = block_map.get("tx") {
                    match icrc3value_map_to_transaction(tx_map, timestamp_opt) {
                        Ok(tx) => println!("Decoded transaction: {:?}", tx),
                        Err(e) => eprintln!("Failed to decode transaction: {:?}", e),
                    }
                } else {
                    eprintln!("No 'tx' field found in block map");
                }
            } else {
                eprintln!("Block candid value is not a Map");
            }
        } else {
            eprintln!("No blocks found in query result");
        }
    } else {
        eprintln!("Failed to query blocks: {:?}", query_block_result);
    }

    // Notify contract of receipt
    let block = transfer_some_tx_decoded.clone().unwrap();
    let blocku64 = block.0.to_u64_digits()[0];

    let tx_notification_result = client
        .transaction_notification(funding.clone(), blocku64, amount_u64)
        .await;

    match tx_notification_result {
        Ok(amount) => {
            println!("Notification Result OK: {:?}", amount);
        }
        Err(e) => {
            println!("Notification error: {:?}", e);
        }
    }

    let funding_deserialized = Encode!(&funding.clone()).unwrap();

    let signed_funding = client.signer.sign_arbitrary(&funding_deserialized);
    let res_sig = signed_funding.clone().unwrap();
    let sig_bytes = res_sig.signature.unwrap();
    let resp_contract_deposit = client.deposit(funding.clone(), sig_bytes).await;

    println!("Deposit Response: {:?}", resp_contract_deposit);

    // Query user's balance after deposit

    let resp_user_after_tx = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser ckBTC balance after deposit: {:?}",
        resp_user_after_tx.unwrap()
    );

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
        .await;

    println!(
        "\nUser contract balance after deposit: {:?}",
        user_contract_balance_after
    );

    // User balance before withdrawal

    let user_balance_before_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "User ckBTC balance before withdrawal: {:?}",
        user_balance_before_withdrawal
    );

    // // Trigger withdraw

    // let trigger_withdraw_tx = client
    //     .trigger_withdraw(200u64.into(), funding.clone(), usr_user_pr)
    //     .await;

    // println!(
    //     "trigger_withdraw tx decoded: {:?}",
    //     trigger_withdraw_tx.unwrap()
    // );

    let resp_user_after_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser's ckBTC balance after withdrawal: {:?}",
        resp_user_after_withdrawal.unwrap()
    );

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

    // Final contract holdings

    let resp_user_after_withdrawal_query_tx = client
        .query_user_lp_holdings(funding_lp_query.clone(), sig_funding_lp_query)
        .await;

    println!(
        "\nFinal User holdings in Contract: {:?}",
        resp_user_after_withdrawal_query_tx
    );

    let resp_contract_final_query_tx = client.icrc1_balance_of(can_ckl_id).await;

    println!(
        "Contract final ckBTC Balance in ckLightning Canister: {:?}",
        resp_contract_final_query_tx.unwrap()
    );

    Ok(())
}

#[tokio::test]
async fn test_ckbtc_deposit_lp_with_auth_cklightning_contract() -> Result<(), AgentError> {
    let mut amount_u64 = 10000u64;
    amount_u64 += 2 * BTC_LEDGER_DEFAULT_FEE;
    let nat_amount = Nat(amount_u64.into());

    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID).unwrap();
    println!("\nckLightning Ledger Canister ID: {:?}", can_ckl_id);
    let str_user = str_home_from_path(PEM_USER_ACC_PATH);
    let usr_user_id = create_identity(Some(&str_user));

    let usr_user_pr = usr_user_id.sender().unwrap();
    println!("\nUser Principal: {:?}", usr_user_pr);

    let zero_subaccount = Subaccount([0; 32]);

    let usr_acc_id = AccountIdentifier::new(&usr_user_pr, &zero_subaccount);
    println!("\nUser Account ID: {:?}", usr_acc_id);

    // Query user's ckBTC balance

    let resp_user_balance_result = client.icrc1_balance_of(usr_user_pr).await;
    let resp_contract_balance_result = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance = resp_contract_balance_result.unwrap();

    let resp_user_balance = resp_user_balance_result.unwrap();

    println!("\nUser ckBTC Balance in Wallet: {:?}", resp_user_balance);
    println!("\nContract ckBTC Balance: {:?}", resp_contract_balance);

    // Prepare funding and deposit to contract
    let (_, verifyingkey) = create_keypair();
    let pk: k256::PublicKey = verifyingkey.into(); // Convert VerifyingKey to PublicKey

    let channel_funding = ChannelFunding {
        channel: ChannelId([0; 32]),
        participant: L2Account(pk.clone()),
    };

    let funding_chan = Funding::Channel(channel_funding.clone());

    let funding_pool = PoolFunding {
        pubkey_l1: client.signer.public_key().unwrap(),
        depositor: L1Account(usr_user_pr),
        asset: PoolAsset::CkBTC,
        timestamp: 0,
    };

    let funding = Funding::Pool(funding_pool.clone());

    let memo_transfer = funding.memo();

    // let memo_bytes = memo_transfer.clone().to_be_bytes().to_vec();
    let memo_transfer_bytes = memo_transfer.0.to_vec(); //..clone(); //.to_be_bytes().to_vec();

    println!("\nMemo for transfer: {:?}", memo_transfer_bytes.clone());

    let transfer_some_tx_decoded = client
        .tx_icrc1_transfer(
            can_ckl_id,
            usr_user_pr,
            amount_u64.clone(),
            memo_transfer_bytes,
        )
        .await
        .map_err(|e| format!("Failed to get user balance: {}", e));

    println!(
        "\nUser -> ckLightning icrc1_transfer in Block: {:?} with amount: {:?}",
        transfer_some_tx_decoded.clone().unwrap(),
        nat_amount.clone()
    );

    let block_idx = transfer_some_tx_decoded.clone().unwrap();

    let resp_contract_balance_result2 = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance2 = resp_contract_balance_result2.unwrap();
    println!(
        "\nContract ckBTC Balance after transfer: {:?}",
        resp_contract_balance2
    );

    //query blocks

    let query_block_result = client
        .query_block(&BTC_LEDGER_ID, block_idx)
        .await
        .map_err(|e| format!("Failed to query block: {}", e));

    println!(
        "\nQueried Block ID from BTC Ledger: {:?}",
        query_block_result
    );
    if let Ok(blocks_result) = query_block_result {
        if let Some(first_block) = blocks_result.blocks.first() {
            let block_candid = &first_block.block;
            if let ICRC3Value::Map(block_map) = block_candid {
                // Extract the timestamp at the block map level as Option<u64>
                let timestamp_opt = match block_map.get("ts") {
                    Some(ICRC3Value::Nat(nat)) => Some(nat.0.to_u64().unwrap_or_default()),
                    _ => None,
                };

                if let Some(ICRC3Value::Map(tx_map)) = block_map.get("tx") {
                    match icrc3value_map_to_transaction(tx_map, timestamp_opt) {
                        Ok(tx) => println!("Decoded transaction: {:?}", tx),
                        Err(e) => eprintln!("Failed to decode transaction: {:?}", e),
                    }
                } else {
                    eprintln!("No 'tx' field found in block map");
                }
            } else {
                eprintln!("Block candid value is not a Map");
            }
        } else {
            eprintln!("No blocks found in query result");
        }
    } else {
        eprintln!("Failed to query blocks: {:?}", query_block_result);
    }

    // Notify contract of receipt
    let block = transfer_some_tx_decoded.clone().unwrap();
    let blocku64 = block.0.to_u64_digits()[0];

    let tx_notification_result = client
        .transaction_notification(funding.clone(), blocku64, amount_u64)
        .await;

    match tx_notification_result {
        Ok(amount) => {
            println!("Notification Result OK: {:?}", amount);
        }
        Err(e) => {
            println!("Notification error: {:?}", e);
        }
    }

    let funding_deserialized = Encode!(&funding.clone()).unwrap();
    let funding_hash = Sha256::digest(&funding_deserialized);

    let signed_funding = client.signer.sign_arbitrary(&funding_hash);
    let res_sig = signed_funding.clone().unwrap();
    let sig_bytes = res_sig.signature.unwrap();
    let resp_contract_deposit = client.deposit(funding.clone(), sig_bytes).await;

    println!("\nDeposit Response: {:?}", resp_contract_deposit);

    // Query user's balance after deposit

    let resp_user_after_tx = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser ckBTC balance after deposit: {:?}",
        resp_user_after_tx.unwrap()
    );

    let channel_funding = ChannelFunding {
        channel: ChannelId([0; 32]),
        participant: L2Account(pk.clone()),
    };

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
        .await;

    println!(
        "\nUser contract balance after deposit: {:?}",
        user_contract_balance_after
    );

    // User balance before withdrawal

    let user_balance_before_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "User ckBTC balance before withdrawal: {:?}",
        user_balance_before_withdrawal
    );

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
        .await;

    println!("withdraw_lp_tx decoded: {:?}", withdraw_lp_tx.unwrap());

    let resp_user_after_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser's ckBTC balance after withdrawal: {:?}",
        resp_user_after_withdrawal.unwrap()
    );

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
        .await;

    println!(
        "\nFinal User holdings in Contract: {:?}",
        resp_user_after_withdrawal_query_tx
    );

    let resp_contract_final_query_tx = client.icrc1_balance_of(can_ckl_id).await;

    println!(
        "Contract final ckBTC Balance in ckLightning Canister: {:?}",
        resp_contract_final_query_tx.unwrap()
    );

    Ok(())
}
