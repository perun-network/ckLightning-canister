use crate::helpers::id::create_identity;
pub use candid::{
    Deserialize, Int, Nat, Principal,
    types::{Serializer, Type, TypeInner, TypeInner::Nat8},
};
use ic_agent::AgentError;
mod helpers;
use crate::helpers::agent::ChannelId;
use crate::helpers::agent::Funding;
use crate::helpers::agent::L2Account;
use candid::{Decode, Encode};
use helpers::agent::{Account, ICAgent, TransferIcrc1};
use helpers::id::{
    BTC_LEDGER_DEFAULT_FEE, BTC_LEDGER_ID, CKLIGHTNING_LEDGER_ID, PEM_NODE_ACC_PATH,
    PEM_USER_ACC_PATH, create_keypair, str_home_from_path,
};
use ic_agent::Identity;
use icrc_ledger_types::icrc1::transfer::TransferError;

#[tokio::test]

async fn test_ic_minter_client_creation() -> Result<(), AgentError> {
    let client = ICAgent::new_from_pem_file(None)?;
    client.fetch_root_key().await?;
    client.agent.status().await?;
    Ok(())
}
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
        memo: 1u64, //Some(0u64.to_be_bytes().to_vec()),
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

    let (sk, pk) = create_keypair();

    let funding = Funding {
        channel: ChannelId([0; 32]), // Use a dummy channel ID for this test
        participant: L2Account(pk.clone()),
    };

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
        memo: 1u64, //Some(0u64.to_be_bytes().to_vec()),
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

    let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID).unwrap();

    let str_user = str_home_from_path(PEM_USER_ACC_PATH);
    let usr_user_id = create_identity(Some(&str_user));

    // let usr_user_id = id::create_identity(Some(&id::str_home_from_path(PEM_USER_ACC_PATH)));
    let usr_user_pr = usr_user_id.sender().unwrap();

    // Query user's ckBTC balance

    let resp_user_balance_result = client.icrc1_balance_of(usr_user_pr).await;
    let resp_contract_balance_result = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance = resp_contract_balance_result.unwrap();

    let resp_user_balance = resp_user_balance_result.unwrap();

    println!("\nUser ckBTC Balance in Wallet: {:?}", resp_user_balance);
    println!("\nContract ckBTC Balance: {:?}", resp_contract_balance);

    // Prepare funding and deposit to contract
    let (_, pk) = create_keypair();
    let funding = Funding {
        channel: ChannelId([0; 32]),
        participant: L2Account(pk.clone()),
    };

    let resp_user_before_deposit_query_tx = client.query_contract_holdings(funding.clone()).await;

    let resp_user_before_deposit_tx = resp_user_before_deposit_query_tx.unwrap();

    println!(
        "\nUser ckBTC Balance in ckLightning Canister: {:?}",
        resp_user_before_deposit_tx
    );

    let memo_transfer = funding.memo();

    let transfer_some_tx_decoded = client
        .tx_icrc1_transfer(can_ckl_id, usr_user_pr, amount_u64.clone(), memo_transfer)
        .await
        .map_err(|e| format!("Failed to get user balance: {}", e));

    println!(
        "\nUser -> ckLightning icrc1_transfer in Block: {:?} with amount: {:?}",
        transfer_some_tx_decoded.clone().unwrap(),
        nat_amount.clone()
    );

    let resp_contract_balance_result2 = client.icrc1_balance_of(can_ckl_id).await;
    let resp_contract_balance2 = resp_contract_balance_result2.unwrap();
    println!(
        "\nContract ckBTC Balance after transfer: {:?}",
        resp_contract_balance2
    );

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
            println!("Notification error: {:?}", e); // <-- THIS IS THE ERR
        }
    }

    // println!(
    //     "\nNotification Result of User Deposit to Contract: {:?}",
    //     tx_notification_result.unwrap()
    // );

    let resp_contract_deposit = client.deposit(funding.clone()).await;

    println!("Deposit Response: {:?}", resp_contract_deposit);

    // Query user's balance after deposit

    let resp_user_after_tx = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser ckBTC balance after deposit: {:?}",
        resp_user_after_tx.unwrap()
    );

    let user_contract_balance_after = client.query_contract_holdings(funding.clone()).await;

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

    let trigger_withdraw_tx = client
        .trigger_withdraw(200u64.into(), funding.clone(), usr_user_pr)
        .await;

    println!("trigger_withdraw tx decoded: {:?}", trigger_withdraw_tx);

    let resp_user_after_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

    println!(
        "\nUser's ckBTC balance after withdrawal: {:?}",
        resp_user_after_withdrawal
    );

    // Final contract holdings

    let resp_user_after_withdrawal_query_tx = client.query_contract_holdings(funding.clone()).await;

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
