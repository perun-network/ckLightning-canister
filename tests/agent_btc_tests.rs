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

pub use candid::{
    Deserialize, Int, Nat, Principal,
    types::{Serializer, Type, TypeInner, TypeInner::Nat8},
};
use tokio::time::{Duration, sleep};
mod helpers;
use helpers::agent::ICAgent;
use helpers::btc_commands::generate_blocks_to_address;
use helpers::id::{PEM_NODE_ACC_PATH, PEM_USER_ACC_PATH, str_home_from_path};

#[tokio::test]
async fn test_basic_bitcoin_get_balance() -> Result<(), Box<dyn std::error::Error>> {
    let user_client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    user_client.fetch_root_key().await?;
    let node_client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    node_client.fetch_root_key().await?;

    // Fetch balances before transfer

    let btc_address_user = user_client.get_own_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    let btc_address_node = node_client.get_own_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    println!(
        "BTC user  address received from canister: {:?}",
        btc_address_user
    );
    println!(
        "BTC node address received from canister: {:?}",
        btc_address_node
    );

    let btcaddrcan = "mhRWwZzPnsrsy5r74Tc7Mw9d2VhePqZ4uM"; //node_client.get_own_btc_address().await?;

    let confs = Some(0);

    // mine BTC to user adress
    // generate_blocks_to_address(&btc_address_user).await?;

    // sleep(Duration::from_secs(10)).await; // Sleep after sending BTC

    let user_balance = user_client
        .get_btc_balance(
            Principal::from_text(helpers::id::CKLIGHTNING_LEDGER_ID)?,
            btc_address_user.clone(), //btcaddrcan.to_string(), //btcaddrcan.to_string(), //btc_address_user.clone(),
            confs,
        )
        .await
        .map_err(|e| {
            println!("Error getting user BTC balance: {:?}", e);
            e
        })?;

    println!("User BTC balance: {}", user_balance);

    let bb_balance_of = "mhRWwZzPnsrsy5r74Tc7Mw9d2VhePqZ4uM".to_string();

    let bb_balance = user_client.get_btc_bb_balance(bb_balance_of).await?;

    println!(
        "User BTC balance from basic bitcoin canister: {}",
        bb_balance
    );

    // verify balance of user address, using the ckLightning canister

    Ok(())
}

#[tokio::test]
async fn test_agent_get_btc_address() -> Result<(), Box<dyn std::error::Error>> {
    let user_client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    user_client.fetch_root_key().await?;
    let node_client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    node_client.fetch_root_key().await?;

    // Fetch balances before transfer

    // let btc_address_type = cklightning::ic_types::BtcAddressType::P2PKH; //P2WPKH;

    let btc_address_user = user_client.get_own_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    let btc_address_node = node_client.get_own_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    println!(
        "BTC user  address received from canister: {:?}",
        btc_address_user
    );
    println!(
        "BTC node address received from canister: {:?}",
        btc_address_node
    );

    let btcaddrcan = btc_address_user; //"mv6hFpg8yd5RGjAPWeujQUXZ3hQWVPM8Rk"; //node_client.get_own_btc_address().await?;

    // mine BTC to user adress
    // generate_blocks_to_address(&btc_address_user).await?;

    // sleep(Duration::from_secs(10)).await; // Sleep after sending BTC

    let confs = Some(1);
    //Some(1);

    let user_balance = user_client
        .get_btc_balance(
            Principal::from_text(helpers::id::CKLIGHTNING_LEDGER_ID)?,
            btcaddrcan.to_string(), //btcaddrcan.to_string(), //btc_address_user.clone(),
            confs,
        )
        .await
        .map_err(|e| {
            println!("Error getting user BTC balance: {:?}", e);
            e
        })?;

    println!("User BTC balance: {}", user_balance);

    // verify balance of user address, using the ckLightning canister

    Ok(())
}

#[tokio::test]
async fn test_agent_set_btc_address() -> Result<(), Box<dyn std::error::Error>> {
    // we call set_btc_address to make it set a new BTC address for the canister
    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let btc_address_type = cklightning::ic_types::BtcAddressType::P2PKH; //P2WPKH;

    let btc_address = client
        .set_btc_address(btc_address_type)
        .await
        .map_err(|e| {
            println!("Error setting BTC address: {:?}", e);
            e
        })?;
    println!("BTC address set successfully: {}", btc_address);
    Ok(())
}

#[tokio::test]
async fn test_agent_send_btc_to_canister() -> Result<(), Box<dyn std::error::Error>> {
    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_USER_ACC_PATH)))?;
    client.fetch_root_key().await?;

    // let btc_address_type = cklightning::ic_types::BtcAddressType::P2WPKH;
    // let btc_address_type = cklightning::ic_types::BtcAddressType::P2PKH; //P2WPKH;

    // Get user BTC address
    let user_btc_address = client.get_own_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    println!("User BTC address: {}", user_btc_address);
    sleep(Duration::from_secs(10)).await; // Sleep after sending BTC

    // Generate blocks before sending BTC to ensure confirmations
    generate_blocks_to_address(&user_btc_address).await?;
    sleep(Duration::from_secs(10)).await; // Sleep after sending BTC

    let btc_address_type = cklightning::ic_types::BtcAddressType::P2PKH;

    // Get canister BTC address
    let canister_btc_address = client
        .set_btc_address(btc_address_type)
        .await
        .map_err(|e| {
            println!("Error setting BTC address: {:?}", e);
            e
        })?;

    println!(
        "Sending BTC to canister's BTC address: {}",
        canister_btc_address
    );

    let amount_sat = 100u64;
    let btc_receiver = canister_btc_address.clone();

    /// send to btc canister
    ///
    // test sending to btc canister
    let tx_id = client
        .send_btc(amount_sat, btc_receiver)
        .await
        .map_err(|e| {
            println!("Error sending BTC to canister: {:?}", e);
            e
        })?;

    println!("BTC sent successfully, transaction ID: {:?}", tx_id);

    // Generate blocks again so balance gets confirmed
    generate_blocks_to_address(&canister_btc_address).await?;
    sleep(Duration::from_secs(10)).await; // Sleep after sending BTC
    let confs = None;
    // Check canister balance after send
    let canister_balance_after_send = client
        .get_btc_balance(
            Principal::from_text(helpers::id::CKLIGHTNING_LEDGER_ID)?,
            user_btc_address,
            confs,
        )
        .await
        .map_err(|e| {
            println!("Error getting canister BTC balance: {:?}", e);
            e
        })?;

    println!(
        "Canister BTC balance after send: {}",
        canister_balance_after_send
    );

    Ok(())
}

use std::env;
use std::path::PathBuf;

#[tokio::test]
async fn test_btc_mine_to_address() -> Result<(), Box<dyn std::error::Error>> {
    // Expand home directory for local bitcoin-cli path
    let home_dir = env::var("HOME")?;
    let bitcoin_cli_path = PathBuf::from(home_dir)
        .join("workrepos")
        .join("bitcoin-25.0")
        .join("bin")
        .join("bitcoin-cli");

    let mined_address = "mhRWwZzPnsrsy5r74Tc7Mw9d2VhePqZ4uM";

    let output = std::process::Command::new(bitcoin_cli_path)
        .args(&[
            "-regtest",
            "-rpcwallet=testwallet",
            "-rpcuser=ic-btc-integration",
            "-rpcpassword=QPQiNaph19FqUsCrBRN0FII7lyM26B51fAMeBQzCb-E=",
            "generatetoaddress",
            "200",
            mined_address,
        ])
        .output()?;

    let stdout_str = str::from_utf8(&output.stdout).unwrap_or("<Invalid UTF-8>");
    let stderr_str = str::from_utf8(&output.stderr).unwrap_or("<Invalid UTF-8>");

    println!("Command stdout:\n{}", stdout_str);
    if !stderr_str.is_empty() {
        eprintln!("Command stderr:\n{}", stderr_str);
    }

    if !output.status.success() {
        return Err(format!(
            "Failed to generate blocks with exit code: {}",
            output.status
        )
        .into());
    }

    if !output.status.success() {
        return Err(format!("Failed to generate blocks: {:?}", output).into());
    }

    println!("Generated 101 blocks to confirm transactions");

    // Continue your test after blocks are generated...
    Ok(())
}
