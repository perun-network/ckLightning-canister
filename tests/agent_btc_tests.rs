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

mod helpers;
use helpers::agent::ICAgent;
use helpers::id::{PEM_NODE_ACC_PATH, str_home_from_path};

#[tokio::test]
async fn test_agent_get_btc_address() -> Result<(), Box<dyn std::error::Error>> {
    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    client.fetch_root_key().await?;

    // Fetch balances before transfer

    let btc_address = client.get_btc_address().await.map_err(|e| {
        println!("Error getting BTC address: {:?}", e);
        e
    })?;

    println!("BTC address received from canister: {:?}", btc_address);

    Ok(())
}

#[tokio::test]
async fn test_agent_set_btc_address() -> Result<(), Box<dyn std::error::Error>> {
    // we call set_btc_address to make it set a new BTC address for the canister
    let client = ICAgent::new_from_pem_file(Some(str_home_from_path(PEM_NODE_ACC_PATH)))?;
    client.fetch_root_key().await?;

    let btc_address = client.set_btc_address().await.map_err(|e| {
        println!("Error setting BTC address: {:?}", e);
        e
    })?;
    println!("BTC address set successfully: {}", btc_address);
    Ok(())
}
