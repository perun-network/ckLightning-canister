// Copyright 2025 - See NOTICE file for copyright holders.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use rand::rngs::StdRng;

use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::{self, Secp256k1};
use ic_agent::{Identity, identity::Secp256k1Identity};
use rand::SeedableRng;
use std::env;
use std::fs;
pub const PEM_MINTING_ACC_PATH: &str = ".config/dfx/identity/minting_ledger/identity.pem";
pub const PEM_NODE_ACC_PATH: &str = ".config/dfx/identity/node/identity.pem";
pub const PEM_USER_ACC_PATH: &str = ".config/dfx/identity/user/identity.pem";
pub const LEDGER_ID: &str = "by6od-j4aaa-aaaaa-qaadq-cai";
pub const BTC_LEDGER_ID: &str = "bd3sg-teaaa-aaaaa-qaaba-cai";
pub const CKLIGHTNING_LEDGER_ID: &str = "avqkn-guaaa-aaaaa-qaaea-cai";
pub const BTC_LEDGER_DEFAULT_FEE: u64 = 1000;

pub fn create_identity(path: Option<&str>) -> impl Identity {
    let home_dir = env::var("HOME").unwrap();
    let pem_path = match path {
        Some(custom_path) => custom_path.to_string(),
        None => format!("{}/{}", home_dir, PEM_MINTING_ACC_PATH),
    };
    if fs::metadata(&pem_path).is_ok() {
        match Secp256k1Identity::from_pem_file(&pem_path) {
            Ok(identity) => identity,
            Err(e) => panic!("Error loading identity: {}", e),
        }
    } else {
        panic!("File does not exist.");
    }
}

pub fn str_home_from_path(path: &str) -> String {
    let home_dir = env::var("HOME").unwrap();
    format!("{}/{}", home_dir, path)
}

pub fn id_from_pem(pem_path: &str) -> impl Identity {
    match Secp256k1Identity::from_pem_file(pem_path) {
        Ok(identity) => identity,
        Err(e) => panic!("Error loading identity: {}", e),
    }
}

pub fn create_keypair() -> (SecpSecretKey, SecpPublicKey) {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(89899);
    secp.generate_keypair(&mut rng)
}
