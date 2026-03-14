// Copyright 2026 - See NOTICE file for copyright holders.
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
use ic_agent::{Identity, identity::Secp256k1Identity};
use std::env;
use std::path::PathBuf;

pub const PEM_NODE_ACC_PATH: &str = ".config/dfx/identity/node/identity.pem";
pub const PEM_USER_ACC_PATH: &str = ".config/dfx/identity/user/identity.pem";
pub const BTC_LEDGER_ID: &str = "u6s2n-gx777-77774-qaaba-cai";
pub const CKLIGHTNING_LEDGER_ID: &str = "vizcg-th777-77774-qaaea-cai";
pub const BTC_MINTER_ID: &str = "uzt4z-lp777-77774-qaabq-cai";
pub const DEVNET_BASIC_BITCOIN: &str = "vpyes-67777-77774-qaaeq-cai";

pub const BTC_LEDGER_DEFAULT_FEE: u64 = 1000;

pub fn create_identity(path: Option<&str>) -> impl Identity {
    let home_dir = env::var("HOME").unwrap();
    let pem_path = match path {
        Some(custom_path) => custom_path.to_string(),
        None => format!("{home_dir}/.config/dfx/identity/minting_ledger/identity.pem"),
    };
    if std::fs::metadata(&pem_path).is_ok() {
        match Secp256k1Identity::from_pem_file(&pem_path) {
            Ok(identity) => identity,
            Err(e) => panic!("Error loading identity: {e}"),
        }
    } else {
        panic!("File does not exist.");
    }
}

pub fn create_secp_identity(path: Option<&str>) -> Secp256k1Identity {
    let home_dir = env::var("HOME").expect("HOME environment variable not set");
    let pem_path = PathBuf::from(match path {
        Some(custom_path) => custom_path,
        None => PEM_NODE_ACC_PATH,
    });

    let absolute_path = PathBuf::from(home_dir).join(&pem_path);

    if !absolute_path.exists() {
        panic!("File does not exist: {}", absolute_path.display());
    }

    Secp256k1Identity::from_pem_file(&absolute_path).unwrap_or_else(|e| {
        panic!(
            "Error loading identity from {}: {}",
            absolute_path.display(),
            e
        )
    })
}

pub fn str_home_from_path(path: &str) -> String {
    let home_dir = env::var("HOME").unwrap();
    format!("{home_dir}/{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::signature::Verifier;
    use k256::ecdsa::{Signature, VerifyingKey};
    use k256::pkcs8::DecodePublicKey;
    use k256::sha2::{Digest, Sha256};

    #[test]
    fn test_sign_and_verify_bogus_data() {
        let identity = create_secp_identity(Some(PEM_USER_ACC_PATH));
        let data = b"this is some test data to sign";
        let digest = Sha256::digest(data);
        let signature = identity
            .sign_arbitrary(&digest)
            .expect("Failed to sign data");
        let sig_bytes = signature
            .signature
            .expect("Signature bytes missing from Signature object");
        let pubkey_der = identity
            .public_key()
            .expect("Public key missing from identity");
        let verifying_key =
            VerifyingKey::from_public_key_der(&pubkey_der).expect("Invalid DER public key");
        let ecdsa_sig =
            Signature::try_from(&sig_bytes[..]).expect("Failed to parse signature bytes");
        verifying_key
            .verify(digest.as_slice(), &ecdsa_sig)
            .expect("Signature verification failed");
    }
}
