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

use cklightning::btc::btc_tx::{sequentially_sign_funding_tx_1, sequentially_sign_funding_tx_2};
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::CompressedPublicKey;
    use bitcoin::PrivateKey;
    use bitcoin::ScriptBuf;
    use bitcoin::absolute::LockTime;
    use bitcoin::secp256k1::ecdsa::Signature as SecpSignature;
    use bitcoin::{
        Address, Amount, Network, PublicKey, Transaction, TxIn, TxOut, Witness,
        secp256k1::{Secp256k1, SecretKey},
    };
    use std::future;
    use std::str::FromStr;

    fn make_mock_signer(
        sk: SecretKey,
    ) -> impl Fn(String, Vec<Vec<u8>>, Vec<u8>) -> future::Ready<SecpSignature> + Copy {
        move |_, _, msg| {
            let secp = Secp256k1::signing_only();
            let message = bitcoin::secp256k1::Message::from_slice(&msg).unwrap();
            let sig = secp.sign_ecdsa(&message, &sk);
            future::ready(sig)
        }
    }

    #[tokio::test]
    async fn test_sequentially_sign_funding_tx_1_and_2_simple() {
        let secp = Secp256k1::new();

        let sk1 = SecretKey::new(&mut rand::thread_rng());

        // Wrap the SecretKey into a bitcoin::PrivateKey specifying the network
        let privkey1 = PrivateKey {
            compressed: true,
            network: Network::Regtest.into(), // or Mainnet
            inner: sk1.clone(),
        };

        let pk1 = PublicKey::from_private_key(&secp, &privkey1);
        let compressed_pk1 = CompressedPublicKey::from_slice(&pk1.to_bytes()).unwrap();
        let addr1 = Address::p2wpkh(&compressed_pk1, Network::Regtest);

        let sk2 = SecretKey::new(&mut rand::thread_rng());

        let privkey2 = PrivateKey {
            compressed: true,
            network: Network::Regtest.into(), // or Mainnet
            inner: sk2.clone(),
        };

        let pk2 = PublicKey::from_private_key(&secp, &privkey2);
        let compressed_pk2 = CompressedPublicKey::from_slice(&pk2.to_bytes()).unwrap();
        let addr2 = Address::p2wpkh(&compressed_pk2, Network::Regtest);

        let prevouts = vec![
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: addr1.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(15_000),
                script_pubkey: addr2.script_pubkey(),
            },
        ];

        let lock_time = LockTime::ZERO;

        let address =
            Address::from_str("bcrt1pwyhrz4mec3znq4m0ay67vlxmvstf8pfprmx7gxu86ef73jezmszs2ly84w")
                .expect("bcrt1pwyhrz4mec3znq4m0ay67vlxmvstf8pfprmx7gxu86ef73jezmszs2ly84w")
                .assume_checked();
        let script_pubkey = address.script_pubkey();
        let unsigned_tx = Transaction {
            version: bitcoin::transaction::Version(2),
            lock_time: lock_time,
            input: vec![
                TxIn {
                    previous_output: Default::default(),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFF),
                    witness: Witness::new(),
                },
                TxIn {
                    previous_output: Default::default(),
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence(0xFFFFFFFF),
                    witness: Witness::new(),
                },
            ],
            output: vec![TxOut {
                value: Amount::from_sat(25_000),
                script_pubkey,
            }],
        };

        let dp1 = cklightning::btc::common::DerivationPath::p2wpkh(0, 0).to_vec_u8_path();
        let dp2 = cklightning::btc::common::DerivationPath::p2wpkh(0, 1).to_vec_u8_path();

        let parties = &[
            (pk1, addr1, dp1, make_mock_signer(sk1)),
            (pk2, addr2, dp2, make_mock_signer(sk2)),
        ];

        let fully_signed_tx_1 =
            sequentially_sign_funding_tx_1(unsigned_tx.clone(), &prevouts, parties).await;
        assert!(!fully_signed_tx_1.input[0].witness.is_empty());
        assert!(!fully_signed_tx_1.input[1].witness.is_empty());

        let fully_signed_tx_2 =
            sequentially_sign_funding_tx_2(unsigned_tx, &prevouts, parties).await;
        assert!(!fully_signed_tx_2.input[0].witness.is_empty());
        assert!(!fully_signed_tx_2.input[1].witness.is_empty());
    }
}
