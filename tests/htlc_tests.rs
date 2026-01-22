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

//! Integration tests for HTLC (Hash Time-Locked Contract) functionality.
//!
//! These tests simulate a two-party payment channel where:
//! - Alice (sender) creates an HTLC to pay Bob (receiver)
//! - Bob can claim funds by revealing the preimage
//! - Alice can reclaim funds after timeout if Bob doesn't claim

use bitcoin::{
    Address, Amount, CompressedPublicKey, Network, OutPoint, Transaction, TxIn, TxOut, Txid,
    Witness,
    absolute::LockTime,
    hashes::Hash,
    secp256k1::{PublicKey, Secp256k1, SecretKey},
};
use cklightning::htlc::{
    Htlc, HtlcManager, HtlcState, apply_htlc_success_witness, apply_htlc_timeout_witness,
    build_htlc_success_tx, build_htlc_timeout_tx, build_htlc_witness_script, compute_payment_hash,
    create_htlc_output, sign_htlc_input, verify_preimage,
};

/// Test helper: Create a keypair for testing
fn create_test_keypair(seed: u8) -> (SecretKey, PublicKey) {
    let secp = Secp256k1::new();
    let mut secret_bytes = [0u8; 32];
    secret_bytes[31] = seed;
    secret_bytes[0] = 0x01; // Ensure valid secret key
    let secret_key = SecretKey::from_slice(&secret_bytes).expect("valid secret key");
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    (secret_key, public_key)
}

/// Test helper: Create a P2WPKH address from a public key
fn pubkey_to_p2wpkh_address(pubkey: &PublicKey, network: Network) -> Address {
    let compressed =
        CompressedPublicKey::from_slice(&pubkey.serialize()).expect("valid compressed pubkey");
    Address::p2wpkh(&compressed, network)
}

/// Test helper: Create a mock funding transaction that funds the HTLC
fn create_mock_funding_tx(htlc_output: &TxOut) -> (Transaction, OutPoint) {
    let funding_tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_slice(&[0u8; 32]).unwrap(),
                vout: 0,
            },
            script_sig: bitcoin::ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![htlc_output.clone()],
    };

    let outpoint = OutPoint {
        txid: funding_tx.compute_txid(),
        vout: 0,
    };

    (funding_tx, outpoint)
}

// =============================================================================
// Two-Party HTLC Lifecycle Tests
// =============================================================================

/// Complete HTLC lifecycle test: Alice pays Bob, Bob claims with preimage.
///
/// This test simulates:
/// 1. Alice creates a secret preimage and shares the hash with Bob
/// 2. Alice funds an HTLC output locked to the payment hash
/// 3. Bob receives the preimage (off-chain, e.g., from upstream payment)
/// 4. Bob signs and broadcasts an HTLC-Success transaction to claim funds
#[test]
fn test_htlc_success_path_alice_to_bob() {
    let network = Network::Regtest;
    let secp = Secp256k1::new();

    // === Setup: Create Alice (sender) and Bob (receiver) ===
    let (alice_sk, alice_pk) = create_test_keypair(1);
    let (bob_sk, bob_pk) = create_test_keypair(2);

    let alice_address = pubkey_to_p2wpkh_address(&alice_pk, network);
    let bob_address = pubkey_to_p2wpkh_address(&bob_pk, network);

    // === Step 1: Create the payment preimage and hash ===
    // In real Lightning, the receiver (Bob) generates this and shares only the hash
    let preimage = b"alice_pays_bob_12345678901234"; // 32 bytes
    let payment_hash = compute_payment_hash(preimage);

    // Verify preimage/hash relationship
    assert!(verify_preimage(preimage, &payment_hash));

    // === Step 2: Alice creates the HTLC output ===
    let htlc_amount_sat = 100_000; // 0.001 BTC
    let cltv_expiry = 500_000; // Block height for timeout

    let htlc_output = create_htlc_output(
        &payment_hash,
        &bob_pk,   // receiver can claim with preimage
        &alice_pk, // sender can reclaim after timeout
        cltv_expiry,
        htlc_amount_sat,
        network,
    );

    // Verify the HTLC output was created correctly
    assert_eq!(htlc_output.amount_sat, htlc_amount_sat);

    // The witness script should contain both pubkeys and the payment hash
    let script_bytes = htlc_output.witness_script.as_bytes();
    assert!(script_bytes.windows(32).any(|w| w == payment_hash));

    // === Step 3: Create mock funding transaction ===
    let htlc_txout = TxOut {
        value: Amount::from_sat(htlc_amount_sat),
        script_pubkey: htlc_output.address.script_pubkey(),
    };
    let (_funding_tx, htlc_outpoint) = create_mock_funding_tx(&htlc_txout);

    // === Step 4: Bob creates and signs the HTLC-Success transaction ===
    let fee_sat = 500;
    let mut success_tx =
        build_htlc_success_tx(htlc_outpoint, htlc_amount_sat, &bob_address, fee_sat);

    // Bob signs the transaction
    let bob_signature = sign_htlc_input(
        &success_tx,
        0, // input index
        &htlc_output.witness_script,
        htlc_amount_sat,
        &bob_sk,
    )
    .expect("signing should succeed");

    // Apply the success witness (includes preimage)
    apply_htlc_success_witness(
        &mut success_tx,
        0,
        bob_signature,
        preimage.to_vec(),
        &htlc_output.witness_script,
    );

    // === Step 5: Verify the signed transaction ===
    // Check that witness is properly populated
    assert!(!success_tx.input[0].witness.is_empty());
    assert_eq!(success_tx.input[0].witness.len(), 4); // sig, preimage, true, script

    // Verify output goes to Bob
    assert_eq!(
        success_tx.output[0].script_pubkey,
        bob_address.script_pubkey()
    );
    assert_eq!(
        success_tx.output[0].value,
        Amount::from_sat(htlc_amount_sat - fee_sat)
    );

    // Verify the witness contains the preimage
    let witness_preimage = success_tx.input[0].witness.nth(1).unwrap();
    assert_eq!(witness_preimage, preimage);

    println!("HTLC Success Path Test Passed!");
    println!("  Alice -> Bob payment: {} sats", htlc_amount_sat);
    println!("  Payment hash: {}", hex::encode(payment_hash));
    println!("  Bob claimed with preimage: {}", hex::encode(preimage));
}

/// HTLC timeout path test: Alice reclaims after Bob doesn't claim.
///
/// This test simulates:
/// 1. Alice creates an HTLC with a timeout
/// 2. Bob never claims (doesn't reveal preimage)
/// 3. After CLTV expiry, Alice reclaims the funds
#[test]
fn test_htlc_timeout_path_alice_reclaims() {
    let network = Network::Regtest;

    // === Setup ===
    let (alice_sk, alice_pk) = create_test_keypair(3);
    let (_bob_sk, bob_pk) = create_test_keypair(4);

    let alice_address = pubkey_to_p2wpkh_address(&alice_pk, network);

    // === Create HTLC ===
    let preimage = b"timeout_test_preimage_1234567"; // 32 bytes
    let payment_hash = compute_payment_hash(preimage);

    let htlc_amount_sat = 50_000;
    let cltv_expiry = 144; // ~1 day in blocks

    let htlc_output = create_htlc_output(
        &payment_hash,
        &bob_pk,
        &alice_pk,
        cltv_expiry,
        htlc_amount_sat,
        network,
    );

    // Create funding
    let htlc_txout = TxOut {
        value: Amount::from_sat(htlc_amount_sat),
        script_pubkey: htlc_output.address.script_pubkey(),
    };
    let (_funding_tx, htlc_outpoint) = create_mock_funding_tx(&htlc_txout);

    // === Alice creates timeout transaction after CLTV expiry ===
    let fee_sat = 400;
    let mut timeout_tx = build_htlc_timeout_tx(
        htlc_outpoint,
        htlc_amount_sat,
        &alice_address,
        cltv_expiry,
        fee_sat,
    );

    // Verify locktime is set correctly
    assert_eq!(
        timeout_tx.lock_time,
        LockTime::from_height(cltv_expiry).unwrap()
    );

    // Alice signs the timeout transaction
    let alice_signature = sign_htlc_input(
        &timeout_tx,
        0,
        &htlc_output.witness_script,
        htlc_amount_sat,
        &alice_sk,
    )
    .expect("signing should succeed");

    // Apply timeout witness (no preimage needed)
    apply_htlc_timeout_witness(
        &mut timeout_tx,
        0,
        alice_signature,
        &htlc_output.witness_script,
    );

    // === Verify ===
    assert!(!timeout_tx.input[0].witness.is_empty());
    assert_eq!(timeout_tx.input[0].witness.len(), 3); // sig, false, script

    // Output goes back to Alice
    assert_eq!(
        timeout_tx.output[0].script_pubkey,
        alice_address.script_pubkey()
    );

    // The witness should have empty bytes for the false branch
    let witness_false = timeout_tx.input[0].witness.nth(1).unwrap();
    assert!(witness_false.is_empty());

    println!("HTLC Timeout Path Test Passed!");
    println!("  Alice reclaimed: {} sats", htlc_amount_sat - fee_sat);
    println!("  After CLTV expiry block: {}", cltv_expiry);
}

/// Test HTLC Manager state transitions.
#[test]
fn test_htlc_manager_lifecycle() {
    let (alice_sk, alice_pk) = create_test_keypair(5);
    let (_bob_sk, bob_pk) = create_test_keypair(6);

    let mut manager = HtlcManager::new();

    // Create preimage and hash
    let preimage = b"manager_test_preimage_1234567";
    let payment_hash = compute_payment_hash(preimage);

    // Add HTLC
    manager
        .add_htlc(
            payment_hash,
            1_000_000, // 1000 sats in msat
            144,
            alice_pk.serialize().to_vec(),
            bob_pk.serialize().to_vec(),
        )
        .expect("should add HTLC");

    // Verify it exists and is pending
    let htlc = manager.get_htlc(&payment_hash).expect("HTLC should exist");
    assert_eq!(htlc.state, HtlcState::Pending);
    assert_eq!(htlc.amount_msat, 1_000_000);

    // Cannot add duplicate
    let result = manager.add_htlc(
        payment_hash,
        2_000_000,
        288,
        alice_pk.serialize().to_vec(),
        bob_pk.serialize().to_vec(),
    );
    assert!(result.is_err());

    // Fulfill with preimage
    let (returned_hash, amount) = manager
        .fulfill_htlc(preimage.to_vec())
        .expect("should fulfill");
    assert_eq!(returned_hash, payment_hash);
    assert_eq!(amount, 1_000_000);

    // Verify state changed
    let htlc = manager.get_htlc(&payment_hash).expect("HTLC should exist");
    match &htlc.state {
        HtlcState::Fulfilled { preimage: p } => {
            assert_eq!(p.as_slice(), preimage);
        }
        _ => panic!("Expected Fulfilled state"),
    }

    // Cannot fulfill again
    let result = manager.fulfill_htlc(preimage.to_vec());
    assert!(result.is_err());

    println!("HTLC Manager Lifecycle Test Passed!");
}

/// Test that wrong preimage doesn't fulfill HTLC.
#[test]
fn test_htlc_wrong_preimage_fails() {
    let (alice_sk, alice_pk) = create_test_keypair(7);
    let (_bob_sk, bob_pk) = create_test_keypair(8);

    let mut manager = HtlcManager::new();

    let correct_preimage = b"correct_preimage_123456789012";
    let wrong_preimage = b"wrong_preimage_1234567890123";
    let payment_hash = compute_payment_hash(correct_preimage);

    manager
        .add_htlc(
            payment_hash,
            500_000,
            144,
            alice_pk.serialize().to_vec(),
            bob_pk.serialize().to_vec(),
        )
        .unwrap();

    // Try to fulfill with wrong preimage
    let result = manager.fulfill_htlc(wrong_preimage.to_vec());
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));

    // HTLC should still be pending
    let htlc = manager.get_htlc(&payment_hash).unwrap();
    assert_eq!(htlc.state, HtlcState::Pending);

    println!("Wrong Preimage Test Passed!");
}

/// Test HTLC timeout state transition.
#[test]
fn test_htlc_timeout_state() {
    let (alice_sk, alice_pk) = create_test_keypair(9);
    let (_bob_sk, bob_pk) = create_test_keypair(10);

    let mut manager = HtlcManager::new();

    let preimage = b"timeout_state_preimage_123456";
    let payment_hash = compute_payment_hash(preimage);

    manager
        .add_htlc(
            payment_hash,
            750_000,
            144,
            alice_pk.serialize().to_vec(),
            bob_pk.serialize().to_vec(),
        )
        .unwrap();

    // Timeout the HTLC
    let amount = manager.timeout_htlc(&payment_hash).unwrap();
    assert_eq!(amount, 750_000);

    // Verify state
    let htlc = manager.get_htlc(&payment_hash).unwrap();
    assert_eq!(htlc.state, HtlcState::TimedOut);

    // Cannot timeout again
    let result = manager.timeout_htlc(&payment_hash);
    assert!(result.is_err());

    // Cannot fulfill after timeout
    let result = manager.fulfill_htlc(preimage.to_vec());
    assert!(result.is_err());

    println!("Timeout State Test Passed!");
}

/// Test multiple concurrent HTLCs.
#[test]
fn test_multiple_htlcs() {
    let (alice_sk, alice_pk) = create_test_keypair(11);
    let (_bob_sk, bob_pk) = create_test_keypair(12);

    let mut manager = HtlcManager::new();

    // Create multiple HTLCs
    let preimages: Vec<&[u8]> = vec![
        b"multi_htlc_preimage_1_abcdefgh",
        b"multi_htlc_preimage_2_abcdefgh",
        b"multi_htlc_preimage_3_abcdefgh",
    ];

    let amounts = [100_000u64, 200_000, 300_000];

    for (i, preimage) in preimages.iter().enumerate() {
        let payment_hash = compute_payment_hash(preimage);
        manager
            .add_htlc(
                payment_hash,
                amounts[i],
                144 + (i as u32),
                alice_pk.serialize().to_vec(),
                bob_pk.serialize().to_vec(),
            )
            .unwrap();
    }

    // All should be pending
    let pending = manager.pending_htlcs();
    assert_eq!(pending.len(), 3);

    // Fulfill the second one
    let (hash, amount) = manager.fulfill_htlc(preimages[1].to_vec()).unwrap();
    assert_eq!(amount, 200_000);

    // Now only 2 pending
    let pending = manager.pending_htlcs();
    assert_eq!(pending.len(), 2);

    // Timeout the third one
    let payment_hash_3 = compute_payment_hash(preimages[2]);
    manager.timeout_htlc(&payment_hash_3).unwrap();

    // Now only 1 pending
    let pending = manager.pending_htlcs();
    assert_eq!(pending.len(), 1);

    // Verify the first is still pending
    let payment_hash_1 = compute_payment_hash(preimages[0]);
    let htlc = manager.get_htlc(&payment_hash_1).unwrap();
    assert_eq!(htlc.state, HtlcState::Pending);
    assert_eq!(htlc.amount_msat, 100_000);

    println!("Multiple HTLCs Test Passed!");
}

/// Test HTLC witness script structure.
#[test]
fn test_htlc_witness_script_structure() {
    let (_alice_sk, alice_pk) = create_test_keypair(13);
    let (_bob_sk, bob_pk) = create_test_keypair(14);

    let preimage = b"script_structure_test_preimage";
    let payment_hash = compute_payment_hash(preimage);
    let cltv_expiry = 500_000u32;

    let witness_script = build_htlc_witness_script(&payment_hash, &bob_pk, &alice_pk, cltv_expiry);

    let script_bytes = witness_script.as_bytes();

    // Verify script contains expected opcodes
    // OP_IF = 0x63, OP_SHA256 = 0xa8, OP_EQUALVERIFY = 0x88
    // OP_CHECKSIG = 0xac, OP_ELSE = 0x67, OP_CLTV = 0xb1
    // OP_DROP = 0x75, OP_ENDIF = 0x68

    assert!(script_bytes.contains(&0x63)); // OP_IF
    assert!(script_bytes.contains(&0xa8)); // OP_SHA256
    assert!(script_bytes.contains(&0x88)); // OP_EQUALVERIFY
    assert!(script_bytes.contains(&0xac)); // OP_CHECKSIG
    assert!(script_bytes.contains(&0x67)); // OP_ELSE
    assert!(script_bytes.contains(&0xb1)); // OP_CLTV
    assert!(script_bytes.contains(&0x75)); // OP_DROP
    assert!(script_bytes.contains(&0x68)); // OP_ENDIF

    // Verify payment hash is in the script
    assert!(script_bytes.windows(32).any(|w| w == payment_hash));

    // Verify both pubkeys are in the script (compressed, 33 bytes)
    let alice_pk_bytes = alice_pk.serialize();
    let bob_pk_bytes = bob_pk.serialize();
    assert!(script_bytes.windows(33).any(|w| w == alice_pk_bytes));
    assert!(script_bytes.windows(33).any(|w| w == bob_pk_bytes));

    println!("Witness Script Structure Test Passed!");
    println!("  Script length: {} bytes", script_bytes.len());
    println!("  Script hex: {}", hex::encode(script_bytes));
}

/// Test payment hash computation matches expected SHA256.
#[test]
fn test_payment_hash_computation() {
    // Known test vector
    let preimage = b"test";
    let hash = compute_payment_hash(preimage);

    // SHA256("test") = 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
    let expected_hex = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08";
    let expected: [u8; 32] = hex::decode(expected_hex).unwrap().try_into().unwrap();

    assert_eq!(hash, expected);

    // Verify preimage verification works
    assert!(verify_preimage(preimage, &expected));
    assert!(!verify_preimage(b"wrong", &expected));

    println!("Payment Hash Computation Test Passed!");
}
