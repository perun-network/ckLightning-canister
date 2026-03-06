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

use bitcoin::{
    Address, Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    absolute::LockTime,
    hashes::Hash,
    opcodes::all::{
        OP_CHECKSIG, OP_CLTV, OP_DROP, OP_ELSE, OP_ENDIF, OP_EQUALVERIFY, OP_IF, OP_SHA256,
    },
    script::Builder,
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey},
    sighash::{EcdsaSighashType, SighashCache},
};
use candid::{CandidType, Deserialize};
use k256::sha2::{Digest, Sha256};
use serde::Serialize;
use std::collections::BTreeMap;

/// HTLC state in the payment flow
#[derive(Clone, Debug, CandidType, Serialize, Deserialize, PartialEq)]
pub enum HtlcState {
    /// HTLC is active and can be fulfilled or timed out
    Pending,
    /// HTLC fulfilled with preimage
    Fulfilled { preimage: Vec<u8> },
    /// HTLC timed out and refunded to sender
    TimedOut,
    /// HTLC failed for other reasons
    Failed { reason: String },
}

/// An HTLC in a Lightning-compatible payment channel.
///
/// Contains all data needed to construct and spend the HTLC output.
#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct Htlc {
    /// SHA256 hash of the preimage (32 bytes)
    pub payment_hash: [u8; 32],
    /// Amount in millisatoshis
    pub amount_msat: u64,
    /// Absolute block height for timeout (CLTV)
    pub cltv_expiry: u32,
    /// Current state of the HTLC
    pub state: HtlcState,
    /// Sender's public key (33 bytes compressed)
    pub sender_pubkey: Vec<u8>,
    /// Receiver's public key (33 bytes compressed)
    pub receiver_pubkey: Vec<u8>,
}

/// A commitment state containing channel balances and HTLCs.
///
/// This represents the current state of a payment channel between two parties.
#[derive(Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct CommitmentState {
    /// Channel identifier
    pub channel_id: [u8; 32],
    /// Commitment number (increments with each state update)
    pub commitment_number: u64,
    /// Party A's balance in satoshis
    pub balance_a_sat: u64,
    /// Party B's balance in satoshis
    pub balance_b_sat: u64,
    /// Active HTLCs offered by party A to party B
    pub htlcs_a_to_b: Vec<Htlc>,
    /// Active HTLCs offered by party B to party A
    pub htlcs_b_to_a: Vec<Htlc>,
}

/// Result of creating an HTLC output
#[derive(Clone, Debug)]
pub struct HtlcOutput {
    /// The P2WSH address for the HTLC
    pub address: Address,
    /// The witness script (redeemScript for P2WSH)
    pub witness_script: ScriptBuf,
    /// The HTLC amount in satoshis
    pub amount_sat: u64,
}

/// Witness data for spending an HTLC via the success path (with preimage)
#[derive(Clone, Debug)]
pub struct HtlcSuccessWitness {
    pub signature: Vec<u8>,
    pub preimage: Vec<u8>,
    pub witness_script: ScriptBuf,
}

/// Witness data for spending an HTLC via the timeout path
#[derive(Clone, Debug)]
pub struct HtlcTimeoutWitness {
    pub signature: Vec<u8>,
    pub witness_script: ScriptBuf,
}

// =============================================================================
// Core HTLC Functions
// =============================================================================

/// Compute SHA256 hash of a preimage to get the payment hash.
pub fn compute_payment_hash(preimage: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(preimage);
    hasher.finalize().into()
}

/// Verify that a preimage matches a payment hash.
pub fn verify_preimage(preimage: &[u8], payment_hash: &[u8; 32]) -> bool {
    compute_payment_hash(preimage) == *payment_hash
}

/// Build an HTLC witness script (P2WSH) compatible with Lightning.
///
/// Script structure:
/// ```text
/// OP_IF
///     # Success path: receiver claims with preimage
///     OP_SHA256 <payment_hash> OP_EQUALVERIFY
///     <receiver_pubkey> OP_CHECKSIG
/// OP_ELSE
///     # Timeout path: sender reclaims after CLTV expiry
///     <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
///     <sender_pubkey> OP_CHECKSIG
/// OP_ENDIF
/// ```
pub fn build_htlc_witness_script(
    payment_hash: &[u8; 32],
    receiver_pubkey: &PublicKey,
    sender_pubkey: &PublicKey,
    cltv_expiry: u32,
) -> ScriptBuf {
    Builder::new()
        .push_opcode(OP_IF)
        // Success path: receiver with preimage
        .push_opcode(OP_SHA256)
        .push_slice(payment_hash)
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(&receiver_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ELSE)
        // Timeout path: sender after CLTV
        .push_int(cltv_expiry as i64)
        .push_opcode(OP_CLTV)
        .push_opcode(OP_DROP)
        .push_slice(&sender_pubkey.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_ENDIF)
        .into_script()
}

/// Create a P2WSH address from an HTLC witness script.
pub fn htlc_script_to_p2wsh_address(witness_script: &ScriptBuf, network: Network) -> Address {
    Address::p2wsh(witness_script, network)
}

/// Create a complete HTLC output ready for inclusion in a transaction.
pub fn create_htlc_output(
    payment_hash: &[u8; 32],
    receiver_pubkey: &PublicKey,
    sender_pubkey: &PublicKey,
    cltv_expiry: u32,
    amount_sat: u64,
    network: Network,
) -> HtlcOutput {
    let witness_script =
        build_htlc_witness_script(payment_hash, receiver_pubkey, sender_pubkey, cltv_expiry);
    let address = htlc_script_to_p2wsh_address(&witness_script, network);

    HtlcOutput {
        address,
        witness_script,
        amount_sat,
    }
}

// =============================================================================
// Transaction Building
// =============================================================================

/// Build an HTLC funding transaction output (TxOut).
pub fn build_htlc_txout(htlc_output: &HtlcOutput) -> TxOut {
    TxOut {
        value: Amount::from_sat(htlc_output.amount_sat),
        script_pubkey: htlc_output.address.script_pubkey(),
    }
}

/// Build an HTLC-Success transaction that spends an HTLC output using the preimage.
///
/// This transaction is used by the receiver to claim the HTLC funds.
pub fn build_htlc_success_tx(
    htlc_outpoint: OutPoint,
    htlc_amount_sat: u64,
    receiver_address: &Address,
    fee_sat: u64,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: htlc_outpoint,
            script_sig: ScriptBuf::new(), // Empty for SegWit
            sequence: Sequence::ZERO,     // No relative timelock needed for success path
            witness: Witness::new(),      // Filled during signing
        }],
        output: vec![TxOut {
            value: Amount::from_sat(htlc_amount_sat.saturating_sub(fee_sat)),
            script_pubkey: receiver_address.script_pubkey(),
        }],
    }
}

/// Build an HTLC-Timeout transaction that reclaims HTLC funds after timeout.
///
/// This transaction is used by the sender to reclaim funds after CLTV expiry.
pub fn build_htlc_timeout_tx(
    htlc_outpoint: OutPoint,
    htlc_amount_sat: u64,
    sender_address: &Address,
    cltv_expiry: u32,
    fee_sat: u64,
) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: LockTime::from_height(cltv_expiry.min(499_999_999))
            .expect("clamped locktime is always valid"),
        input: vec![TxIn {
            previous_output: htlc_outpoint,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::from_height(0), // Allows CLTV to be checked
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(htlc_amount_sat.saturating_sub(fee_sat)),
            script_pubkey: sender_address.script_pubkey(),
        }],
    }
}

// =============================================================================
// Transaction Signing
// =============================================================================

/// Compute the sighash for spending a P2WSH HTLC output.
pub fn compute_htlc_sighash(
    tx: &Transaction,
    input_index: usize,
    witness_script: &ScriptBuf,
    amount_sat: u64,
) -> Result<[u8; 32], String> {
    let mut sighash_cache = SighashCache::new(tx);
    let sighash = sighash_cache
        .p2wsh_signature_hash(
            input_index,
            witness_script,
            Amount::from_sat(amount_sat),
            EcdsaSighashType::All,
        )
        .map_err(|e| format!("Failed to compute sighash: {:?}", e))?;

    Ok(sighash.to_byte_array())
}

/// Sign an HTLC transaction input.
///
/// Returns the DER-encoded signature with sighash type appended.
pub fn sign_htlc_input(
    tx: &Transaction,
    input_index: usize,
    witness_script: &ScriptBuf,
    amount_sat: u64,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, String> {
    let sighash = compute_htlc_sighash(tx, input_index, witness_script, amount_sat)?;
    let message = Message::from_digest(sighash);

    let secp = Secp256k1::signing_only();
    let signature = secp.sign_ecdsa(&message, secret_key);

    // Append SIGHASH_ALL byte
    let mut sig_bytes = signature.serialize_der().to_vec();
    sig_bytes.push(EcdsaSighashType::All.to_u32() as u8);

    Ok(sig_bytes)
}

/// Apply the success path witness to an HTLC transaction.
///
/// Witness stack for success path: [signature, preimage, OP_TRUE, witness_script]
pub fn apply_htlc_success_witness(
    tx: &mut Transaction,
    input_index: usize,
    signature: Vec<u8>,
    preimage: Vec<u8>,
    witness_script: &ScriptBuf,
) {
    let mut witness = Witness::new();
    witness.push(&signature);
    witness.push(&preimage);
    witness.push(&[0x01]); // OP_TRUE to take the IF branch
    witness.push(witness_script.as_bytes());

    tx.input[input_index].witness = witness;
}

/// Apply the timeout path witness to an HTLC transaction.
///
/// Witness stack for timeout path: [signature, OP_FALSE, witness_script]
pub fn apply_htlc_timeout_witness(
    tx: &mut Transaction,
    input_index: usize,
    signature: Vec<u8>,
    witness_script: &ScriptBuf,
) {
    let mut witness = Witness::new();
    witness.push(&signature);
    witness.push(&[]); // OP_FALSE (empty) to take the ELSE branch
    witness.push(witness_script.as_bytes());

    tx.input[input_index].witness = witness;
}

// =============================================================================
// HTLC Manager (Candid-compatible state management)
// =============================================================================

/// Manager for HTLC operations in the canister.
///
/// Tracks pending HTLCs and provides Candid-compatible state management.
#[derive(Default, Clone, Debug, CandidType, Serialize, Deserialize)]
pub struct HtlcManager {
    htlcs: BTreeMap<[u8; 32], Htlc>,
    next_htlc_id: u64,
}

impl HtlcManager {
    pub fn new() -> Self {
        Self {
            htlcs: BTreeMap::new(),
            next_htlc_id: 0,
        }
    }

    /// Add a new pending HTLC.
    pub fn add_htlc(
        &mut self,
        payment_hash: [u8; 32],
        amount_msat: u64,
        cltv_expiry: u32,
        sender_pubkey: Vec<u8>,
        receiver_pubkey: Vec<u8>,
    ) -> Result<(), String> {
        if self.htlcs.contains_key(&payment_hash) {
            return Err("HTLC with this payment hash already exists".to_string());
        }

        let htlc = Htlc {
            payment_hash,
            amount_msat,
            cltv_expiry,
            state: HtlcState::Pending,
            sender_pubkey,
            receiver_pubkey,
        };

        self.htlcs.insert(payment_hash, htlc);
        self.next_htlc_id += 1;
        Ok(())
    }

    /// Fulfill an HTLC by revealing the preimage.
    ///
    /// Returns the payment hash and amount if successful.
    pub fn fulfill_htlc(&mut self, preimage: Vec<u8>) -> Result<([u8; 32], u64), String> {
        let payment_hash = compute_payment_hash(&preimage);

        let htlc = self
            .htlcs
            .get_mut(&payment_hash)
            .ok_or("HTLC not found for this preimage")?;

        match &htlc.state {
            HtlcState::Pending => {
                htlc.state = HtlcState::Fulfilled {
                    preimage: preimage.clone(),
                };
                Ok((payment_hash, htlc.amount_msat))
            }
            HtlcState::Fulfilled { .. } => Err("HTLC already fulfilled".to_string()),
            HtlcState::TimedOut => Err("HTLC already timed out".to_string()),
            HtlcState::Failed { reason } => Err(format!("HTLC failed: {}", reason)),
        }
    }

    /// Mark an HTLC as timed out (sender reclaims).
    pub fn timeout_htlc(&mut self, payment_hash: &[u8; 32]) -> Result<u64, String> {
        let htlc = self.htlcs.get_mut(payment_hash).ok_or("HTLC not found")?;

        match &htlc.state {
            HtlcState::Pending => {
                htlc.state = HtlcState::TimedOut;
                Ok(htlc.amount_msat)
            }
            _ => Err("HTLC not in pending state".to_string()),
        }
    }

    /// Get an HTLC by payment hash.
    pub fn get_htlc(&self, payment_hash: &[u8; 32]) -> Option<&Htlc> {
        self.htlcs.get(payment_hash)
    }

    /// Get all pending HTLCs.
    pub fn pending_htlcs(&self) -> Vec<&Htlc> {
        self.htlcs
            .values()
            .filter(|h| h.state == HtlcState::Pending)
            .collect()
    }

    /// Remove a resolved HTLC from the manager.
    pub fn remove_htlc(&mut self, payment_hash: &[u8; 32]) -> Option<Htlc> {
        self.htlcs.remove(payment_hash)
    }
}

// =============================================================================
// Serialization helpers for Candid compatibility
// =============================================================================

/// Serialize a commitment state for signing.
///
/// This produces a canonical byte representation that can be signed.
pub fn serialize_commitment_for_signing(state: &CommitmentState) -> Vec<u8> {
    let mut data = Vec::new();

    // Channel ID
    data.extend_from_slice(&state.channel_id);

    // Commitment number (big-endian)
    data.extend_from_slice(&state.commitment_number.to_be_bytes());

    // Balances (big-endian)
    data.extend_from_slice(&state.balance_a_sat.to_be_bytes());
    data.extend_from_slice(&state.balance_b_sat.to_be_bytes());

    // Number of HTLCs A->B
    data.extend_from_slice(&(state.htlcs_a_to_b.len() as u32).to_be_bytes());
    for htlc in &state.htlcs_a_to_b {
        data.extend_from_slice(&htlc.payment_hash);
        data.extend_from_slice(&htlc.amount_msat.to_be_bytes());
        data.extend_from_slice(&htlc.cltv_expiry.to_be_bytes());
    }

    // Number of HTLCs B->A
    data.extend_from_slice(&(state.htlcs_b_to_a.len() as u32).to_be_bytes());
    for htlc in &state.htlcs_b_to_a {
        data.extend_from_slice(&htlc.payment_hash);
        data.extend_from_slice(&htlc.amount_msat.to_be_bytes());
        data.extend_from_slice(&htlc.cltv_expiry.to_be_bytes());
    }

    data
}

/// Hash a commitment state for signing (SHA256).
pub fn hash_commitment_for_signing(state: &CommitmentState) -> [u8; 32] {
    let data = serialize_commitment_for_signing(state);
    compute_payment_hash(&data)
}
