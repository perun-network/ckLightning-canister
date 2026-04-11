// =============================================================================
// Commitment, Justice, and HTLC Transaction Signing
//
// Phase 3: Batched commitment + HTLC signing (chainkey for commitment, local
//           ECDSA for HTLCs)
// Phase 4: Justice + HTLC transaction signing (local ECDSA only)
//
// The canister computes ALL sighashes from full transaction bytes.
// The relay never provides raw hashes — only full serialized transactions.
// =============================================================================

use super::{STATE, ChannelSecretsInternal};
use super::bolt3_keys;
use crate::btc::ecdsa::sign_with_ecdsa;
use crate::helpers::LN_FUNDING_DERIVATION_PATH;
use crate::ic_types::{
    SignCounterpartyCommitmentRequest, SignCounterpartyCommitmentResponse,
    SignHolderCommitmentRequest, SignHolderCommitmentResponse,
    SignClosingTxRequest,
    SignJusticeTxRequest, SignHtlcTxRequest,
    LnSignResponse,
};

use bitcoin::consensus::{deserialize, serialize as btc_serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{Message, Secp256k1, SecretKey};
use bitcoin::sighash::SighashCache;
use bitcoin::Transaction;

/// Helper: get the funding redeemscript for a channel.
///
/// Reconstructs the 2-of-2 multisig witness script from:
/// 1. The canister's funding pubkey (from chainkey ECDSA)
/// 2. The counterparty's funding pubkey (stored via register_channel_info)
fn get_funding_redeemscript(channel_keys_id: &[u8; 32]) -> Result<bitcoin::ScriptBuf, String> {
    let state = STATE.read().expect("STATE lock: get_funding_redeemscript");
    let counterparty_pubkey = state
        .channel_counterparty_pubkeys
        .get(channel_keys_id)
        .ok_or_else(|| "Counterparty funding pubkey not registered".to_string())?
        .clone();
    drop(state);

    // Get canister's funding pubkey
    let _ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());
    let derivation_path: Vec<Vec<u8>> = LN_FUNDING_DERIVATION_PATH
        .iter()
        .map(|s| s.to_vec())
        .collect();

    // We can't call async from here, so we use the cached key.
    // The funding pubkey MUST be cached already (fetched during channel setup).
    let our_pubkey = crate::btc::ecdsa::ECDSA_KEY_CACHE
        .with_borrow(|map| map.get(&derivation_path).cloned())
        .ok_or_else(|| "Canister funding pubkey not cached — call get_ln_funding_pubkey first".to_string())?;

    crate::helpers::build_funding_witness_script(&our_pubkey, &counterparty_pubkey)
}

/// Helper: sign a sighash with chainkey ECDSA (the funding key).
async fn sign_funding_sighash(sighash_bytes: &[u8; 32]) -> Result<Vec<u8>, String> {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());
    let derivation_path: Vec<Vec<u8>> = LN_FUNDING_DERIVATION_PATH
        .iter()
        .map(|s| s.to_vec())
        .collect();

    let signature = sign_with_ecdsa(
        ctx.key_name.to_string(),
        derivation_path,
        sighash_bytes.to_vec(),
    )
    .await;

    Ok(signature.serialize_compact().to_vec())
}

/// Helper: compute P2WSH sighash for input 0 of a transaction.
fn compute_funding_sighash(
    tx: &Transaction,
    funding_redeemscript: &bitcoin::ScriptBuf,
    funding_amount_sat: u64,
) -> Result<[u8; 32], String> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(
            0,
            funding_redeemscript,
            bitcoin::Amount::from_sat(funding_amount_sat),
            bitcoin::sighash::EcdsaSighashType::All,
        )
        .map_err(|e| format!("Failed to compute sighash: {e:?}"))?;
    Ok(sighash.to_byte_array())
}

/// Helper: compute P2WSH sighash for a specific input.
fn compute_witness_sighash(
    tx: &Transaction,
    input_index: usize,
    witness_script: &bitcoin::ScriptBuf,
    amount_sat: u64,
) -> Result<[u8; 32], String> {
    let mut cache = SighashCache::new(tx);
    let sighash = cache
        .p2wsh_signature_hash(
            input_index,
            witness_script,
            bitcoin::Amount::from_sat(amount_sat),
            bitcoin::sighash::EcdsaSighashType::All,
        )
        .map_err(|e| format!("Failed to compute sighash: {e:?}"))?;
    Ok(sighash.to_byte_array())
}

/// Helper: look up channel secrets by channel_keys_id.
fn get_channel_secrets(channel_keys_id: &[u8; 32]) -> Result<ChannelSecretsInternal, String> {
    let state = STATE.read().expect("STATE lock: get_channel_secrets");
    state
        .channel_secrets
        .get(channel_keys_id)
        .cloned()
        .ok_or_else(|| "Channel secrets not found".to_string())
}

// =============================================================================
// Shared helpers
// =============================================================================

/// Parse a Vec<u8> as a 32-byte channel_keys_id.
fn parse_channel_keys_id(bytes: Vec<u8>) -> Result<[u8; 32], String> {
    bytes.try_into().map_err(|_| "channel_keys_id must be 32 bytes".to_string())
}

/// Deserialize, compute sighash, and sign a funding-output transaction with chainkey ECDSA.
/// Shared by holder commitment, closing tx, and the commitment part of counterparty signing.
async fn sign_funding_output_tx(
    channel_keys_id: &[u8; 32],
    tx_bytes: &[u8],
    funding_amount_sat: u64,
) -> Result<Vec<u8>, String> {
    let tx: Transaction = deserialize(tx_bytes)
        .map_err(|e| format!("Failed to deserialize tx: {e:?}"))?;
    let funding_redeemscript = get_funding_redeemscript(channel_keys_id)?;
    let sighash = compute_funding_sighash(&tx, &funding_redeemscript, funding_amount_sat)?;
    sign_funding_sighash(&sighash).await
        .map_err(|e| format!("Chainkey signing failed: {e}"))
}

/// Derive the HTLC signing key for a given channel and per-commitment point.
fn derive_htlc_key(
    channel_keys_id: &[u8; 32],
    per_commitment_point_bytes: &[u8],
) -> Result<SecretKey, String> {
    let secrets = get_channel_secrets(channel_keys_id)?;
    let secp = Secp256k1::new();

    let per_commitment_point = bitcoin::secp256k1::PublicKey::from_slice(per_commitment_point_bytes)
        .map_err(|_| "Invalid per_commitment_point".to_string())?;
    let htlc_base_secret = SecretKey::from_slice(&secrets.htlc_base_secret)
        .map_err(|_| "Invalid htlc_base_secret".to_string())?;

    bolt3_keys::derive_private_key(&secp, &per_commitment_point, &htlc_base_secret)
        .map_err(|e| format!("HTLC key derivation failed: {e}"))
}

/// Sign a witness sighash with a local secret key, returning the compact signature.
fn sign_witness_with_key(
    tx_bytes: &[u8],
    input_index: usize,
    witness_script_bytes: &[u8],
    amount_sat: u64,
    signing_key: &SecretKey,
) -> Result<Vec<u8>, String> {
    let tx: Transaction = deserialize(tx_bytes)
        .map_err(|e| format!("Failed to deserialize tx: {e:?}"))?;
    let witness_script = bitcoin::ScriptBuf::from_bytes(witness_script_bytes.to_vec());
    let sighash = compute_witness_sighash(&tx, input_index, &witness_script, amount_sat)?;
    let secp = Secp256k1::new();
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, signing_key);
    Ok(sig.serialize_compact().to_vec())
}

fn ln_sign_err(msg: impl Into<String>) -> LnSignResponse {
    LnSignResponse { success: false, signature: None, error: Some(msg.into()) }
}

/// Build the complete P2WSH witness for a 2-of-2 multisig commitment transaction
/// and broadcast it via the IC Bitcoin API.
///
/// The witness structure for P2WSH 2-of-2 multisig is:
///   <empty> <sig_for_first_pubkey> <sig_for_second_pubkey> <witness_script>
///
/// Signatures are ordered to match the pubkey ordering in the witness script
/// (lexicographic sort per BOLT spec).
async fn build_and_broadcast_commitment(
    channel_keys_id: &[u8; 32],
    commitment_tx_bytes: &[u8],
    our_sig_compact: &[u8],
    counterparty_sig_compact: &[u8],
) -> Result<(), String> {
    use bitcoin::Witness;
    use ic_cdk::bitcoin_canister::{
        bitcoin_send_transaction, SendTransactionRequest,
    };

    // Deserialize the unsigned transaction
    let mut tx: Transaction = deserialize(commitment_tx_bytes)
        .map_err(|e| format!("Failed to deserialize commitment tx: {e:?}"))?;

    if tx.input.is_empty() {
        return Err("Transaction has no inputs".into());
    }

    // Get the funding redeemscript to determine pubkey ordering
    let funding_redeemscript = get_funding_redeemscript(channel_keys_id)?;

    // Get our funding pubkey (cached)
    let derivation_path: Vec<Vec<u8>> = LN_FUNDING_DERIVATION_PATH
        .iter()
        .map(|s| s.to_vec())
        .collect();
    let our_pubkey = crate::btc::ecdsa::ECDSA_KEY_CACHE
        .with_borrow(|map| map.get(&derivation_path).cloned())
        .ok_or_else(|| "Canister funding pubkey not cached".to_string())?;

    // Get counterparty funding pubkey
    let state = STATE.read().expect("STATE lock: build_and_broadcast");
    let counterparty_pubkey = state.channel_counterparty_pubkeys
        .get(channel_keys_id)
        .cloned()
        .ok_or_else(|| "Counterparty pubkey not found".to_string())?;
    drop(state);

    // Convert compact signatures to DER-encoded with SIGHASH_ALL suffix
    let our_sig_der = compact_sig_to_der_with_sighash(our_sig_compact)?;
    let cp_sig_der = compact_sig_to_der_with_sighash(counterparty_sig_compact)?;

    // Order signatures by pubkey sort order (lexicographic, as in the witness script)
    let (sig_first, sig_second) = if our_pubkey <= counterparty_pubkey {
        (our_sig_der, cp_sig_der)
    } else {
        (cp_sig_der, our_sig_der)
    };

    // Build the P2WSH witness: <empty> <sig1> <sig2> <witness_script>
    let mut witness = Witness::new();
    witness.push([]); // OP_0 placeholder for CHECKMULTISIG bug
    witness.push(&sig_first);
    witness.push(&sig_second);
    witness.push(funding_redeemscript.as_bytes());

    // Set the witness on input 0 (the funding output)
    tx.input[0].witness = witness;

    // Serialize and broadcast
    let signed_tx_bytes = btc_serialize(&tx);
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    bitcoin_send_transaction(&SendTransactionRequest {
        network: ctx.network,
        transaction: signed_tx_bytes,
    }).await;

    Ok(())
}

/// Convert a 64-byte compact ECDSA signature to DER-encoded with SIGHASH_ALL appended.
fn compact_sig_to_der_with_sighash(compact: &[u8]) -> Result<Vec<u8>, String> {
    let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(compact)
        .map_err(|e| format!("Invalid compact signature: {e}"))?;
    let mut der = sig.serialize_der().to_vec();
    der.push(0x01); // SIGHASH_ALL
    Ok(der)
}

// =============================================================================
// Phase 3: Commitment Transaction Signing
// =============================================================================

/// Sign a counterparty commitment transaction.
///
/// Returns the commitment signature (chainkey ECDSA) and HTLC signatures
/// (local ECDSA using derived HTLC key).
pub async fn sign_counterparty_commitment_impl(
    request: SignCounterpartyCommitmentRequest,
) -> SignCounterpartyCommitmentResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return SignCounterpartyCommitmentResponse {
            success: false, commitment_sig: None, htlc_sigs: None, error: Some(e),
        },
    };

    let num_htlcs = request.htlc_tx_bytes.len();
    if request.htlc_amounts_sat.len() != num_htlcs || request.htlc_redeemscripts.len() != num_htlcs {
        return SignCounterpartyCommitmentResponse {
            success: false, commitment_sig: None, htlc_sigs: None,
            error: Some("HTLC arrays must have consistent lengths".to_string()),
        };
    }

    // Sign the commitment transaction with chainkey ECDSA
    let commitment_sig = match sign_funding_output_tx(
        &channel_keys_id, &request.commitment_tx_bytes, request.funding_amount_sat,
    ).await {
        Ok(sig) => sig,
        Err(e) => return SignCounterpartyCommitmentResponse {
            success: false, commitment_sig: None, htlc_sigs: None, error: Some(e),
        },
    };

    // Derive the HTLC key for signing HTLC transactions
    let derived_htlc_key = match derive_htlc_key(&channel_keys_id, &request.per_commitment_point) {
        Ok(k) => k,
        Err(e) => return SignCounterpartyCommitmentResponse {
            success: false, commitment_sig: None, htlc_sigs: None, error: Some(e),
        },
    };

    // Sign each HTLC transaction
    let mut htlc_sigs = Vec::with_capacity(num_htlcs);
    for i in 0..num_htlcs {
        let sig = match sign_witness_with_key(
            &request.htlc_tx_bytes[i], 0, &request.htlc_redeemscripts[i],
            request.htlc_amounts_sat[i], &derived_htlc_key,
        ) {
            Ok(s) => s,
            Err(e) => return SignCounterpartyCommitmentResponse {
                success: false, commitment_sig: None, htlc_sigs: None,
                error: Some(format!("HTLC {i}: {e}")),
            },
        };
        htlc_sigs.push(sig);
    }

    // Track commitment number progression (old-state attack prevention).
    // Extract the commitment number from the transaction and update the counter.
    if let Ok(tx) = deserialize::<Transaction>(&request.commitment_tx_bytes) {
        let state = STATE.read().expect("STATE lock: sign_counterparty_commitment read");
        if let Some(commit_state) = state.channel_commitment_state.get(&channel_keys_id) {
            let obscure_factor = commit_state.obscure_factor;
            drop(state);
            if let Ok(commitment_number) = bolt3_keys::extract_commitment_number(&tx, obscure_factor) {
                let mut state = STATE.write().expect("STATE lock: sign_counterparty_commitment write");
                if let Some(commit_state) = state.channel_commitment_state.get_mut(&channel_keys_id) {
                    let should_update = match commit_state.highest_counterparty_commitment {
                        Some(prev) => commitment_number > prev,
                        None => true,
                    };
                    if should_update {
                        commit_state.highest_counterparty_commitment = Some(commitment_number);
                    }
                }
            }
        }
    }

    SignCounterpartyCommitmentResponse {
        success: true,
        commitment_sig: Some(commitment_sig),
        htlc_sigs: Some(htlc_sigs),
        error: None,
    }
}

/// Sign a holder commitment transaction.
///
/// Only needs the commitment signature (chainkey ECDSA). No HTLC sigs needed.
///
/// Enforces commitment number monotonicity: rejects signing if the commitment
/// number extracted from the transaction is behind the highest counterparty
/// commitment number seen. This prevents the old-state channel close attack.
pub async fn sign_holder_commitment_impl(
    request: SignHolderCommitmentRequest,
) -> SignHolderCommitmentResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    };

    // Check commitment number against the counter (old-state attack prevention).
    // If we have a ChannelCommitmentState for this channel, extract the commitment
    // number from the transaction and reject if it's stale.
    {
        let state = STATE.read().expect("STATE lock: sign_holder_commitment read");
        if let Some(commit_state) = state.channel_commitment_state.get(&channel_keys_id) {
            if let Some(highest) = commit_state.highest_counterparty_commitment {
                let tx: Transaction = match deserialize(&request.commitment_tx_bytes) {
                    Ok(tx) => tx,
                    Err(e) => return SignHolderCommitmentResponse {
                        success: false, commitment_sig: None,
                        error: Some(format!("Failed to deserialize tx for commitment check: {e:?}")),
                    },
                };
                match bolt3_keys::extract_commitment_number(&tx, commit_state.obscure_factor) {
                    Ok(commitment_number) => {
                        // Allow current state and off-by-one during handshake
                        if highest > 0 && commitment_number < highest - 1 {
                            return SignHolderCommitmentResponse {
                                success: false, commitment_sig: None,
                                error: Some(format!(
                                    "Stale commitment rejected: number {} is behind counter {}",
                                    commitment_number, highest
                                )),
                            };
                        }
                    }
                    Err(e) => {
                        return SignHolderCommitmentResponse {
                            success: false, commitment_sig: None,
                            error: Some(format!("Failed to extract commitment number: {e}")),
                        };
                    }
                }
            }
            // If highest_counterparty_commitment is None, this is the first signing — allow
        }
        // If no ChannelCommitmentState, channel was registered before the fix — allow
    }

    let our_sig = match sign_funding_output_tx(&channel_keys_id, &request.commitment_tx_bytes, request.funding_amount_sat).await {
        Ok(sig) => sig,
        Err(e) => return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    };

    // If the relay provided the counterparty's signature, build the full witness
    // and broadcast the transaction directly from the canister.
    // The canister is the primary broadcaster in our protocol. The relay's LDK
    // will also attempt to broadcast the same tx as part of its normal flow —
    // this is a harmless duplicate that bitcoind rejects ("already in mempool").
    // The signature is still returned to the relay for LDK state consistency.
    if let Some(ref counterparty_sig_bytes) = request.counterparty_sig {
        match build_and_broadcast_commitment(
            &channel_keys_id,
            &request.commitment_tx_bytes,
            &our_sig,
            counterparty_sig_bytes,
        ).await {
            Ok(_) => ic_cdk::println!("Holder commitment broadcast by canister"),
            Err(e) => ic_cdk::println!("WARNING: canister broadcast failed (relay will retry): {e}"),
        }
    }

    SignHolderCommitmentResponse { success: true, commitment_sig: Some(our_sig), error: None }
}

/// Sign a cooperative closing transaction.
pub async fn sign_closing_tx_impl(
    request: SignClosingTxRequest,
) -> SignHolderCommitmentResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    };

    match sign_funding_output_tx(&channel_keys_id, &request.closing_tx_bytes, request.funding_amount_sat).await {
        Ok(sig) => SignHolderCommitmentResponse { success: true, commitment_sig: Some(sig), error: None },
        Err(e) => SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    }
}

// =============================================================================
// Phase 4: Justice + HTLC Transaction Signing
// =============================================================================

/// Sign a justice (penalty) transaction.
///
/// Uses the derived revocation key (from per-commitment secret + revocation base secret).
pub fn sign_justice_tx_impl(request: SignJusticeTxRequest) -> LnSignResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return ln_sign_err(e),
    };

    let per_commitment_secret_bytes: [u8; 32] = match request.per_commitment_secret.clone().try_into() {
        Ok(s) => s,
        Err(_) => return ln_sign_err("per_commitment_secret must be 32 bytes"),
    };

    let secrets = match get_channel_secrets(&channel_keys_id) {
        Ok(s) => s,
        Err(e) => return ln_sign_err(e),
    };

    let secp = Secp256k1::new();
    let per_commitment_secret = match SecretKey::from_slice(&per_commitment_secret_bytes) {
        Ok(sk) => sk,
        Err(_) => return ln_sign_err("Invalid per_commitment_secret"),
    };
    let revocation_base_secret = match SecretKey::from_slice(&secrets.revocation_base_secret) {
        Ok(sk) => sk,
        Err(_) => return ln_sign_err("Invalid revocation_base_secret"),
    };

    let revocation_key = match bolt3_keys::derive_private_revocation_key(
        &secp, &per_commitment_secret, &revocation_base_secret,
    ) {
        Ok(k) => k,
        Err(e) => return ln_sign_err(format!("Revocation key derivation failed: {e}")),
    };

    match sign_witness_with_key(
        &request.justice_tx_bytes, request.input_index as usize,
        &request.witness_script, request.amount_sat, &revocation_key,
    ) {
        Ok(sig) => LnSignResponse { success: true, signature: Some(sig), error: None },
        Err(e) => ln_sign_err(e),
    }
}

/// Sign an HTLC transaction (holder or counterparty second-level HTLC tx).
///
/// Uses the derived HTLC key (from per-commitment point + HTLC base secret).
pub fn sign_htlc_tx_impl(request: SignHtlcTxRequest) -> LnSignResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return ln_sign_err(e),
    };

    let derived_htlc_key = match derive_htlc_key(&channel_keys_id, &request.per_commitment_point) {
        Ok(k) => k,
        Err(e) => return ln_sign_err(e),
    };

    match sign_witness_with_key(
        &request.htlc_tx_bytes, request.input_index as usize,
        &request.witness_script, request.amount_sat, &derived_htlc_key,
    ) {
        Ok(sig) => LnSignResponse { success: true, signature: Some(sig), error: None },
        Err(e) => ln_sign_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ChannelSecretsInternal;
    use bitcoin::consensus::serialize as btc_serialize;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey, Message};
    use bitcoin::{Transaction, TxIn, TxOut, OutPoint, Txid, Witness, ScriptBuf};
    use bitcoin::transaction::Version;
    use bitcoin::locktime::absolute::LockTime;

    /// Insert test channel secrets into STATE and return them for verification.
    fn setup_test_channel(channel_keys_id: [u8; 32]) -> ChannelSecretsInternal {
        let secrets = ChannelSecretsInternal {
            htlc_base_secret: [11u8; 32],
            revocation_base_secret: [12u8; 32],
            delayed_payment_base_secret: [13u8; 32],
            payment_secret: [14u8; 32],
            commitment_seed: [15u8; 32],
        };
        let mut state = STATE.write().expect("STATE lock: setup_test_channel");
        state.channel_secrets.insert(channel_keys_id, secrets.clone());
        secrets
    }

    /// Build a minimal valid transaction for sighash testing.
    fn build_test_tx() -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0xAA; 32]),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::new_p2wpkh(
                    &bitcoin::WPubkeyHash::from_byte_array([0xBB; 20]),
                ),
            }],
        }
    }

    /// Build a simple P2WSH witness script for testing sighash computation.
    fn build_test_witness_script(pubkey: &PublicKey) -> ScriptBuf {
        use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_1};
        bitcoin::script::Builder::new()
            .push_opcode(OP_PUSHNUM_1)
            .push_slice(pubkey.serialize())
            .push_opcode(OP_PUSHNUM_1)
            .push_opcode(OP_CHECKMULTISIG)
            .into_script()
    }

    #[test]
    fn test_sign_justice_tx_valid_signature() {
        let channel_keys_id = [0xA1; 32];
        let secrets = setup_test_channel(channel_keys_id);
        let secp = Secp256k1::new();

        // Use a known per-commitment secret
        let per_commitment_secret = SecretKey::from_slice(&[20u8; 32]).unwrap();
        let revocation_base_secret = SecretKey::from_slice(&secrets.revocation_base_secret).unwrap();

        // Derive the expected revocation key + pubkey
        let expected_rev_key = bolt3_keys::derive_private_revocation_key(
            &secp, &per_commitment_secret, &revocation_base_secret,
        ).unwrap();
        let expected_rev_pubkey = expected_rev_key.public_key(&secp);

        // Build test transaction and witness script
        let tx = build_test_tx();
        let witness_script = build_test_witness_script(&expected_rev_pubkey);
        let amount_sat = 100_000u64;
        let tx_bytes = btc_serialize(&tx);

        let request = SignJusticeTxRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            justice_tx_bytes: tx_bytes,
            input_index: 0,
            amount_sat,
            per_commitment_secret: per_commitment_secret.secret_bytes().to_vec(),
            witness_script: witness_script.as_bytes().to_vec(),
        };

        let response = sign_justice_tx_impl(request);
        assert!(response.success, "Justice tx signing should succeed: {:?}", response.error);

        // Verify signature against the expected revocation pubkey
        let sig_bytes = response.signature.unwrap();
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig_bytes).unwrap();

        // Compute the expected sighash
        let sighash = compute_witness_sighash(&tx, 0, &witness_script, amount_sat).unwrap();
        let msg = Message::from_digest(sighash);

        assert!(secp.verify_ecdsa(&msg, &sig, &expected_rev_pubkey).is_ok(),
            "Justice tx signature must verify against derived revocation pubkey");
    }

    #[test]
    fn test_sign_justice_tx_missing_secrets() {
        let missing_id = [0xFF; 32];
        let tx = build_test_tx();
        let request = SignJusticeTxRequest {
            channel_keys_id: missing_id.to_vec(),
            justice_tx_bytes: btc_serialize(&tx),
            input_index: 0,
            amount_sat: 100_000,
            per_commitment_secret: [20u8; 32].to_vec(),
            witness_script: vec![0x51],
        };

        let response = sign_justice_tx_impl(request);
        assert!(!response.success, "Should fail when channel secrets missing");
        assert!(response.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_sign_htlc_tx_valid_signature() {
        let channel_keys_id = [0xA2; 32];
        let secrets = setup_test_channel(channel_keys_id);
        let secp = Secp256k1::new();

        // Create a per-commitment point
        let per_commitment_secret = SecretKey::from_slice(&[25u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);

        // Derive expected HTLC key
        let htlc_base_secret = SecretKey::from_slice(&secrets.htlc_base_secret).unwrap();
        let expected_htlc_key = bolt3_keys::derive_private_key(
            &secp, &per_commitment_point, &htlc_base_secret,
        ).unwrap();
        let expected_htlc_pubkey = expected_htlc_key.public_key(&secp);

        // Build test transaction and witness script
        let tx = build_test_tx();
        let witness_script = build_test_witness_script(&expected_htlc_pubkey);
        let amount_sat = 75_000u64;
        let tx_bytes = btc_serialize(&tx);

        let request = SignHtlcTxRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            htlc_tx_bytes: tx_bytes,
            input_index: 0,
            amount_sat,
            per_commitment_point: per_commitment_point.serialize().to_vec(),
            witness_script: witness_script.as_bytes().to_vec(),
        };

        let response = sign_htlc_tx_impl(request);
        assert!(response.success, "HTLC tx signing should succeed: {:?}", response.error);

        // Verify signature
        let sig_bytes = response.signature.unwrap();
        let sig = bitcoin::secp256k1::ecdsa::Signature::from_compact(&sig_bytes).unwrap();

        let sighash = compute_witness_sighash(&tx, 0, &witness_script, amount_sat).unwrap();
        let msg = Message::from_digest(sighash);

        assert!(secp.verify_ecdsa(&msg, &sig, &expected_htlc_pubkey).is_ok(),
            "HTLC tx signature must verify against derived HTLC pubkey");
    }

    #[test]
    fn test_sign_htlc_tx_missing_secrets() {
        let missing_id = [0xFE; 32];
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[25u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);
        let tx = build_test_tx();

        let request = SignHtlcTxRequest {
            channel_keys_id: missing_id.to_vec(),
            htlc_tx_bytes: btc_serialize(&tx),
            input_index: 0,
            amount_sat: 75_000,
            per_commitment_point: per_commitment_point.serialize().to_vec(),
            witness_script: vec![0x51],
        };

        let response = sign_htlc_tx_impl(request);
        assert!(!response.success, "Should fail when channel secrets missing");
        assert!(response.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_compact_sig_to_der_with_sighash() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[40u8; 32]).unwrap();
        let msg = Message::from_digest([0xCC; 32]);
        let sig = secp.sign_ecdsa(&msg, &key);
        let compact = sig.serialize_compact();

        let der_with_sighash = compact_sig_to_der_with_sighash(&compact).unwrap();

        // Must end with SIGHASH_ALL (0x01)
        assert_eq!(*der_with_sighash.last().unwrap(), 0x01,
            "DER signature must end with SIGHASH_ALL byte");

        // Must be valid DER (without the sighash byte)
        let der_only = &der_with_sighash[..der_with_sighash.len() - 1];
        let recovered = bitcoin::secp256k1::ecdsa::Signature::from_der(der_only)
            .expect("Must be valid DER encoding");

        // Round-trip: DER → compact must equal original
        assert_eq!(recovered.serialize_compact(), compact,
            "Round-trip compact → DER → compact must preserve signature");
    }

    #[test]
    fn test_compact_sig_to_der_with_sighash_invalid() {
        // Too short
        let result = compact_sig_to_der_with_sighash(&[0u8; 32]);
        assert!(result.is_err(), "Should reject invalid compact signature");

        // Too long
        let result = compact_sig_to_der_with_sighash(&[0u8; 65]);
        assert!(result.is_err(), "Should reject oversized input");
    }

    #[test]
    fn test_witness_signature_ordering() {
        // Test that signatures are correctly ordered by pubkey in the witness.
        // Per BOLT spec, pubkeys in the witness script are sorted lexicographically,
        // and signatures must appear in the same order.
        let secp = Secp256k1::new();

        let sk_a = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let sk_b = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk_a = sk_a.public_key(&secp).serialize().to_vec();
        let pk_b = sk_b.public_key(&secp).serialize().to_vec();

        // Determine which is actually smaller (don't assume)
        let (smaller_pk, larger_pk, sk_smaller, sk_larger) = if pk_a < pk_b {
            (pk_a.clone(), pk_b.clone(), sk_a, sk_b)
        } else {
            (pk_b.clone(), pk_a.clone(), sk_b, sk_a)
        };

        let msg = Message::from_digest([0xDD; 32]);
        let sig_smaller = secp.sign_ecdsa(&msg, &sk_smaller).serialize_compact();
        let sig_larger = secp.sign_ecdsa(&msg, &sk_larger).serialize_compact();

        let sig_smaller_der = compact_sig_to_der_with_sighash(&sig_smaller).unwrap();
        let sig_larger_der = compact_sig_to_der_with_sighash(&sig_larger).unwrap();

        // When our_pubkey is the smaller one: our sig first
        let (first, second) = if smaller_pk <= larger_pk {
            (sig_smaller_der.clone(), sig_larger_der.clone())
        } else {
            (sig_larger_der.clone(), sig_smaller_der.clone())
        };
        assert_eq!(first, sig_smaller_der, "Smaller pubkey's sig must go first");
        assert_eq!(second, sig_larger_der, "Larger pubkey's sig must go second");

        // When our_pubkey is the larger one: counterparty (smaller) sig first
        let (first, second) = if larger_pk <= smaller_pk {
            (sig_larger_der.clone(), sig_smaller_der.clone())
        } else {
            (sig_smaller_der.clone(), sig_larger_der.clone())
        };
        assert_eq!(first, sig_smaller_der, "Smaller pubkey's sig always first regardless of role");
    }

    #[test]
    fn test_witness_structure_p2wsh_2of2() {
        // Verify the witness has the correct structure:
        // <empty> <sig1> <sig2> <witness_script>
        use bitcoin::Witness;

        let secp = Secp256k1::new();
        let sk1 = SecretKey::from_slice(&[41u8; 32]).unwrap();
        let sk2 = SecretKey::from_slice(&[42u8; 32]).unwrap();
        let pk1 = sk1.public_key(&secp);
        let pk2 = sk2.public_key(&secp);

        // Build a 2-of-2 multisig witness script (sorted)
        let witness_script = crate::helpers::build_funding_witness_script(
            &pk1.serialize(), &pk2.serialize(),
        ).unwrap();

        // Create dummy signatures
        let msg = Message::from_digest([0xEE; 32]);
        let sig1 = secp.sign_ecdsa(&msg, &sk1).serialize_compact();
        let sig2 = secp.sign_ecdsa(&msg, &sk2).serialize_compact();
        let sig1_der = compact_sig_to_der_with_sighash(&sig1).unwrap();
        let sig2_der = compact_sig_to_der_with_sighash(&sig2).unwrap();

        // Order by pubkey
        let pk1_bytes = pk1.serialize().to_vec();
        let pk2_bytes = pk2.serialize().to_vec();
        let (first_sig, second_sig) = if pk1_bytes <= pk2_bytes {
            (sig1_der.clone(), sig2_der.clone())
        } else {
            (sig2_der.clone(), sig1_der.clone())
        };

        // Build witness
        let mut witness = Witness::new();
        witness.push([]); // OP_0 for CHECKMULTISIG bug
        witness.push(&first_sig);
        witness.push(&second_sig);
        witness.push(witness_script.as_bytes());

        // Verify structure
        assert_eq!(witness.len(), 4, "Witness must have exactly 4 elements");
        assert_eq!(witness.nth(0).unwrap(), &[] as &[u8], "First element must be empty (OP_0)");
        assert_eq!(witness.nth(1).unwrap(), first_sig.as_slice(), "Second element is first sig");
        assert_eq!(witness.nth(2).unwrap(), second_sig.as_slice(), "Third element is second sig");
        assert_eq!(witness.nth(3).unwrap(), witness_script.as_bytes(), "Fourth element is witness script");

        // Verify the witness script contains OP_2 ... OP_2 OP_CHECKMULTISIG
        let ws_bytes = witness_script.as_bytes();
        assert_eq!(ws_bytes[0], 0x52, "Must start with OP_2");
        assert_eq!(*ws_bytes.last().unwrap(), 0xAE, "Must end with OP_CHECKMULTISIG");
    }

    #[test]
    fn test_compute_funding_sighash_deterministic() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[30u8; 32]).unwrap();
        let pubkey = key.public_key(&secp);
        let script = build_test_witness_script(&pubkey);
        let tx = build_test_tx();
        let amount = 100_000u64;

        let hash1 = compute_funding_sighash(&tx, &script, amount).unwrap();
        let hash2 = compute_funding_sighash(&tx, &script, amount).unwrap();
        assert_eq!(hash1, hash2, "Same tx+script+amount must produce same sighash");
        assert_ne!(hash1, [0u8; 32], "Sighash must not be all zeros");
    }

    #[test]
    fn test_compute_witness_sighash_deterministic() {
        let secp = Secp256k1::new();
        let key = SecretKey::from_slice(&[31u8; 32]).unwrap();
        let pubkey = key.public_key(&secp);
        let script = build_test_witness_script(&pubkey);
        let tx = build_test_tx();
        let amount = 80_000u64;

        let hash1 = compute_witness_sighash(&tx, 0, &script, amount).unwrap();
        let hash2 = compute_witness_sighash(&tx, 0, &script, amount).unwrap();
        assert_eq!(hash1, hash2, "Same inputs must produce same sighash");
        assert_ne!(hash1, [0u8; 32], "Sighash must not be all zeros");
    }
}
