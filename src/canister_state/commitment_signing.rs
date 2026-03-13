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

use bitcoin::consensus::deserialize;
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
        .map_err(|e| format!("Failed to compute sighash: {:?}", e))?;
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
        .map_err(|e| format!("Failed to compute sighash: {:?}", e))?;
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
        .map_err(|e| format!("Failed to deserialize tx: {:?}", e))?;
    let funding_redeemscript = get_funding_redeemscript(channel_keys_id)?;
    let sighash = compute_funding_sighash(&tx, &funding_redeemscript, funding_amount_sat)?;
    sign_funding_sighash(&sighash).await
        .map_err(|e| format!("Chainkey signing failed: {}", e))
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
        .map_err(|e| format!("HTLC key derivation failed: {}", e))
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
        .map_err(|e| format!("Failed to deserialize tx: {:?}", e))?;
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
                error: Some(format!("HTLC {}: {}", i, e)),
            },
        };
        htlc_sigs.push(sig);
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
pub async fn sign_holder_commitment_impl(
    request: SignHolderCommitmentRequest,
) -> SignHolderCommitmentResponse {
    let channel_keys_id = match parse_channel_keys_id(request.channel_keys_id.clone()) {
        Ok(id) => id,
        Err(e) => return SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    };

    match sign_funding_output_tx(&channel_keys_id, &request.commitment_tx_bytes, request.funding_amount_sat).await {
        Ok(sig) => SignHolderCommitmentResponse { success: true, commitment_sig: Some(sig), error: None },
        Err(e) => SignHolderCommitmentResponse { success: false, commitment_sig: None, error: Some(e) },
    }
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
        Err(e) => return ln_sign_err(format!("Revocation key derivation failed: {}", e)),
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
            .push_slice(&pubkey.serialize())
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
