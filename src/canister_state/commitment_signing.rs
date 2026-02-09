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
    let state = STATE.read().unwrap();
    let counterparty_pubkey = state
        .channel_counterparty_pubkeys
        .get(channel_keys_id)
        .ok_or_else(|| "Counterparty funding pubkey not registered".to_string())?
        .clone();
    drop(state);

    // Get canister's funding pubkey
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());
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
    let state = STATE.read().unwrap();
    state
        .channel_secrets
        .get(channel_keys_id)
        .cloned()
        .ok_or_else(|| "Channel secrets not found".to_string())
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
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    // Validate HTLC arrays are consistent
    let num_htlcs = request.htlc_tx_bytes.len();
    if request.htlc_amounts_sat.len() != num_htlcs || request.htlc_redeemscripts.len() != num_htlcs {
        return SignCounterpartyCommitmentResponse {
            success: false,
            commitment_sig: None,
            htlc_sigs: None,
            error: Some("HTLC arrays must have consistent lengths".to_string()),
        };
    }

    // Deserialize commitment transaction
    let commitment_tx: Transaction = match deserialize(&request.commitment_tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(format!("Failed to deserialize commitment tx: {:?}", e)),
            };
        }
    };

    // Get the funding redeemscript
    let funding_redeemscript = match get_funding_redeemscript(&channel_keys_id) {
        Ok(script) => script,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(e),
            };
        }
    };

    // Compute commitment sighash
    let sighash = match compute_funding_sighash(
        &commitment_tx,
        &funding_redeemscript,
        request.funding_amount_sat,
    ) {
        Ok(h) => h,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(e),
            };
        }
    };

    // Sign commitment with chainkey ECDSA
    let commitment_sig = match sign_funding_sighash(&sighash).await {
        Ok(sig) => sig,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(format!("Chainkey signing failed: {}", e)),
            };
        }
    };

    // Sign each HTLC transaction with derived HTLC key
    let secrets = match get_channel_secrets(&channel_keys_id) {
        Ok(s) => s,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(e),
            };
        }
    };

    // Parse per-commitment point
    let per_commitment_point = match bitcoin::secp256k1::PublicKey::from_slice(&request.per_commitment_point) {
        Ok(p) => p,
        Err(_) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some("Invalid per_commitment_point".to_string()),
            };
        }
    };

    let secp = Secp256k1::new();
    let htlc_base_secret = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some("Invalid HTLC base secret".to_string()),
            };
        }
    };

    // Derive the HTLC key for this commitment
    let derived_htlc_key = match bolt3_keys::derive_private_key(
        &secp,
        &per_commitment_point,
        &htlc_base_secret,
    ) {
        Ok(k) => k,
        Err(e) => {
            return SignCounterpartyCommitmentResponse {
                success: false,
                commitment_sig: None,
                htlc_sigs: None,
                error: Some(format!("HTLC key derivation failed: {}", e)),
            };
        }
    };

    let mut htlc_sigs = Vec::with_capacity(num_htlcs);
    for i in 0..num_htlcs {
        // Deserialize HTLC transaction
        let htlc_tx: Transaction = match deserialize(&request.htlc_tx_bytes[i]) {
            Ok(tx) => tx,
            Err(e) => {
                return SignCounterpartyCommitmentResponse {
                    success: false,
                    commitment_sig: None,
                    htlc_sigs: None,
                    error: Some(format!("Failed to deserialize HTLC tx {}: {:?}", i, e)),
                };
            }
        };

        let htlc_redeemscript = bitcoin::ScriptBuf::from_bytes(request.htlc_redeemscripts[i].clone());

        // Compute HTLC sighash
        let htlc_sighash = match compute_witness_sighash(
            &htlc_tx,
            0, // HTLC txs always sign input 0
            &htlc_redeemscript,
            request.htlc_amounts_sat[i],
        ) {
            Ok(h) => h,
            Err(e) => {
                return SignCounterpartyCommitmentResponse {
                    success: false,
                    commitment_sig: None,
                    htlc_sigs: None,
                    error: Some(format!("HTLC {} sighash failed: {}", i, e)),
                };
            }
        };

        // Sign with local ECDSA
        let msg = match Message::from_digest(htlc_sighash) {
            msg => msg,
        };
        let sig = secp.sign_ecdsa(&msg, &derived_htlc_key);
        htlc_sigs.push(sig.serialize_compact().to_vec());
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
/// Only needs the commitment signature (chainkey ECDSA). No HTLC sigs needed
/// for holder commitments.
pub async fn sign_holder_commitment_impl(
    request: SignHolderCommitmentRequest,
) -> SignHolderCommitmentResponse {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    // Deserialize commitment transaction
    let commitment_tx: Transaction = match deserialize(&request.commitment_tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(format!("Failed to deserialize commitment tx: {:?}", e)),
            };
        }
    };

    // Get the funding redeemscript
    let funding_redeemscript = match get_funding_redeemscript(&channel_keys_id) {
        Ok(script) => script,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(e),
            };
        }
    };

    // Compute sighash
    let sighash = match compute_funding_sighash(
        &commitment_tx,
        &funding_redeemscript,
        request.funding_amount_sat,
    ) {
        Ok(h) => h,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(e),
            };
        }
    };

    // Sign with chainkey ECDSA
    let commitment_sig = match sign_funding_sighash(&sighash).await {
        Ok(sig) => sig,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(format!("Chainkey signing failed: {}", e)),
            };
        }
    };

    SignHolderCommitmentResponse {
        success: true,
        commitment_sig: Some(commitment_sig),
        error: None,
    }
}

/// Sign a cooperative closing transaction.
pub async fn sign_closing_tx_impl(
    request: SignClosingTxRequest,
) -> SignHolderCommitmentResponse {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    // Deserialize closing transaction
    let closing_tx: Transaction = match deserialize(&request.closing_tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(format!("Failed to deserialize closing tx: {:?}", e)),
            };
        }
    };

    // Get the funding redeemscript
    let funding_redeemscript = match get_funding_redeemscript(&channel_keys_id) {
        Ok(script) => script,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(e),
            };
        }
    };

    // Compute sighash
    let sighash = match compute_funding_sighash(
        &closing_tx,
        &funding_redeemscript,
        request.funding_amount_sat,
    ) {
        Ok(h) => h,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(e),
            };
        }
    };

    // Sign with chainkey ECDSA
    let sig = match sign_funding_sighash(&sighash).await {
        Ok(sig) => sig,
        Err(e) => {
            return SignHolderCommitmentResponse {
                success: false,
                commitment_sig: None,
                error: Some(format!("Chainkey signing failed: {}", e)),
            };
        }
    };

    SignHolderCommitmentResponse {
        success: true,
        commitment_sig: Some(sig),
        error: None,
    }
}

// =============================================================================
// Phase 4: Justice + HTLC Transaction Signing
// =============================================================================

/// Sign a justice (penalty) transaction.
///
/// Uses the derived revocation key (from per-commitment secret + revocation base secret).
/// Local ECDSA only — no chainkey needed.
pub fn sign_justice_tx_impl(request: SignJusticeTxRequest) -> LnSignResponse {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    let per_commitment_secret_bytes: [u8; 32] = match request.per_commitment_secret.clone().try_into() {
        Ok(s) => s,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("per_commitment_secret must be 32 bytes".to_string()),
            };
        }
    };

    let secrets = match get_channel_secrets(&channel_keys_id) {
        Ok(s) => s,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(e),
            };
        }
    };

    let secp = Secp256k1::new();

    let per_commitment_secret = match SecretKey::from_slice(&per_commitment_secret_bytes) {
        Ok(sk) => sk,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("Invalid per_commitment_secret".to_string()),
            };
        }
    };

    let revocation_base_secret = match SecretKey::from_slice(&secrets.revocation_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("Invalid revocation_base_secret".to_string()),
            };
        }
    };

    // Derive the revocation key
    let revocation_key = match bolt3_keys::derive_private_revocation_key(
        &secp,
        &per_commitment_secret,
        &revocation_base_secret,
    ) {
        Ok(k) => k,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(format!("Revocation key derivation failed: {}", e)),
            };
        }
    };

    // Deserialize justice transaction
    let justice_tx: Transaction = match deserialize(&request.justice_tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(format!("Failed to deserialize justice tx: {:?}", e)),
            };
        }
    };

    let witness_script = bitcoin::ScriptBuf::from_bytes(request.witness_script);

    // Compute sighash
    let sighash = match compute_witness_sighash(
        &justice_tx,
        request.input_index as usize,
        &witness_script,
        request.amount_sat,
    ) {
        Ok(h) => h,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(e),
            };
        }
    };

    // Sign with local ECDSA
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, &revocation_key);

    LnSignResponse {
        success: true,
        signature: Some(sig.serialize_compact().to_vec()),
        error: None,
    }
}

/// Sign an HTLC transaction (holder or counterparty second-level HTLC tx).
///
/// Uses the derived HTLC key (from per-commitment point + HTLC base secret).
/// Local ECDSA only — no chainkey needed.
pub fn sign_htlc_tx_impl(request: SignHtlcTxRequest) -> LnSignResponse {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    let secrets = match get_channel_secrets(&channel_keys_id) {
        Ok(s) => s,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(e),
            };
        }
    };

    let secp = Secp256k1::new();

    // Parse per-commitment point
    let per_commitment_point = match bitcoin::secp256k1::PublicKey::from_slice(&request.per_commitment_point) {
        Ok(p) => p,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("Invalid per_commitment_point".to_string()),
            };
        }
    };

    let htlc_base_secret = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some("Invalid htlc_base_secret".to_string()),
            };
        }
    };

    // Derive the HTLC key for this commitment
    let derived_htlc_key = match bolt3_keys::derive_private_key(
        &secp,
        &per_commitment_point,
        &htlc_base_secret,
    ) {
        Ok(k) => k,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(format!("HTLC key derivation failed: {}", e)),
            };
        }
    };

    // Deserialize HTLC transaction
    let htlc_tx: Transaction = match deserialize(&request.htlc_tx_bytes) {
        Ok(tx) => tx,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(format!("Failed to deserialize HTLC tx: {:?}", e)),
            };
        }
    };

    let witness_script = bitcoin::ScriptBuf::from_bytes(request.witness_script);

    // Compute sighash
    let sighash = match compute_witness_sighash(
        &htlc_tx,
        request.input_index as usize,
        &witness_script,
        request.amount_sat,
    ) {
        Ok(h) => h,
        Err(e) => {
            return LnSignResponse {
                success: false,
                signature: None,
                error: Some(e),
            };
        }
    };

    // Sign with local ECDSA
    let msg = Message::from_digest(sighash);
    let sig = secp.sign_ecdsa(&msg, &derived_htlc_key);

    LnSignResponse {
        success: true,
        signature: Some(sig.serialize_compact().to_vec()),
        error: None,
    }
}
