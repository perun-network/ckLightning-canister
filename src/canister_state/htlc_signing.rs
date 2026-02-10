// =============================================================================
// Channel Secrets Management (Phase 2)
// + HTLC with Transaction Details (Phase 2)
// + HTLC Signing (Phase 2)
// =============================================================================

use super::{STATE, ChannelSecretsInternal, HtlcTxDetails};
use crate::htlc::{
    build_htlc_witness_script, build_htlc_success_tx, build_htlc_timeout_tx,
    sign_htlc_input, apply_htlc_success_witness, apply_htlc_timeout_witness,
    verify_preimage,
};
use crate::ic_types::{
    ChannelSecretsInfo,
    CreateHtlcWithTxDetailsRequest, CreateHtlcWithTxDetailsResponse,
    SignHtlcSuccessRequest, SignHtlcTimeoutRequest, SignHtlcResponse,
    GenerateChannelSecretsRequest, GenerateChannelSecretsResponse,
    GetPerCommitmentPointRequest, GetPerCommitmentPointResponse,
    ReleaseCommitmentSecretRequest, ReleaseCommitmentSecretResponse,
    RegisterChannelInfoRequest,
};
use super::bolt3_keys;

use bitcoin::hashes::Hash;
use bitcoin::consensus::serialize;

// =============================================================================
// Channel Secrets Management
// =============================================================================

/// Query channel secrets info (public keys only, secrets are never exposed).
pub fn get_channel_secrets_info_impl(channel_id: Vec<u8>) -> Option<ChannelSecretsInfo> {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let channel_id: [u8; 32] = channel_id.try_into().ok()?;
    let state = STATE.read().unwrap();
    let secrets = state.channel_secrets.get(&channel_id)?;

    let secp = Secp256k1::new();

    let htlc_basepoint = SecretKey::from_slice(&secrets.htlc_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let revocation_basepoint = SecretKey::from_slice(&secrets.revocation_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let delayed_payment_basepoint = SecretKey::from_slice(&secrets.delayed_payment_base_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    let payment_point = SecretKey::from_slice(&secrets.payment_secret)
        .ok()?
        .public_key(&secp)
        .serialize()
        .to_vec();

    Some(ChannelSecretsInfo {
        channel_id: channel_id.to_vec(),
        has_secrets: true,
        htlc_basepoint,
        revocation_basepoint,
        delayed_payment_basepoint,
        payment_point,
    })
}

// =============================================================================
// HTLC with Transaction Details
// =============================================================================

/// Create an HTLC with full transaction details for later signing.
pub fn create_htlc_with_tx_details_impl(
    request: CreateHtlcWithTxDetailsRequest,
) -> CreateHtlcWithTxDetailsResponse {
    use bitcoin::secp256k1::PublicKey;

    // Validate payment_hash
    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    // Validate channel_id
    let channel_id: [u8; 32] = match request.channel_id.clone().try_into() {
        Ok(c) => c,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("channel_id must be 32 bytes".to_string()),
            };
        }
    };

    // Validate outpoint txid
    let htlc_outpoint_txid: [u8; 32] = match request.htlc_outpoint_txid.clone().try_into() {
        Ok(t) => t,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("htlc_outpoint_txid must be 32 bytes".to_string()),
            };
        }
    };

    // Validate per_commitment_point
    let per_commitment_point: [u8; 33] = match request.per_commitment_point.clone().try_into() {
        Ok(p) => p,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("per_commitment_point must be 33 bytes".to_string()),
            };
        }
    };

    // Parse public keys
    let sender_pubkey = match PublicKey::from_slice(&request.sender_pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("Invalid sender_pubkey".to_string()),
            };
        }
    };

    let receiver_pubkey = match PublicKey::from_slice(&request.receiver_pubkey) {
        Ok(pk) => pk,
        Err(_) => {
            return CreateHtlcWithTxDetailsResponse {
                success: false,
                witness_script: None,
                error: Some("Invalid receiver_pubkey".to_string()),
            };
        }
    };

    // Build the witness script
    let witness_script = build_htlc_witness_script(
        &payment_hash,
        &receiver_pubkey,
        &sender_pubkey,
        request.cltv_expiry,
    );

    // Store HTLC in HtlcManager
    let mut state = STATE.write().unwrap();

    if let Err(e) = state.htlc_manager.add_htlc(
        payment_hash,
        request.amount_msat,
        request.cltv_expiry,
        request.sender_pubkey.clone(),
        request.receiver_pubkey.clone(),
    ) {
        return CreateHtlcWithTxDetailsResponse {
            success: false,
            witness_script: None,
            error: Some(e),
        };
    }

    // Store transaction details for signing
    let tx_details = HtlcTxDetails {
        channel_id,
        htlc_outpoint_txid,
        htlc_outpoint_vout: request.htlc_outpoint_vout,
        htlc_amount_sat: request.htlc_amount_sat,
        receiver_address: request.receiver_address,
        sender_address: request.sender_address,
        per_commitment_point,
        witness_script: witness_script.as_bytes().to_vec(),
    };

    state.htlc_tx_details.insert(payment_hash, tx_details);

    CreateHtlcWithTxDetailsResponse {
        success: true,
        witness_script: Some(witness_script.as_bytes().to_vec()),
        error: None,
    }
}

// =============================================================================
// HTLC Signing
// =============================================================================

/// Sign an HTLC-Success transaction (receiver claims with preimage).
pub fn sign_htlc_success_impl(request: SignHtlcSuccessRequest) -> SignHtlcResponse {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{OutPoint, ScriptBuf, Txid};

    // Validate preimage and compute payment hash
    if request.preimage.len() != 32 {
        return SignHtlcResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some("preimage must be 32 bytes".to_string()),
        };
    }

    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    // Verify preimage matches payment hash
    if !verify_preimage(&request.preimage, &payment_hash) {
        return SignHtlcResponse {
            success: false,
            signed_tx: None,
            txid: None,
            error: Some("preimage does not match payment_hash".to_string()),
        };
    }

    let state = STATE.read().unwrap();

    // Get HTLC transaction details
    let tx_details = match state.htlc_tx_details.get(&payment_hash) {
        Some(d) => d.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC transaction details not found".to_string()),
            };
        }
    };

    // Get HTLC info
    let htlc = match state.htlc_manager.get_htlc(&payment_hash) {
        Some(h) => h.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC not found".to_string()),
            };
        }
    };

    // Get channel secrets
    let secrets = match state.channel_secrets.get(&tx_details.channel_id) {
        Some(s) => s.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    drop(state); // Release lock

    // Parse receiver address
    let receiver_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        match tx_details.receiver_address.parse() {
            Ok(a) => a,
            Err(_) => {
                return SignHtlcResponse {
                    success: false,
                    signed_tx: None,
                    txid: None,
                    error: Some("Invalid receiver address".to_string()),
                };
            }
        };
    let receiver_address = receiver_address.assume_checked();

    // Build HTLC outpoint
    let txid_bytes: [u8; 32] = tx_details.htlc_outpoint_txid;
    let txid = Txid::from_byte_array(txid_bytes);
    let htlc_outpoint = OutPoint {
        txid,
        vout: tx_details.htlc_outpoint_vout,
    };

    // Build HTLC-Success transaction
    let mut tx = build_htlc_success_tx(
        htlc_outpoint,
        tx_details.htlc_amount_sat,
        &receiver_address,
        request.fee_sat,
    );

    // Get the witness script
    let witness_script = ScriptBuf::from_bytes(tx_details.witness_script.clone());

    // Sign the transaction
    let htlc_secret_key = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Invalid HTLC secret key".to_string()),
            };
        }
    };

    let signature = match sign_htlc_input(
        &tx,
        0, // input index
        &witness_script,
        tx_details.htlc_amount_sat,
        &htlc_secret_key,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to sign: {}", e)),
            };
        }
    };

    // Apply the success witness
    apply_htlc_success_witness(&mut tx, 0, signature, request.preimage, &witness_script);

    // Serialize the signed transaction
    let signed_tx = serialize(&tx);
    let result_txid = tx.compute_txid().to_byte_array().to_vec();

    SignHtlcResponse {
        success: true,
        signed_tx: Some(signed_tx),
        txid: Some(result_txid),
        error: None,
    }
}

/// Sign an HTLC-Timeout transaction (sender reclaims after expiry).
pub fn sign_htlc_timeout_impl(request: SignHtlcTimeoutRequest) -> SignHtlcResponse {
    use bitcoin::secp256k1::SecretKey;
    use bitcoin::{OutPoint, ScriptBuf, Txid};

    let payment_hash: [u8; 32] = match request.payment_hash.clone().try_into() {
        Ok(h) => h,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("payment_hash must be 32 bytes".to_string()),
            };
        }
    };

    let state = STATE.read().unwrap();

    // Get HTLC transaction details
    let tx_details = match state.htlc_tx_details.get(&payment_hash) {
        Some(d) => d.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC transaction details not found".to_string()),
            };
        }
    };

    // Get HTLC info
    let htlc = match state.htlc_manager.get_htlc(&payment_hash) {
        Some(h) => h.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("HTLC not found".to_string()),
            };
        }
    };

    // Get channel secrets
    let secrets = match state.channel_secrets.get(&tx_details.channel_id) {
        Some(s) => s.clone(),
        None => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    drop(state); // Release lock

    // Parse sender address
    let sender_address: bitcoin::Address<bitcoin::address::NetworkUnchecked> =
        match tx_details.sender_address.parse() {
            Ok(a) => a,
            Err(_) => {
                return SignHtlcResponse {
                    success: false,
                    signed_tx: None,
                    txid: None,
                    error: Some("Invalid sender address".to_string()),
                };
            }
        };
    let sender_address = sender_address.assume_checked();

    // Build HTLC outpoint
    let txid_bytes: [u8; 32] = tx_details.htlc_outpoint_txid;
    let txid = Txid::from_byte_array(txid_bytes);
    let htlc_outpoint = OutPoint {
        txid,
        vout: tx_details.htlc_outpoint_vout,
    };

    // Build HTLC-Timeout transaction
    let mut tx = build_htlc_timeout_tx(
        htlc_outpoint,
        tx_details.htlc_amount_sat,
        &sender_address,
        htlc.cltv_expiry,
        request.fee_sat,
    );

    // Get the witness script
    let witness_script = ScriptBuf::from_bytes(tx_details.witness_script.clone());

    // Sign the transaction
    let htlc_secret_key = match SecretKey::from_slice(&secrets.htlc_base_secret) {
        Ok(sk) => sk,
        Err(_) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some("Invalid HTLC secret key".to_string()),
            };
        }
    };

    let signature = match sign_htlc_input(
        &tx,
        0, // input index
        &witness_script,
        tx_details.htlc_amount_sat,
        &htlc_secret_key,
    ) {
        Ok(sig) => sig,
        Err(e) => {
            return SignHtlcResponse {
                success: false,
                signed_tx: None,
                txid: None,
                error: Some(format!("Failed to sign: {}", e)),
            };
        }
    };

    // Apply the timeout witness
    apply_htlc_timeout_witness(&mut tx, 0, signature, &witness_script);

    // Serialize the signed transaction
    let signed_tx = serialize(&tx);
    let result_txid = tx.compute_txid().to_byte_array().to_vec();

    SignHtlcResponse {
        success: true,
        signed_tx: Some(signed_tx),
        txid: Some(result_txid),
        error: None,
    }
}

// =============================================================================
// Channel Secret Generation (Phase 3: Canister generates secrets)
// =============================================================================

/// Generate channel secrets on the canister using `raw_rand()`.
///
/// Instead of the relay sending secrets to the canister, the canister now
/// generates them internally. Secrets never leave the canister.
///
/// Derivation: raw_rand() → master_seed → HMAC-SHA256(master_seed, channel_keys_id || tag)
/// for each of the 5 secrets.
pub async fn generate_channel_secrets_impl(
    request: GenerateChannelSecretsRequest,
) -> GenerateChannelSecretsResponse {
    use bitcoin::hashes::{sha256, HashEngine, Hmac, HmacEngine};
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    // Validate channel_keys_id
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.clone().try_into() {
        Ok(id) => id,
        Err(_) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    // Check if secrets already exist for this channel
    {
        let state = STATE.read().unwrap();
        if state.channel_secrets.contains_key(&channel_keys_id) {
            // Return existing public keys
            return match get_channel_secrets_info_impl(channel_keys_id.to_vec()) {
                Some(info) => GenerateChannelSecretsResponse {
                    success: true,
                    htlc_basepoint: Some(info.htlc_basepoint),
                    revocation_basepoint: Some(info.revocation_basepoint),
                    delayed_payment_basepoint: Some(info.delayed_payment_basepoint),
                    payment_point: Some(info.payment_point),
                    error: None,
                },
                None => GenerateChannelSecretsResponse {
                    success: false,
                    htlc_basepoint: None,
                    revocation_basepoint: None,
                    delayed_payment_basepoint: None,
                    payment_point: None,
                    error: Some("Failed to read existing secrets".to_string()),
                },
            };
        }
    }

    // Generate master seed using IC's raw_rand()
    let master_seed: [u8; 32] = match ic_cdk::api::management_canister::main::raw_rand().await {
        Ok((random_bytes,)) => {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&random_bytes[..32]);
            seed
        }
        Err(e) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some(format!("raw_rand() failed: {:?}", e)),
            };
        }
    };

    // Derive 5 secrets via HMAC-SHA256(master_seed, channel_keys_id || tag)
    let derive_secret = |tag: &[u8]| -> [u8; 32] {
        let mut hmac = HmacEngine::<sha256::Hash>::new(&master_seed);
        hmac.input(&channel_keys_id);
        hmac.input(tag);
        let result = Hmac::from_engine(hmac);
        result.to_byte_array()
    };

    let htlc_base_secret = derive_secret(b"htlc");
    let revocation_base_secret = derive_secret(b"revocation");
    let delayed_payment_base_secret = derive_secret(b"delayed");
    let payment_secret = derive_secret(b"payment");
    let commitment_seed = derive_secret(b"commitment");

    // Compute public keys from secrets
    let secp = Secp256k1::new();

    let htlc_basepoint = match SecretKey::from_slice(&htlc_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Derived invalid htlc_base_secret".to_string()),
            };
        }
    };

    let revocation_basepoint = match SecretKey::from_slice(&revocation_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Derived invalid revocation_base_secret".to_string()),
            };
        }
    };

    let delayed_payment_basepoint = match SecretKey::from_slice(&delayed_payment_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Derived invalid delayed_payment_base_secret".to_string()),
            };
        }
    };

    let payment_point = match SecretKey::from_slice(&payment_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return GenerateChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Derived invalid payment_secret".to_string()),
            };
        }
    };

    // Store in canister state
    let internal_secrets = ChannelSecretsInternal {
        htlc_base_secret,
        revocation_base_secret,
        delayed_payment_base_secret,
        payment_secret,
        commitment_seed,
    };

    {
        let mut state = STATE.write().unwrap();
        state.channel_secrets.insert(channel_keys_id, internal_secrets);
    }

    ic_cdk::println!(
        "Generated channel secrets for channel_keys_id: {}",
        hex::encode(channel_keys_id)
    );

    GenerateChannelSecretsResponse {
        success: true,
        htlc_basepoint: Some(htlc_basepoint),
        revocation_basepoint: Some(revocation_basepoint),
        delayed_payment_basepoint: Some(delayed_payment_basepoint),
        payment_point: Some(payment_point),
        error: None,
    }
}

/// Get the per-commitment point for a specific commitment index.
///
/// Uses BOLT-3 48-bit tree derivation from the channel's commitment_seed.
/// Returns PublicKey::from_secret_key(derived_secret).
pub fn get_per_commitment_point_impl(
    request: GetPerCommitmentPointRequest,
) -> GetPerCommitmentPointResponse {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let channel_keys_id: [u8; 32] = match request.channel_keys_id.try_into() {
        Ok(id) => id,
        Err(_) => {
            return GetPerCommitmentPointResponse {
                success: false,
                point: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    let state = STATE.read().unwrap();
    let secrets = match state.channel_secrets.get(&channel_keys_id) {
        Some(s) => s,
        None => {
            return GetPerCommitmentPointResponse {
                success: false,
                point: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    let per_commitment_secret = bolt3_keys::derive_per_commitment_secret(
        &secrets.commitment_seed,
        request.idx,
    );

    let secp = Secp256k1::new();
    let secret_key = match SecretKey::from_slice(&per_commitment_secret) {
        Ok(sk) => sk,
        Err(e) => {
            return GetPerCommitmentPointResponse {
                success: false,
                point: None,
                error: Some(format!("Invalid per-commitment secret: {:?}", e)),
            };
        }
    };

    let point = secret_key.public_key(&secp).serialize().to_vec();

    GetPerCommitmentPointResponse {
        success: true,
        point: Some(point),
        error: None,
    }
}

/// Release (reveal) a per-commitment secret for a given commitment index.
///
/// Same derivation as get_per_commitment_point, but returns the raw 32-byte secret.
pub fn release_commitment_secret_impl(
    request: ReleaseCommitmentSecretRequest,
) -> ReleaseCommitmentSecretResponse {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.try_into() {
        Ok(id) => id,
        Err(_) => {
            return ReleaseCommitmentSecretResponse {
                success: false,
                secret: None,
                error: Some("channel_keys_id must be 32 bytes".to_string()),
            };
        }
    };

    let state = STATE.read().unwrap();
    let secrets = match state.channel_secrets.get(&channel_keys_id) {
        Some(s) => s,
        None => {
            return ReleaseCommitmentSecretResponse {
                success: false,
                secret: None,
                error: Some("Channel secrets not found".to_string()),
            };
        }
    };

    let per_commitment_secret = bolt3_keys::derive_per_commitment_secret(
        &secrets.commitment_seed,
        request.idx,
    );

    ReleaseCommitmentSecretResponse {
        success: true,
        secret: Some(per_commitment_secret.to_vec()),
        error: None,
    }
}

/// Register counterparty channel info (funding pubkey) for a channel.
///
/// This is needed so the canister can reconstruct the funding redeemscript
/// when computing sighashes for commitment/closing transactions.
pub fn register_channel_info_impl(request: RegisterChannelInfoRequest) -> bool {
    let channel_keys_id: [u8; 32] = match request.channel_keys_id.try_into() {
        Ok(id) => id,
        Err(_) => return false,
    };

    if request.counterparty_funding_pubkey.len() != 33 {
        return false;
    }

    // Validate it's a valid pubkey
    if bitcoin::secp256k1::PublicKey::from_slice(&request.counterparty_funding_pubkey).is_err() {
        return false;
    }

    let mut state = STATE.write().unwrap();
    state.channel_counterparty_pubkeys.insert(
        channel_keys_id,
        request.counterparty_funding_pubkey,
    );
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::ChannelSecretsInternal;
    use bitcoin::secp256k1::{Secp256k1, SecretKey, PublicKey};

    /// Insert test channel secrets into STATE and return them.
    fn setup_test_channel_secrets(channel_keys_id: [u8; 32]) -> ChannelSecretsInternal {
        let secrets = ChannelSecretsInternal {
            htlc_base_secret: [21u8; 32],
            revocation_base_secret: [22u8; 32],
            delayed_payment_base_secret: [23u8; 32],
            payment_secret: [24u8; 32],
            commitment_seed: [25u8; 32],
        };
        let mut state = STATE.write().unwrap();
        state.channel_secrets.insert(channel_keys_id, secrets.clone());
        secrets
    }

    #[test]
    fn test_get_per_commitment_point_valid() {
        let channel_keys_id = [0xB1; 32];
        setup_test_channel_secrets(channel_keys_id);

        let request = GetPerCommitmentPointRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx: 0,
        };

        let response = get_per_commitment_point_impl(request);
        assert!(response.success, "Should succeed: {:?}", response.error);

        let point_bytes = response.point.unwrap();
        assert_eq!(point_bytes.len(), 33, "Point must be 33 bytes (compressed pubkey)");

        // Verify it's a valid public key
        assert!(PublicKey::from_slice(&point_bytes).is_ok(), "Must be a valid secp256k1 pubkey");
    }

    #[test]
    fn test_get_per_commitment_point_consistency() {
        let channel_keys_id = [0xB2; 32];
        let secrets = setup_test_channel_secrets(channel_keys_id);
        let secp = Secp256k1::new();

        let request = GetPerCommitmentPointRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx: 0,
        };

        let response = get_per_commitment_point_impl(request);
        assert!(response.success);
        let point_bytes = response.point.unwrap();

        // Manually derive the expected point
        let per_commitment_secret_bytes = bolt3_keys::derive_per_commitment_secret(
            &secrets.commitment_seed, 0,
        );
        let sk = SecretKey::from_slice(&per_commitment_secret_bytes).unwrap();
        let expected_point = sk.public_key(&secp).serialize().to_vec();

        assert_eq!(point_bytes, expected_point,
            "Point from impl must match manual derivation");
    }

    #[test]
    fn test_get_per_commitment_point_different_indices() {
        let channel_keys_id = [0xB3; 32];
        setup_test_channel_secrets(channel_keys_id);

        let response0 = get_per_commitment_point_impl(GetPerCommitmentPointRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx: 0,
        });
        let response1 = get_per_commitment_point_impl(GetPerCommitmentPointRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx: 1,
        });

        assert!(response0.success && response1.success);
        assert_ne!(response0.point.unwrap(), response1.point.unwrap(),
            "Different indices must produce different commitment points");
    }

    #[test]
    fn test_get_per_commitment_point_missing_secrets() {
        let missing_id = [0xBF; 32];
        let request = GetPerCommitmentPointRequest {
            channel_keys_id: missing_id.to_vec(),
            idx: 0,
        };

        let response = get_per_commitment_point_impl(request);
        assert!(!response.success, "Should fail when secrets not found");
        assert!(response.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_release_commitment_secret_valid() {
        let channel_keys_id = [0xC1; 32];
        setup_test_channel_secrets(channel_keys_id);

        let request = ReleaseCommitmentSecretRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx: 5,
        };

        let response = release_commitment_secret_impl(request);
        assert!(response.success, "Should succeed: {:?}", response.error);

        let secret = response.secret.unwrap();
        assert_eq!(secret.len(), 32, "Released secret must be 32 bytes");

        // Should be a valid secret key
        assert!(SecretKey::from_slice(&secret).is_ok(), "Released secret must be a valid secret key");
    }

    #[test]
    fn test_release_commitment_secret_matches_point() {
        let channel_keys_id = [0xC2; 32];
        setup_test_channel_secrets(channel_keys_id);
        let secp = Secp256k1::new();
        let idx = 42u64;

        // Get the point for this index
        let point_response = get_per_commitment_point_impl(GetPerCommitmentPointRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx,
        });
        assert!(point_response.success);
        let point_bytes = point_response.point.unwrap();
        let point = PublicKey::from_slice(&point_bytes).unwrap();

        // Release the secret for this index
        let secret_response = release_commitment_secret_impl(ReleaseCommitmentSecretRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            idx,
        });
        assert!(secret_response.success);
        let secret_bytes = secret_response.secret.unwrap();
        let sk = SecretKey::from_slice(&secret_bytes).unwrap();

        // The public key of the released secret must match the commitment point
        let derived_point = sk.public_key(&secp);
        assert_eq!(derived_point, point,
            "PublicKey::from_secret_key(released_secret) must equal get_per_commitment_point(same_idx)");
    }

    #[test]
    fn test_register_channel_info_valid() {
        let secp = Secp256k1::new();
        let channel_keys_id = [0xD1; 32];
        let counterparty_key = SecretKey::from_slice(&[50u8; 32]).unwrap();
        let counterparty_pubkey = counterparty_key.public_key(&secp).serialize().to_vec();

        let request = RegisterChannelInfoRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            counterparty_funding_pubkey: counterparty_pubkey.clone(),
        };

        let result = register_channel_info_impl(request);
        assert!(result, "Should succeed with valid pubkey");

        // Verify it's stored in STATE
        let state = STATE.read().unwrap();
        let stored = state.channel_counterparty_pubkeys.get(&channel_keys_id).unwrap();
        assert_eq!(stored, &counterparty_pubkey, "Stored pubkey must match input");
    }

    #[test]
    fn test_register_channel_info_invalid_pubkey() {
        let channel_keys_id = [0xD2; 32];

        // 33 bytes but not a valid secp256k1 point
        let invalid_pubkey = vec![0x04; 33]; // 0x04 prefix is for uncompressed, but only 33 bytes

        let request = RegisterChannelInfoRequest {
            channel_keys_id: channel_keys_id.to_vec(),
            counterparty_funding_pubkey: invalid_pubkey,
        };

        let result = register_channel_info_impl(request);
        assert!(!result, "Should fail with invalid pubkey bytes");
    }
}
