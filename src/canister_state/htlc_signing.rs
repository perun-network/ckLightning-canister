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
    RegisterChannelSecretsRequest, RegisterChannelSecretsResponse,
    ChannelSecretsInfo,
    CreateHtlcWithTxDetailsRequest, CreateHtlcWithTxDetailsResponse,
    SignHtlcSuccessRequest, SignHtlcTimeoutRequest, SignHtlcResponse,
};

use bitcoin::hashes::Hash;
use bitcoin::consensus::serialize;

// =============================================================================
// Channel Secrets Management
// =============================================================================

/// Register channel secrets for a Lightning channel.
///
/// Called by the relay when a channel is opened. Stores the secrets in canister
/// state for later use in HTLC signing operations.
///
/// Security note: These secrets are stored in canister memory, which is readable
/// by subnet nodes. This is an accepted tradeoff per HTLC_SECRET_IMPL.md.
pub fn register_channel_secrets_impl(
    request: RegisterChannelSecretsRequest,
) -> RegisterChannelSecretsResponse {
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    let secrets = &request.secrets;

    // Validate lengths
    if secrets.channel_id.len() != 32 {
        return RegisterChannelSecretsResponse {
            success: false,
            htlc_basepoint: None,
            revocation_basepoint: None,
            delayed_payment_basepoint: None,
            payment_point: None,
            error: Some("channel_id must be 32 bytes".to_string()),
        };
    }
    if secrets.htlc_base_secret.len() != 32
        || secrets.revocation_base_secret.len() != 32
        || secrets.delayed_payment_base_secret.len() != 32
        || secrets.payment_secret.len() != 32
        || secrets.commitment_seed.len() != 32
    {
        return RegisterChannelSecretsResponse {
            success: false,
            htlc_basepoint: None,
            revocation_basepoint: None,
            delayed_payment_basepoint: None,
            payment_point: None,
            error: Some("All secrets must be 32 bytes".to_string()),
        };
    }

    // Convert to fixed arrays
    let channel_id: [u8; 32] = secrets.channel_id.clone().try_into().unwrap();
    let htlc_base_secret: [u8; 32] = secrets.htlc_base_secret.clone().try_into().unwrap();
    let revocation_base_secret: [u8; 32] = secrets.revocation_base_secret.clone().try_into().unwrap();
    let delayed_payment_base_secret: [u8; 32] = secrets.delayed_payment_base_secret.clone().try_into().unwrap();
    let payment_secret: [u8; 32] = secrets.payment_secret.clone().try_into().unwrap();
    let commitment_seed: [u8; 32] = secrets.commitment_seed.clone().try_into().unwrap();

    // Derive public keys from secrets
    let secp = Secp256k1::new();

    let htlc_basepoint = match SecretKey::from_slice(&htlc_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid htlc_base_secret".to_string()),
            };
        }
    };

    let revocation_basepoint = match SecretKey::from_slice(&revocation_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid revocation_base_secret".to_string()),
            };
        }
    };

    let delayed_payment_basepoint = match SecretKey::from_slice(&delayed_payment_base_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid delayed_payment_base_secret".to_string()),
            };
        }
    };

    let payment_point = match SecretKey::from_slice(&payment_secret) {
        Ok(sk) => sk.public_key(&secp).serialize().to_vec(),
        Err(_) => {
            return RegisterChannelSecretsResponse {
                success: false,
                htlc_basepoint: None,
                revocation_basepoint: None,
                delayed_payment_basepoint: None,
                payment_point: None,
                error: Some("Invalid payment_secret".to_string()),
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

    let mut state = STATE.write().unwrap();
    state.channel_secrets.insert(channel_id, internal_secrets);

    RegisterChannelSecretsResponse {
        success: true,
        htlc_basepoint: Some(htlc_basepoint),
        revocation_basepoint: Some(revocation_basepoint),
        delayed_payment_basepoint: Some(delayed_payment_basepoint),
        payment_point: Some(payment_point),
        error: None,
    }
}

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
