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

//! Stateless helper functions for the ckLightning canister.
//!
//! This module contains utility functions that do not require access to the
//! canister state. These are pure functions or async functions that make
//! external calls without needing state.

use crate::btc::address::get_segwit_address;
use crate::btc::common::{get_fee_per_byte, PrimaryOutput};
use crate::btc::ecdsa::{get_ecdsa_public_key, sign_with_ecdsa};
use crate::btc::{p2pkh, p2wpkh};
use crate::error::{BtcError, CklError};
use crate::ic_types::{
    BtcAddressType, BtcPurpose, CKBTC_LEDGER_PRINCIPAL, DEFAULT_CKBTC_FEE, LnFundingPubkeyResponse,
    LnInvoiceRequest, LnSignRequest, LnSignResponse, SendBtcTxMsg, SignedCandidInvoice,
    WithdrawalReq,
};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2};
use bitcoin::script::Builder;
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::{consensus::serialize, Address, CompressedPublicKey, PublicKey, ScriptBuf};
use candid::{Nat, Principal};
use ic_cdk::api::call::CallResult;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use ic_cdk::bitcoin_canister::{
    bitcoin_get_utxos, bitcoin_send_transaction, GetUtxosRequest, SendTransactionRequest,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use lightning_invoice::{Bolt11Invoice, Currency, InvoiceBuilder, PaymentSecret};
use std::str::FromStr;

/// Derivation path for the canister's Lightning funding key.
/// Using a single key for all channels for simplicity.
pub const LN_FUNDING_DERIVATION_PATH: &[&[u8]] = &[b"lightning", b"funding"];

// =============================================================================
// Ledger Transfer Helpers
// =============================================================================

/// Execute an ICRC-1 transfer on the ckBTC ledger.
///
/// This is a stateless helper that performs the actual ledger call.
/// Used by withdrawal and swap completion functions.
pub async fn execute_ledger_transfer(
    req: &WithdrawalReq,
    amount_u64: u64,
) -> std::result::Result<Nat, CklError> {
    let receiver = req.receiver;

    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: receiver,
            subaccount: None,
        },
        amount: Nat(amount_u64.into()),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(b"ckl:lp_withdraw".to_vec())),
        created_at_time: Some(ic_cdk::api::time()),
    };

    let ckbtc_ledger_id = *CKBTC_LEDGER_PRINCIPAL;

    let call_result: CallResult<(
        std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_height) => Ok(block_height),
            Err(_e) => Err(CklError::LedgerError),
        },
        Err((_code, _msg)) => Err(CklError::LedgerError),
    }
}

// =============================================================================
// Lightning Channel Helpers
// =============================================================================

/// Build the 2-of-2 multisig witness script for Lightning channel funding.
///
/// This creates the P2WSH witness script used in Lightning channel funding
/// transactions. The pubkeys are sorted lexicographically as per BOLT spec.
pub fn build_funding_witness_script(pubkey1: &[u8], pubkey2: &[u8]) -> Result<ScriptBuf, String> {
    // Validate pubkey lengths (33 bytes for compressed)
    if pubkey1.len() != 33 || pubkey2.len() != 33 {
        return Err("Invalid pubkey length (must be 33 bytes compressed)".to_string());
    }

    // Convert to fixed-size arrays
    let pk1: [u8; 33] = pubkey1.try_into().map_err(|_| "Invalid pubkey1")?;
    let pk2: [u8; 33] = pubkey2.try_into().map_err(|_| "Invalid pubkey2")?;

    // Sort pubkeys lexicographically (as per Lightning BOLT spec)
    let (first, second) = if pk1 < pk2 { (pk1, pk2) } else { (pk2, pk1) };

    // Build 2-of-2 multisig script
    let script = Builder::new()
        .push_opcode(OP_PUSHNUM_2)
        .push_slice(first)
        .push_slice(second)
        .push_opcode(OP_PUSHNUM_2)
        .push_opcode(OP_CHECKMULTISIG)
        .into_script();

    Ok(script)
}

/// Derive the P2WSH funding address from two pubkeys.
///
/// Used to verify Lightning channel funding transactions by computing
/// the expected funding address from the channel pubkeys.
pub fn derive_funding_address(
    pubkey1: &[u8],
    pubkey2: &[u8],
    network: bitcoin::Network,
) -> Result<Address, String> {
    let witness_script = build_funding_witness_script(pubkey1, pubkey2)?;
    Ok(Address::p2wsh(&witness_script, network))
}

// =============================================================================
// Bitcoin Transaction Helpers
// =============================================================================

/// Send BTC from the caller's address to a destination.
///
/// This function builds, signs, and broadcasts a Bitcoin transaction using
/// threshold ECDSA. It does not use canister state - all context comes from
/// BTC_CONTEXT.
pub async fn send_btc_tx_impl(
    destination_address_str: String,
    from_address_type: BtcAddressType,
    amount_in_satoshi: u64,
) -> Result<SendBtcTxMsg, BtcError> {
    if destination_address_str.len() > 200 {
        return Err(BtcError::Other("Destination address too long (max 200 chars)".to_string()));
    }

    if amount_in_satoshi == 0 {
        ic_cdk::trap("Amount must be greater than 0");
    }

    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Parse destination address and check network
    let dst_address = Address::from_str(&destination_address_str)
        .map_err(|e| BtcError::Other(format!("Invalid destination address: {}", e)))?
        .require_network(ctx.bitcoin_network)
        .map_err(|e| BtcError::Other(format!("Destination address network mismatch: {:?}", e)))?;

    // Derive own address and public key according to address type
    let derivation_path = match from_address_type {
        BtcAddressType::P2PKH => crate::btc::common::DerivationPath::p2pkh(0, 0),
        BtcAddressType::P2WPKH => crate::btc::common::DerivationPath::p2wpkh(0, 0),
        BtcAddressType::P2TR => crate::btc::common::DerivationPath::p2tr(0, 0),
    };

    let public_key_bytes =
        crate::btc::ecdsa::get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;

    // Prepare strings from public key bytes
    let (own_address, own_public_key) = match from_address_type {
        BtcAddressType::P2PKH => {
            let pubkey = PublicKey::from_slice(&public_key_bytes)
                .map_err(|e| BtcError::Other(format!("Failed to parse public key: {}", e)))?;
            let address = Address::p2pkh(pubkey, ctx.bitcoin_network);
            (address, pubkey)
        }
        BtcAddressType::P2WPKH => {
            let compressed_key =
                CompressedPublicKey::from_slice(&public_key_bytes).map_err(|e| {
                    BtcError::Other(format!("Failed to parse compressed public key: {}", e))
                })?;
            let pubkey = PublicKey::from_slice(&public_key_bytes)
                .map_err(|e| BtcError::Other(format!("Failed to parse public key: {}", e)))?;
            let address = Address::p2wpkh(&compressed_key, ctx.bitcoin_network);
            (address, pubkey)
        }
        BtcAddressType::P2TR => {
            return Err(BtcError::Other("P2TR address type not yet supported".to_string()));
        }
    };

    // Fetch all UTXOs for own address
    let own_utxos = bitcoin_get_utxos(&GetUtxosRequest {
        address: own_address.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to fetch UTXOs: {}", e)))?
    .utxos;

    // Get fee rate for transaction
    let fee_per_byte = get_fee_per_byte(&ctx).await;

    // Build, sign, send transaction based on address type
    let txid = match from_address_type {
        BtcAddressType::P2PKH => {
            // Build transaction
            let transaction = p2pkh::build_transaction(
                &ctx,
                &own_public_key,
                &own_address,
                &own_utxos,
                &PrimaryOutput::Address(dst_address, amount_in_satoshi),
                fee_per_byte,
            )
            .await;

            // Sign transaction
            let signed_tx = p2pkh::sign_transaction(
                &ctx,
                &own_public_key,
                &own_address,
                transaction,
                derivation_path.to_vec_u8_path(),
                crate::btc::ecdsa::sign_with_ecdsa,
            )
            .await;

            // Send transaction to Bitcoin canister
            bitcoin_send_transaction(&SendTransactionRequest {
                network: ctx.network,
                transaction: serialize(&signed_tx),
            })
            .await
            .map_err(|e| BtcError::Other(format!("Failed to send transaction: {}", e)))?;

            signed_tx.compute_txid().to_string()
        }
        BtcAddressType::P2WPKH => {
            // Build transaction with prevouts
            let (transaction, prevouts) = p2wpkh::build_transaction(
                &ctx,
                &own_public_key,
                &own_address,
                &own_utxos,
                &dst_address,
                amount_in_satoshi,
                fee_per_byte,
            )
            .await;

            // Sign transaction
            let signed_tx = p2wpkh::sign_transaction(
                &ctx,
                &own_public_key,
                &own_address,
                transaction,
                &prevouts,
                derivation_path.to_vec_u8_path(),
                crate::btc::ecdsa::sign_with_ecdsa,
            )
            .await;

            bitcoin_send_transaction(&SendTransactionRequest {
                network: ctx.network,
                transaction: serialize(&signed_tx),
            })
            .await
            .map_err(|e| BtcError::Other(format!("Failed to send transaction: {}", e)))?;

            signed_tx.compute_txid().to_string()
        }
        BtcAddressType::P2TR => {
            return Err(BtcError::Other("P2TR transaction sending not yet supported".to_string()));
        }
    };

    Ok(SendBtcTxMsg::Success(txid))
}

// =============================================================================
// Lightning Invoice Helpers
// =============================================================================

/// Generate a signed Lightning invoice for ckBTC swaps.
///
/// This creates a BOLT11 invoice with the caller's principal embedded in the
/// description for swap detection. Does not use canister state.
pub async fn get_ln_invoice_impl(
    request: LnInvoiceRequest,
) -> std::result::Result<SignedCandidInvoice, BtcError> {
    // 1. Verify caller matches principal
    let caller = msg_caller();
    if caller != request.caller_principal {
        return Err(BtcError::Other("Principal mismatch".to_string()));
    }

    // 2. Verify btc_address matches expected deposit address
    let purpose = BtcPurpose::LnInvoiceDeposit;
    let expected_deposit_addr = get_segwit_address(purpose).await?;
    if request.btc_address != expected_deposit_addr {
        return Err(BtcError::Other("BTC address mismatch".to_string()));
    }

    // 3. Payment hash: hash(principal || amount || time)
    let mut hash_input = caller.as_slice().to_vec();
    hash_input.extend_from_slice(&request.amount_msat.to_be_bytes());
    hash_input.extend_from_slice(&blocktime().to_be_bytes());
    let payment_hash = sha256::Hash::hash(&hash_input);

    // 4. Payment secret: deterministic from principal + amount + time + salt
    let mut secret_input = caller.as_slice().to_vec();
    secret_input.extend_from_slice(&request.amount_msat.to_be_bytes());
    secret_input.extend_from_slice(&blocktime().to_be_bytes());
    secret_input.extend_from_slice(b"ln_payment_secret");
    let payment_secret_bytes = sha256::Hash::hash(&secret_input).to_byte_array();
    let payment_secret = PaymentSecret(payment_secret_bytes);

    // 5. Timestamp from blocktime
    let now_nanos = blocktime();
    let now_secs = (now_nanos / 1_000_000_000) as u64;
    let timestamp_duration = std::time::Duration::from_secs(now_secs);

    // 6. Build and SIGN real invoice
    let secp_ctx = Secp256k1::new();
    // Legacy: This endpoint is unused in the canister-first architecture (relay creates invoices).
    // Using a deterministic key here since this invoice is never routable — the relay's node key
    // is what matters for real invoice signing. This endpoint should be removed in cleanup.
    let privkey = SecretKey::from_slice(&[41; 32]).expect("deterministic signing key for legacy invoice endpoint");

    let raw_invoice = InvoiceBuilder::new(Currency::Bitcoin)
        .description(format!("ckBTC_SWAP:{}", caller).into())
        .payment_hash(payment_hash)
        .payment_secret(payment_secret)
        .duration_since_epoch(timestamp_duration)
        .amount_milli_satoshis(request.amount_msat)
        .expiry_time(timestamp_duration + std::time::Duration::from_secs(3600))
        .build_raw()
        .map_err(|e| BtcError::Other(format!("Invoice build failed: {:?}", e)))?;

    let signed_invoice = raw_invoice
        .sign::<_, ()>(|msg_hash| Ok(secp_ctx.sign_ecdsa_recoverable(msg_hash, &privkey)))
        .map_err(|e| BtcError::Other(format!("Invoice signing failed: {:?}", e)))?;

    let invoice = Bolt11Invoice::from_signed(signed_invoice.clone())
        .map_err(|e| BtcError::Other(format!("Invoice parsing failed: {:?}", e)))?;

    // 7. Extract signature from signed invoice
    let (recovery_id, signature_bytes) = signed_invoice.signature().serialize_compact();
    let mut signature_serialized = Vec::with_capacity(65);
    signature_serialized.push(recovery_id.to_i32() as u8);
    signature_serialized.extend_from_slice(&signature_bytes);

    // 8. Build SignedCandidInvoice with real signed data
    let currency = "Bitcoin".to_string();
    let channel_id = vec![0u8; 32];

    let signed_candid_invoice = SignedCandidInvoice {
        invoice: invoice.to_string(),
        amount_msat: Some(Nat::from(request.amount_msat)),
        payment_hash: payment_hash.to_byte_array().to_vec(),
        payment_secret: payment_secret.0.to_vec(),
        timestamp: now_secs,
        expiry_secs: Some(3600_u64),
        currency,
        channel_id,
        signature: signature_serialized,
    };

    Ok(signed_candid_invoice)
}

// =============================================================================
// Lightning Key Management Helpers
// =============================================================================

/// Get the canister's Lightning funding public key.
///
/// This key is derived via threshold ECDSA (chainkey) and is used as one of the
/// two keys in the 2-of-2 multisig funding address for Lightning channels.
pub async fn get_ln_funding_pubkey_impl() -> LnFundingPubkeyResponse {
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    let derivation_path: Vec<Vec<u8>> = LN_FUNDING_DERIVATION_PATH
        .iter()
        .map(|s| s.to_vec())
        .collect();

    let pubkey = get_ecdsa_public_key(&ctx, derivation_path).await;

    LnFundingPubkeyResponse {
        pubkey,
        address: None, // Address requires counterparty's pubkey
    }
}

/// Sign a message hash for Lightning channel operations.
///
/// This is called by the relay when it needs a signature for:
/// - Commitment transactions
/// - HTLC transactions
/// - Closing transactions
///
/// The canister signs using its Lightning funding key derived via chainkey ECDSA.
pub async fn sign_ln_message_impl(request: LnSignRequest) -> LnSignResponse {
    // Validate message hash length (must be 32 bytes for ECDSA)
    if request.message_hash.len() != 32 {
        return LnSignResponse {
            success: false,
            signature: None,
            error: Some(format!(
                "Invalid message_hash length: expected 32 bytes, got {}",
                request.message_hash.len()
            )),
        };
    }

    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    let derivation_path: Vec<Vec<u8>> = LN_FUNDING_DERIVATION_PATH
        .iter()
        .map(|s| s.to_vec())
        .collect();

    // Log the signing request for auditing
    if let Some(purpose) = &request.purpose {
        ic_cdk::println!("Signing LN message for purpose: {}", purpose);
    }

    // Sign using chainkey ECDSA
    let signature = sign_with_ecdsa(
        ctx.key_name.to_string(),
        derivation_path,
        request.message_hash,
    )
    .await;

    // Convert signature to bytes (compact 64-byte format: r || s)
    let sig_bytes = signature.serialize_compact().to_vec();

    LnSignResponse {
        success: true,
        signature: Some(sig_bytes),
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Secp256k1, SecretKey};

    #[test]
    fn test_build_funding_witness_script_valid() {
        let secp = Secp256k1::new();
        let key1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let key2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk1 = key1.public_key(&secp).serialize();
        let pk2 = key2.public_key(&secp).serialize();

        let script = build_funding_witness_script(&pk1, &pk2).unwrap();
        let script_bytes = script.as_bytes();

        // Must be a valid script containing both pubkeys and 2-of-2 multisig opcodes
        assert!(script_bytes.len() > 70, "Script must be at least 70 bytes for 2-of-2 multisig");

        // Verify both pubkeys appear in the script (sorted lexicographically)
        let (first, second) = if pk1 < pk2 { (pk1, pk2) } else { (pk2, pk1) };

        // Check the script contains both sorted pubkeys
        let script_hex = hex::encode(script_bytes);
        assert!(script_hex.contains(&hex::encode(first)),
            "Script must contain the lexicographically first pubkey");
        assert!(script_hex.contains(&hex::encode(second)),
            "Script must contain the lexicographically second pubkey");

        // Verify OP_2 at start and before OP_CHECKMULTISIG
        assert_eq!(script_bytes[0], 0x52, "Script must start with OP_2");
        assert_eq!(script_bytes[script_bytes.len() - 2], 0x52, "OP_2 before OP_CHECKMULTISIG");
        assert_eq!(*script_bytes.last().unwrap(), 0xAE, "Script must end with OP_CHECKMULTISIG");
    }

    #[test]
    fn test_build_funding_witness_script_sorted() {
        let secp = Secp256k1::new();
        let key1 = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let key2 = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let pk1 = key1.public_key(&secp).serialize();
        let pk2 = key2.public_key(&secp).serialize();

        // Regardless of input order, the same script should be produced
        let script_a = build_funding_witness_script(&pk1, &pk2).unwrap();
        let script_b = build_funding_witness_script(&pk2, &pk1).unwrap();

        assert_eq!(script_a, script_b,
            "Funding witness script must be identical regardless of pubkey input order");
    }
}
