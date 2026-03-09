use super::common::DerivationPath;
use super::{
    ecdsa::{get_ecdsa_public_key, sign_with_ecdsa},
    schnorr::get_schnorr_public_key,
};
use crate::BTC_CONTEXT;
use crate::btc::common::get_fee_per_byte;
use crate::btc::p2pkh;
use crate::error::BtcError;
use crate::error::ResultBtc;
use crate::ic_types::{BtcAddressType, BtcPurpose, GetBtcBalanceArgs};
use bitcoin::consensus::serialize;
use bitcoin::{Address, CompressedPublicKey, XOnlyPublicKey};
use bitcoin::{PublicKey, key::Secp256k1};
use ic_cdk::bitcoin_canister::GetBalanceRequest;
use ic_cdk::update;
use ic_cdk::{
    bitcoin_canister::{
        GetUtxosRequest, SendTransactionRequest, bitcoin_get_balance, bitcoin_get_utxos,
        bitcoin_send_transaction,
    },
    // trap, // update,
};
use std::str::FromStr;

#[update]

pub async fn get_segwit_address(purpose: BtcPurpose) -> Result<String, BtcError> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    let public_key_bytes = get_ecdsa_public_key(&ctx, purpose.derivation_path()).await;

    let compressed_key = CompressedPublicKey::from_slice(&public_key_bytes)
        .map_err(|_| BtcError::Other("Invalid public key".to_string()))?;

    let address = Address::p2wpkh(&compressed_key, ctx.bitcoin_network).to_string();

    Ok(address)
}

/// Returns a legacy P2PKH (Pay-to-PubKey-Hash) address for this smart contract.
///
/// This address uses an ECDSA public key and encodes it in the legacy Base58 format.
/// It is supported by all bitcoin wallets and full nodes.
#[update]
pub async fn get_p2pkh_address() -> ResultBtc<String> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    // Unique derivation paths are used for every address type generated, to ensure
    // each address has its own unique key pair.
    let derivation_path = DerivationPath::p2pkh(0, 0);

    // Get the ECDSA public key of this smart contract at the given derivation path
    let public_key = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;

    // Convert the public key to the format used by the Bitcoin library
    let public_key = PublicKey::from_slice(&public_key)
        .map_err(|e| BtcError::Other(format!("Invalid P2PKH public key: {}", e)))?;

    // Generate a legacy P2PKH address from the public key.
    // The address encoding (Base58) depends on the network type.
    let address = Address::p2pkh(public_key, ctx.bitcoin_network).to_string();

    Ok(address)
}

/// Returns a Taproot (P2TR) address of this smart contract that supports **key path spending only**.
///
/// This address does not commit to a script path (it commits to an unspendable path per BIP-341).
/// It allows spending using a single Schnorr signature corresponding to the internal key.
#[update]
pub async fn get_p2tr_key_path_only_address() -> ResultBtc<String> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    // Derivation path strategy:
    // We assign fixed address indexes for key roles within Taproot:
    // - Index 0: key-path-only Taproot (no script tree committed)
    // - Index 1: internal key for a Taproot output that includes a script tree
    // - Index 2: script leaf key committed to in the Merkle tree
    let internal_key_path = DerivationPath::p2tr(0, 0);

    // Derive the public key used as the internal key (untweaked key path base).
    // This key is used for key path spending only, without any committed script tree.
    let internal_key = get_schnorr_public_key(&ctx, internal_key_path.to_vec_u8_path()).await;

    // Convert the internal key to an x-only public key, as required by Taproot (BIP-341).
    let internal_key = XOnlyPublicKey::from(
        PublicKey::from_slice(&internal_key)
            .map_err(|e| BtcError::Other(format!("Invalid P2TR internal key: {}", e)))?,
    );

    // Create a Taproot address using the internal key only.
    // We pass `None` as the Merkle root, which per BIP-341 means the address commits
    // to an unspendable script path, enabling only key path spending.
    let secp256k1_engine = Secp256k1::new();
    let address =
        Address::p2tr(&secp256k1_engine, internal_key, None, ctx.bitcoin_network).to_string();
    Ok(address)
}

#[update]
pub async fn get_p2wpkh_address() -> ResultBtc<String> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    // Unique derivation paths are used for every address type generated, to ensure
    // each address has its own unique key pair.
    let derivation_path = DerivationPath::p2wpkh(0, 0);

    // Get the ECDSA public key of this smart contract at the given derivation path
    let public_key = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;

    // Create a CompressedPublicKey from the raw public key bytes
    let public_key = CompressedPublicKey::from_slice(&public_key)
        .map_err(|e| BtcError::Other(format!("Invalid P2WPKH compressed public key: {}", e)))?;

    // Generate a P2WPKH Bech32 address.
    // The network (mainnet, testnet, regtest) determines the HRP (e.g., "bc1" or "tb1").
    let address = Address::p2wpkh(&public_key, ctx.bitcoin_network).to_string();
    return Ok(address);
}

#[derive(candid::CandidType, candid::Deserialize)]
pub struct SendRequest {
    pub destination_address: String,
    pub amount_in_satoshi: u64,
}

#[update]
pub async fn send_from_p2pkh_address(request: SendRequest) -> Result<String, BtcError> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    if request.destination_address.len() > 200 {
        return Err(BtcError::Other("Destination address too long (max 200 chars)".to_string()));
    }

    if request.amount_in_satoshi == 0 {
        return Err(BtcError::Other("Amount must be greater than 0".to_string()));
    }

    // Parse and validate the destination address. The address type needs to be
    // valid for the Bitcoin network we are on.
    let dst_address = Address::from_str(&request.destination_address)
        .map_err(|e| BtcError::Other(format!("Invalid destination address: {}", e)))?
        .require_network(ctx.bitcoin_network)
        .map_err(|e| BtcError::Other(format!("Address network mismatch: {}", e)))?;

    // Unique derivation paths are used for every address type generated, to ensure
    // each address has its own unique key pair. To generate a user-specific address,
    // you would typically use a derivation path based on the user's identity or some other unique identifier.
    let derivation_path = DerivationPath::p2pkh(0, 0);

    // Get the ECDSA public key of this smart contract at the given derivation path.
    let own_public_key = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;

    // Convert the public key to the format used by the Bitcoin library.
    let own_public_key = PublicKey::from_slice(&own_public_key)
        .map_err(|e| BtcError::Other(format!("Invalid own public key: {}", e)))?;

    // Generate a P2PKH address from the public key.
    let own_address = Address::p2pkh(own_public_key, ctx.bitcoin_network);

    // Note that pagination may have to be used to get all UTXOs for the given address.
    // For the sake of simplicity, it is assumed here that the `utxo` field in the response
    // contains all UTXOs.
    let own_utxos = bitcoin_get_utxos(&GetUtxosRequest {
        address: own_address.to_string(),
        network: ctx.network,
        filter: None,
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to get UTXOs: {}", e)))?
    .utxos;

    // Build the transaction.
    let fee_per_byte = get_fee_per_byte(&ctx).await;
    let transaction = crate::btc::p2pkh::build_transaction(
        &ctx,
        &own_public_key,
        &own_address,
        &own_utxos,
        &crate::btc::common::PrimaryOutput::Address(dst_address, request.amount_in_satoshi),
        fee_per_byte,
    )
    .await;

    // Sign the transaction.
    let signed_transaction = p2pkh::sign_transaction(
        &ctx,
        &own_public_key,
        &own_address,
        transaction,
        derivation_path.to_vec_u8_path(),
        sign_with_ecdsa,
    )
    .await;

    // Send the transaction to the Bitcoin API.
    bitcoin_send_transaction(&SendTransactionRequest {
        network: ctx.network,
        transaction: serialize(&signed_transaction),
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to send transaction: {}", e)))?;

    // Return the transaction ID.
    Ok(signed_transaction.compute_txid().to_string())
}

pub async fn get_balance(get_balance_args: GetBtcBalanceArgs) -> Result<u64, BtcError> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    let confs = get_balance_args
        .confirmations
        .unwrap_or(0)
        .try_into()
        .map_err(|e| BtcError::Other(format!("Invalid confirmations value: {}", e)))?;

    let satoshi: u64 = bitcoin_get_balance(&GetBalanceRequest {
        address: get_balance_args.address,
        network: ctx.network,
        min_confirmations: Some(confs),
    })
    .await
    .map_err(|e| BtcError::Other(format!("Failed to get BTC balance: {}", e)))?;

    // satoshi is already u64, return it directly
    Ok(satoshi)
}

pub async fn derive_btc_address(
    address_type: BtcAddressType,
) -> Result<String, Box<dyn std::error::Error>> {
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    let derivation_path = match address_type {
        BtcAddressType::P2PKH => DerivationPath::p2pkh(0, 0),
        BtcAddressType::P2WPKH => DerivationPath::p2wpkh(0, 0),
        BtcAddressType::P2TR => DerivationPath::p2tr(0, 0),
    };

    let public_key_bytes = get_ecdsa_public_key(&ctx, derivation_path.to_vec_u8_path()).await;

    // Parse keys just once and reuse
    let public_key = PublicKey::from_slice(&public_key_bytes)
        .map_err(|e| format!("Failed to parse public key: {}", e))?;

    let address = match address_type {
        BtcAddressType::P2PKH => {
            // Directly return Address, no map_err needed
            Address::p2pkh(public_key, ctx.bitcoin_network)
        }
        BtcAddressType::P2WPKH => {
            // Convert to compressed pubkey type required by p2wpkh
            let compressed_key = CompressedPublicKey::from_slice(&public_key_bytes)
                .map_err(|e| format!("Failed to parse compressed public key: {}", e))?;
            Address::p2wpkh(&compressed_key, ctx.bitcoin_network)
        }
        BtcAddressType::P2TR => {
            // Use pubkey.inner to get the secp256k1::PublicKey inside bitcoin::PublicKey
            let xonly_key = XOnlyPublicKey::from(public_key.inner);
            Address::p2tr(
                &bitcoin::secp256k1::Secp256k1::new(),
                xonly_key,
                None,
                ctx.bitcoin_network,
            )
        }
    };

    // Return the string representation of the generated Address
    Ok(address.to_string())
}
