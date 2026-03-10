use crate::{
    BitcoinContext,
    btc::common::{PrimaryOutput, build_transaction_with_fee, select_utxos_greedy},
    btc::ecdsa::mock_sign_with_ecdsa,
};
use bitcoin::{
    Address, AddressType, Amount, OutPoint, PublicKey, ScriptBuf, Sequence,
    Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    ecdsa::Signature as BitcoinSignature,
    hashes::Hash,
    secp256k1::{Message, ecdsa::Signature as SecpSignature},
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};
use ic_cdk::bitcoin_canister::{MillisatoshiPerByte, Satoshi, Utxo};

/// A UTXO together with the address/key info needed to spend it.
/// Used for building transactions that spend from multiple addresses.
pub struct SourcedUtxo {
    pub utxo: Utxo,
    pub address: Address,
    pub public_key: PublicKey,
    pub derivation_path: Vec<Vec<u8>>,
}

// Builds a transaction to send the given `amount` of satoshis to the
// destination address.
pub async fn build_transaction(
    ctx: &BitcoinContext,
    own_public_key: &PublicKey,
    own_address: &Address,
    own_utxos: &[Utxo],
    dst_address: &Address,
    amount: Satoshi,
    fee_per_vbyte: MillisatoshiPerByte,
) -> (Transaction, Vec<TxOut>) {
    // We have a chicken-and-egg problem where we need to know the length
    // of the transaction in order to compute its proper fee, but we need
    // to know the proper fee in order to figure out the inputs needed for
    // the transaction.
    //
    // We solve this problem iteratively. We start with a fee of zero, build
    // and sign a transaction, see what its size is, and then update the fee,
    // rebuild the transaction, until the fee is set to the correct amount.
    let mut fee = 0;
    loop {
        let utxos_to_spend = select_utxos_greedy(own_utxos, amount, fee)
            .expect("Insufficient UTXOs for P2WPKH transaction");
        let (transaction, prevouts) = build_transaction_with_fee(
            utxos_to_spend,
            own_address,
            &PrimaryOutput::Address(dst_address.clone(), amount),
            fee,
        )
        .expect("Failed to build P2WPKH transaction with fee");

        // Sign the transaction. In this case, we only care about the size
        // of the signed transaction, so we use a mock signer here for efficiency.
        let signed_transaction = sign_transaction(
            ctx,
            own_public_key,
            own_address,
            transaction.clone(),
            &prevouts,
            vec![], // mock derivation path
            mock_sign_with_ecdsa,
        )
        .await;

        let tx_vsize = signed_transaction.vsize() as u64;

        if (tx_vsize * fee_per_vbyte) / 1000 == fee {
            return (transaction, prevouts);
        } else {
            fee = (tx_vsize * fee_per_vbyte) / 1000;
        }
    }
}

// Sign a P2WPKH bitcoin transaction.
//
// IMPORTANT: This method is for demonstration purposes only and it only
// supports signing transactions if:
//
// 1. All the inputs are referencing outpoints that are owned by `own_address`.
// 2. `own_address` is a P2WPKH address.
pub async fn sign_transaction<SignFun, Fut>(
    ctx: &BitcoinContext,
    own_public_key: &PublicKey,
    own_address: &Address,
    mut transaction: Transaction,
    prevouts: &[TxOut],
    derivation_path: Vec<Vec<u8>>,
    signer: SignFun,
) -> Transaction
where
    SignFun: Fn(String, Vec<Vec<u8>>, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = SecpSignature>,
{
    assert_eq!(
        own_address.address_type(),
        Some(AddressType::P2wpkh),
        "Only P2WPKH addresses are supported"
    );

    let transaction_clone = transaction.clone();
    let mut sighash_cache = SighashCache::new(&transaction_clone);

    for (index, input) in transaction.input.iter_mut().enumerate() {
        let script_pubkey = &prevouts[index].script_pubkey;
        let value = prevouts[index].value;
        let sighash = sighash_cache
            .p2wpkh_signature_hash(index, script_pubkey, value, EcdsaSighashType::All)
            .unwrap();

        let message = Message::from(sighash);

        let raw_signature = signer(
            ctx.key_name.to_string(),
            derivation_path.clone(),
            message.as_ref().to_vec(),
        )
        .await;

        let signature = BitcoinSignature {
            signature: raw_signature,
            sighash_type: EcdsaSighashType::All,
        };

        input.script_sig = ScriptBuf::new();
        input.witness = Witness::new();
        input.witness.push(signature.to_vec());
        input.witness.push(own_public_key.to_bytes());
    }

    transaction
}

// =============================================================================
// Multi-address transaction building (inputs from different derivation paths)
// =============================================================================

/// Greedy UTXO selection across multiple sourced UTXOs.
/// Returns indices into the `sourced_utxos` slice.
fn select_sourced_utxos_greedy(
    sourced_utxos: &[SourcedUtxo],
    amount: u64,
    fee: u64,
) -> Result<Vec<usize>, String> {
    let mut selected = vec![];
    let mut total = 0u64;
    for (i, su) in sourced_utxos.iter().enumerate().rev() {
        total += su.utxo.value;
        selected.push(i);
        if total >= amount + fee {
            return Ok(selected);
        }
    }
    Err(format!(
        "Insufficient balance across all LP addresses: {} sats available, need {} + {} fee",
        total, amount, fee
    ))
}

/// Build an unsigned transaction from UTXOs belonging to different addresses.
/// Change is sent to `change_address`.
fn build_multi_address_tx_with_fee(
    selected: &[&SourcedUtxo],
    change_address: &Address,
    primary_output: &PrimaryOutput,
    fee: u64,
) -> Result<(Transaction, Vec<TxOut>), String> {
    const DUST_THRESHOLD: u64 = 1_000;

    let inputs: Vec<TxIn> = selected
        .iter()
        .map(|su| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_raw_hash(Hash::from_slice(&su.utxo.outpoint.txid).unwrap()),
                vout: su.utxo.outpoint.vout,
            },
            sequence: Sequence::MAX,
            witness: Witness::new(),
            script_sig: ScriptBuf::new(),
        })
        .collect();

    // Each prevout uses the script_pubkey of the address that owns that UTXO
    let prevouts: Vec<TxOut> = selected
        .iter()
        .map(|su| TxOut {
            value: Amount::from_sat(su.utxo.value),
            script_pubkey: su.address.script_pubkey(),
        })
        .collect();

    let mut outputs = Vec::new();
    match primary_output {
        PrimaryOutput::Address(addr, amt) => outputs.push(TxOut {
            script_pubkey: addr.script_pubkey(),
            value: Amount::from_sat(*amt),
        }),
        PrimaryOutput::OpReturn(script) => outputs.push(TxOut {
            script_pubkey: script.clone(),
            value: Amount::from_sat(0),
        }),
    }

    let total_in: u64 = selected.iter().map(|su| su.utxo.value).sum();
    let change = total_in
        .checked_sub(outputs.iter().map(|o| o.value.to_sat()).sum::<u64>() + fee)
        .ok_or("fee exceeds inputs")?;
    if change >= DUST_THRESHOLD {
        outputs.push(TxOut {
            script_pubkey: change_address.script_pubkey(),
            value: Amount::from_sat(change),
        });
    }

    Ok((
        Transaction {
            input: inputs,
            output: outputs,
            lock_time: LockTime::ZERO,
            version: Version::TWO,
        },
        prevouts,
    ))
}

/// Sign a transaction where each input may belong to a different address/key.
/// `per_input` must be in the same order as the transaction inputs.
async fn sign_multi_address_tx<SignFun, Fut>(
    ctx: &BitcoinContext,
    per_input: &[&SourcedUtxo],
    mut transaction: Transaction,
    prevouts: &[TxOut],
    signer: SignFun,
) -> Transaction
where
    SignFun: Fn(String, Vec<Vec<u8>>, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = SecpSignature>,
{
    let transaction_clone = transaction.clone();
    let mut sighash_cache = SighashCache::new(&transaction_clone);

    for (index, input) in transaction.input.iter_mut().enumerate() {
        let script_pubkey = &prevouts[index].script_pubkey;
        let value = prevouts[index].value;
        let sighash = sighash_cache
            .p2wpkh_signature_hash(index, script_pubkey, value, EcdsaSighashType::All)
            .unwrap();

        let message = Message::from(sighash);
        let raw_signature = signer(
            ctx.key_name.to_string(),
            per_input[index].derivation_path.clone(),
            message.as_ref().to_vec(),
        )
        .await;

        let signature = BitcoinSignature {
            signature: raw_signature,
            sighash_type: EcdsaSighashType::All,
        };

        input.script_sig = ScriptBuf::new();
        input.witness = Witness::new();
        input.witness.push(signature.to_vec());
        input.witness.push(per_input[index].public_key.to_bytes());
    }

    transaction
}

/// Build a P2WPKH transaction spending from multiple addresses with iterative fee estimation.
/// Change goes to `change_address`. Returns (unsigned_tx, prevouts, selected_indices).
pub async fn build_multi_address_transaction(
    ctx: &BitcoinContext,
    all_sourced_utxos: &[SourcedUtxo],
    change_address: &Address,
    dst_address: &Address,
    amount: Satoshi,
    fee_per_vbyte: MillisatoshiPerByte,
) -> (Transaction, Vec<TxOut>, Vec<usize>) {
    let mut fee = 0;
    loop {
        let indices = select_sourced_utxos_greedy(all_sourced_utxos, amount, fee)
            .expect("Insufficient UTXOs across all LP addresses");
        let selected: Vec<&SourcedUtxo> = indices.iter().map(|&i| &all_sourced_utxos[i]).collect();

        let (transaction, prevouts) = build_multi_address_tx_with_fee(
            &selected,
            change_address,
            &PrimaryOutput::Address(dst_address.clone(), amount),
            fee,
        )
        .expect("Failed to build multi-address transaction");

        // Mock-sign to estimate vsize
        let signed = sign_multi_address_tx(
            ctx,
            &selected,
            transaction.clone(),
            &prevouts,
            mock_sign_with_ecdsa,
        )
        .await;

        let tx_vsize = signed.vsize() as u64;
        if (tx_vsize * fee_per_vbyte) / 1000 == fee {
            return (transaction, prevouts, indices);
        } else {
            fee = (tx_vsize * fee_per_vbyte) / 1000;
        }
    }
}

/// Sign a multi-address transaction with real ECDSA signatures.
pub async fn sign_multi_address_transaction<SignFun, Fut>(
    ctx: &BitcoinContext,
    all_sourced_utxos: &[SourcedUtxo],
    selected_indices: &[usize],
    transaction: Transaction,
    prevouts: &[TxOut],
    signer: SignFun,
) -> Transaction
where
    SignFun: Fn(String, Vec<Vec<u8>>, Vec<u8>) -> Fut,
    Fut: std::future::Future<Output = SecpSignature>,
{
    let per_input: Vec<&SourcedUtxo> =
        selected_indices.iter().map(|&i| &all_sourced_utxos[i]).collect();
    sign_multi_address_tx(ctx, &per_input, transaction, prevouts, signer).await
}
