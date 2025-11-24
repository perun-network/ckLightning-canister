//  Copyright 2025 PolyCrypt GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writiing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

// Assume you already have the unsigned transaction ready with all inputs (from both parties)
// and the corresponding prevouts array (TxOuts for inputs)

use crate::BTC_CONTEXT;
use bitcoin::{
    Address, PublicKey, Transaction, TxOut, secp256k1::ecdsa::Signature as SecpSignature,
};
pub async fn sequentially_sign_funding_tx_1<SignFun, Fut>(
    mut transaction: Transaction,
    prevouts: &[TxOut],
    parties: &[(PublicKey, Address, Vec<Vec<u8>>, SignFun)],
) -> Transaction
where
    SignFun: Fn(String, Vec<Vec<u8>>, Vec<u8>) -> Fut + Copy,
    Fut: std::future::Future<Output = SecpSignature>,
{
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    for (pubkey, address, derivation_path, signer_fn) in parties {
        transaction = crate::btc::p2wpkh::sign_transaction(
            &ctx,
            pubkey,
            address,
            transaction,
            prevouts,
            derivation_path.clone(),
            *signer_fn,
        )
        .await;
    }

    transaction
}

pub async fn sequentially_sign_funding_tx_2<SignFun, Fut>(
    // ctx: &BitcoinContext,
    mut transaction: Transaction,
    prevouts: &[TxOut],
    parties: &[(PublicKey, Address, Vec<Vec<u8>>, SignFun)],
) -> Transaction
where
    SignFun: Fn(String, Vec<Vec<u8>>, Vec<u8>) -> Fut + Copy,
    Fut: std::future::Future<Output = SecpSignature>,
{
    let ctx = BTC_CONTEXT.with(|ctx| ctx.get());

    for (pubkey, address, derivation_path, signer) in parties {
        // Only sign inputs belonging to 'address' for this party

        // Partial sign: call sign_transaction for each party, passing existing tx
        transaction = crate::btc::p2wpkh::sign_transaction(
            &ctx,
            pubkey,
            address,
            transaction,
            prevouts,
            derivation_path.clone(),
            *signer,
        )
        .await;
    }

    transaction
}
