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
use crate::BtcPurpose;
use crate::btc::address::get_balance;
use crate::btc::address::get_segwit_address;
use crate::btc::address::{get_p2pkh_address, get_p2tr_key_path_only_address, get_p2wpkh_address};
use crate::btc::common::PrimaryOutput;
use crate::btc::common::get_fee_per_byte;
use crate::btc::p2pkh;
use crate::btc::p2wpkh;
use crate::error::{BtcError, CklError, ResultBtc};
use crate::ic_types::LnInvoiceRequest;
use crate::ic_types::PoolAsset;
use crate::ic_types::SetLiquidityBtcAddressResponse;
use crate::ic_types::SignedCandidInvoice;
use crate::ic_types::{
    Amount, BtcAddressType, ChannelFunding, ChannelId, DEVNET_CKBTC_LEDGER, DepositorInfo, Funding,
    FundingLPArgs, FundingLPQueryArgs, GetBtcBalanceArgs, GetBtcBalancesResponse, HoldingsResponse,
    NotifyArgs, PoolWithdrawal, RegisteredState, SendBtcTxMsg, SetBtcAddressArgs, SetBtcAddressMsg,
    SetBtcAddressResponse, WithdrawalLPArgs, WithdrawalReq,
};
use crate::ic_types::{
    CompleteSwapRequest, CompleteSwapResponse, RegisterSwapRequest, RegisterSwapResponse,
    SwapInfo, SwapState,
};
use crate::ic_types::{
    BtcOutpoint, LnChannelInfo, LnChannelStatus, QueryLnChannelRequest, QueryLnChannelsResponse,
    RegisterLnChannelRequest, RegisterLnChannelResponse, VerifyLnChannelResponse,
};
use crate::liquidity_pool::LiquidityPool;
use crate::receiver::ICPReceiverError;
use crate::receiver::TransactionICRCNotification;
use lightning_invoice::Currency;
use lightning_invoice::PaymentSecret;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{Secp256k1, SecretKey};
use bitcoin::opcodes::all::{OP_CHECKMULTISIG, OP_PUSHNUM_2};
use bitcoin::script::Builder;
use bitcoin::{Address, CompressedPublicKey, ScriptBuf};
use bitcoin::{PublicKey, XOnlyPublicKey, consensus::serialize};
use candid::Encode;
use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use ic_cdk::{
    bitcoin_canister::{
        GetUtxosRequest, SendTransactionRequest, bitcoin_get_utxos, bitcoin_send_transaction,
    },
    trap, update,
};
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use k256::ecdsa::Signature;
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::signature::Verifier;
use k256::pkcs8::DecodePublicKey;
use k256::sha2::{Digest, Sha256};
use lightning_invoice::Bolt11Invoice;
use lightning_invoice::InvoiceBuilder;

use crate::error::ResultCkl;
use crate::ic_types::{DEFAULT_CKBTC_FEE, L1Account, Params, State, Timestamp};
use crate::receiver;
use crate::require;
use candid::{Nat, Principal};
use std::str::FromStr;

use lazy_static::lazy_static;
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    static ref STATE: RwLock<CanisterState<receiver::CanisterTXQuerier>> =
        RwLock::new(CanisterState::new(
            receiver::CanisterTXQuerier::new(
                Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal") // //bkyz2-fmaaa-aaaaa-qaaaq-cai
            ),
            canister_self(),
        ));
}

pub struct CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    principal: Principal,

    // Multiple liquidity depositor addresses
    btc_liquidity_addresses: HashMap<Principal, String>,

    // SINGLE global invoice deposit address
    btc_invoice_address: Option<String>,

    icrc_receiver: receiver::Receiver<Q>,
    user_holdings: HashMap<Funding, Amount>,
    channels: HashMap<ChannelId, RegisteredState>,
    liq_pool: LiquidityPool,

    // Lightning → ckBTC swaps storage (payment_hash -> SwapInfo)
    swaps: HashMap<[u8; 32], SwapInfo>,

    // Lightning channel funding verification (channel_id -> LnChannelInfo)
    ln_channels: HashMap<[u8; 32], LnChannelInfo>,
}

// pub struct CanisterState<Q>
// where
//     Q: receiver::TXQuerier,
// {
//     principal: Principal,
//     btc_addresses_liquidity: Option<String>,
//     btc_address_lightning: Option<String>,
//     own_btc_addresses: HashMap<BtcAddressType, String>,
//     icrc_receiver: receiver::Receiver<Q>,
//     user_holdings: HashMap<Funding, Amount>,
//     channels: HashMap<ChannelId, RegisteredState>,
//     liq_pool: LiquidityPool,
// }

pub async fn set_btc_liquidity_address_impl() -> Result<SetLiquidityBtcAddressResponse, BtcError> {
    let depositor = msg_caller(); // IC principal of the caller

    // First check state
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_liquidity_addresses.get(&depositor) {
            return Ok(SetLiquidityBtcAddressResponse {
                address: addr.clone(),
                already_existed: true,
            });
        }
    }

    // Derive new SegWit address for this depositor
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // Store in state
    {
        let mut state = STATE.write().unwrap();
        state
            .btc_liquidity_addresses
            .insert(depositor, address.clone());
    }

    Ok(SetLiquidityBtcAddressResponse {
        address,
        already_existed: false,
    })
}

// This function is called inside canister_state.rs and delegates BTC-context logic to btc/calls.rs
pub async fn send_btc_tx_impl(
    destination_address_str: String,
    from_address_type: BtcAddressType,
    amount_in_satoshi: u64,
) -> Result<SendBtcTxMsg, BtcError> {
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
            todo!()
            // let pubkey = PublicKey::from_slice(&public_key_bytes)
            //     .map_err(|e| BtcError::Other(format!("Failed to parse public key: {}", e)))?;
            // let xonly = XOnlyPublicKey::from(pubkey.inner);
            // let address = Address::p2tr(&Secp256k1::new(), xonly, None, ctx.bitcoin_network);
            // (address, pubkey)
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
            todo!()
        }
    };

    Ok(SendBtcTxMsg::Success(txid))
}

pub async fn set_btc_address_impl(
    set_btc_address_args: SetBtcAddressArgs,
) -> Result<SetBtcAddressResponse, BtcError> {
    let mut state = STATE.write().unwrap();
    let address_type = set_btc_address_args.address_type;
    let principal = msg_caller();

    assert!(principal == set_btc_address_args.principal.unwrap());

    assert!(!state.btc_liquidity_addresses.contains_key(&principal));

    // Check if address for this type exists
    if let Some(address) = state.btc_liquidity_addresses.get(&principal) {
        return Ok(SetBtcAddressResponse {
            address: address.clone(),
            msg: SetBtcAddressMsg::BtcAddressAlreadySetSingle(address_type),
        });
    }

    // If not, retrieve address for the given type by calling the matching async fn
    let address = match address_type {
        BtcAddressType::P2PKH => get_p2pkh_address().await?,
        BtcAddressType::P2WPKH => get_p2wpkh_address().await?,
        BtcAddressType::P2TR => get_p2tr_key_path_only_address().await?,
    };

    // Store in the map
    state
        .btc_liquidity_addresses
        .insert(principal.clone(), address.clone());

    Ok(SetBtcAddressResponse {
        address,
        msg: SetBtcAddressMsg::BtcAddressSetNowSingle(address_type),
    })
}

pub async fn get_btc_balances_impl(
    confirmations: Option<u64>,
) -> Result<GetBtcBalancesResponse, BtcError> {
    let state = STATE.read().unwrap();

    let mut balances: HashMap<Principal, Option<u64>> = HashMap::new();
    let mut any_address_set = false;

    for (address_type, address) in &state.btc_liquidity_addresses {
        any_address_set = true;

        // Construct GetBtcBalanceArgs with actual address string, not address_type
        let args = GetBtcBalanceArgs {
            address: address.clone(),
            confirmations, // pass on confirmation filter if any
        };

        // Query balance asynchronously, handle errors gracefully
        let balance = match get_balance(args).await {
            Ok(bal) => Some(bal),
            Err(_) => None, // optionally log or process error
        };

        balances.insert(*address_type, balance);
    }

    let msg = if any_address_set {
        SetBtcAddressMsg::BtcAddressesAvailable
    } else {
        SetBtcAddressMsg::BtcAddressNotSet
    };

    Ok(GetBtcBalancesResponse { balances, msg })
}

pub async fn get_ln_invoice_impl(
    request: LnInvoiceRequest,
) -> std::result::Result<SignedCandidInvoice, BtcError> {
    // 1. Verify caller matches principal
    let caller = msg_caller();
    if caller != request.caller_principal {
        return Err(BtcError::Other("Principal mismatch".to_string()));
    }

    // 2. Verify btc_address matches expected deposit address
    let purpose = BtcPurpose::LnInvoiceDeposit; //LiquidityDepositor(caller);
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
    let now_secs = (now_nanos / 1_000_000_000) as u64; // Truncate to seconds
    let timestamp_duration = std::time::Duration::from_secs(now_secs); // For InvoiceBuilder

    // 6. Build and SIGN real invoice (exactly like nocandid_impl)
    let secp_ctx = Secp256k1::new();
    let privkey = SecretKey::from_slice(&[41; 32]).expect("canister signing key"); // TODO: proper key mgmt

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

    // 7. Extract signature from signed invoice for storage/verification
    // let signature = signed_invoice.signature().serialize_compact(); //.to_bytes().to_vec(); // ✅ Real invoice signature
    let (recovery_id, signature_bytes) = signed_invoice.signature().serialize_compact();
    let mut signature_serialized = Vec::with_capacity(65);
    signature_serialized.push(recovery_id.to_i32() as u8); // RecoveryId as single byte (0-3)
    signature_serialized.extend_from_slice(&signature_bytes); // 64 signature bytes
    // 8. Build SignedCandidInvoice with real signed data
    let currency = "Bitcoin".to_string();
    let channel_id = vec![0u8; 32];

    let signed_candid_invoice = SignedCandidInvoice {
        invoice: invoice.to_string(), // ✅ Real signed BOLT11
        amount_msat: Some(Nat::from(request.amount_msat)),
        payment_hash: payment_hash.to_byte_array().to_vec(),
        payment_secret: payment_secret.0.to_vec(),
        timestamp: now_secs,
        expiry_secs: Some(3600_u64),
        currency,
        channel_id,
        signature: signature_serialized, // ✅ Signature of REAL invoice
    };

    Ok(signed_candid_invoice)
}

pub async fn get_ln_address_impl() -> Result<String, BtcError> {
    // Check global cache first
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_invoice_address.as_ref() {
            return Ok(addr.clone());
        }
    }

    // Derive SINGLE invoice deposit address
    let purpose = BtcPurpose::LnInvoiceDeposit;
    let address = get_segwit_address(purpose).await?;

    // Store globally
    {
        let mut state = STATE.write().unwrap();
        state.btc_invoice_address = Some(address.clone());
    }

    Ok(address)
}

pub async fn get_btc_liquidity_address_for_caller_impl() -> std::result::Result<String, BtcError> {
    let depositor = msg_caller();

    // 1. Fast path: return existing address if present
    {
        let state = STATE.read().unwrap();
        if let Some(addr) = state.btc_liquidity_addresses.get(&depositor) {
            return Ok(addr.clone());
        }
    }

    // 2. Derive new SegWit address for this depositor
    let purpose = BtcPurpose::LiquidityDepositor(depositor);
    let address = get_segwit_address(purpose).await?;

    // 3. Store in state and return
    {
        let mut state = STATE.write().unwrap();
        state
            .btc_liquidity_addresses
            .insert(depositor, address.clone());
    }

    Ok(address)
}

// pub async fn get_btc_liquidity_address_for_caller_impl() -> std::result::Result<String, BtcError> {
//     let depositor = msg_caller();
//     let state = STATE.read().unwrap();
//     match state.btc_liquidity_addresses.get(&depositor) {
//         Some(addr) => Ok(addr.clone()),
//         None => Err(BtcError::Other(
//             "No liquidity BTC address set for caller".to_string(),
//         )),
//     }
// }

// pub async fn query_btc_address_impl() -> Result<QueryBtcAddressResponse, BtcError> {
//     let state = STATE.read().unwrap();
//     let addresses_map = state.btc_liquidity_addresses.clone();

//     if addresses_map.is_empty() {
//         // No addresses set, respond with None
//         Ok(QueryBtcAddressResponse {
//             msg: SetBtcAddressMsg::BtcAddressNotSet,
//             addresses: None,
//         })
//     } else {
//         // Return all stored addresses in Some(HashMap)
//         Ok(QueryBtcAddressResponse {
//             msg: SetBtcAddressMsg::BtcAddressesAvailable,
//             addresses: Some(addresses_map),
//         })
//     }
// }

pub async fn transaction_notification_impl(
    notify_args: NotifyArgs,
) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
    let mut state = STATE.write().unwrap();
    state
        .process_icrc_tx(
            notify_args.block_height,
            notify_args.amount,
            notify_args.funding,
        )
        .await
}

pub fn query_user_lp_holdings_impl(
    funding: FundingLPQueryArgs,
) -> std::result::Result<HoldingsResponse, CklError> {
    let state = STATE.read().unwrap();
    state.query_holdings(funding)
}

pub async fn withdraw_lp_impl(
    withdrawal: WithdrawalLPArgs,
    sig_withdrawal: Vec<u8>,
) -> std::result::Result<(), CklError> {
    //std::result::Result<(), CklError>
    let mut state = STATE.write().unwrap();
    let pr_caller = msg_caller();
    let receiver = withdrawal.pool_withdrawal.depositor.0;

    // compare pr_caller and receiver, give error if unequal
    if pr_caller != receiver {
        return Err(CklError::UnauthorizedCaller);
    }

    let pool_withdrawal = withdrawal.pool_withdrawal;

    state
        .withdraw_icrc(blocktime(), receiver, pool_withdrawal, &sig_withdrawal)
        .await
}

pub async fn trigger_withdraw_impl(req: WithdrawalReq) -> std::result::Result<Nat, CklError> {
    let mut state = STATE.write().unwrap();
    state.withdraw_from_liq_pool(req).await
}

pub fn deposit_channel_impl(
    funding: ChannelFunding,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().unwrap();
    state.deposit_icrc(blocktime(), Funding::Channel(funding), signature_bytes)
}

pub fn deposit_lp_impl(
    funding: FundingLPArgs,
    signature_bytes: &[u8],
) -> std::result::Result<(), CklError> {
    let mut state = STATE.write().unwrap();

    let pool_funding = funding.pool_funding;

    state.deposit_icrc(blocktime(), Funding::Pool(pool_funding), signature_bytes)
}

pub fn query_state_impl(id: ChannelId) -> Option<RegisteredState> {
    let state = STATE.read().unwrap();
    state.state(&id)
}

impl<Q> CanisterState<Q>
where
    Q: receiver::TXQuerier,
{
    pub fn new(q: Q, my_principal: Principal) -> Self {
        assert!(my_principal == canister_self());

        Self {
            principal: canister_self(),
            btc_liquidity_addresses: HashMap::new(), // multiple per depositor
            btc_invoice_address: None,               // single global invoice address
            icrc_receiver: receiver::Receiver::new(q, my_principal),
            user_holdings: Default::default(),
            channels: Default::default(),
            liq_pool: LiquidityPool::new(),
            swaps: HashMap::new(),       // Lightning → ckBTC swaps
            ln_channels: HashMap::new(), // Lightning channel funding verification
        }
    }

    // pub fn set_btc_address_impl(&mut self, address: String) -> () {
    //     self.btc_liquidity_addresses = Some(address);
    // }

    pub fn deposit_channel(&mut self, funding: Funding, amount: Amount) -> ResultCkl<()> {
        *self
            .user_holdings
            .entry(funding)
            .or_insert(Default::default()) += amount;
        Ok(())
    }

    pub async fn withdraw_icrc(
        &mut self,
        time: Timestamp,
        receiver: Principal,
        withdrawal: PoolWithdrawal,
        signature_bytes: &[u8],
    ) -> ResultCkl<()> {
        let PoolWithdrawal {
            asset,
            pubkey_l1,
            depositor,
            amount,
        } = &withdrawal;

        // Retrieve depositor info
        let depositor_info = self
            .liq_pool
            .depositors
            .get_mut(depositor)
            .ok_or_else(|| CklError::InsufficientLiquidity)?;

        // Verify pubkey matches stored
        if depositor_info.pubkey.as_slice() != pubkey_l1.as_slice() {
            return Err(CklError::PubKeyMismatch);
        }

        // Serialize the withdrawal data
        let withdrawal_serialized =
            Encode!(&withdrawal).map_err(|_| CklError::SerializationError)?;

        // Hash the serialized data
        let hash = Sha256::digest(&withdrawal_serialized);

        // Verify signature using stored pubkey
        let pubkey_bytes = &depositor_info.pubkey;
        let verifying_key =
            VerifyingKey::from_public_key_der(pubkey_bytes).map_err(|_| CklError::InvalidPubKey)?;
        let signature =
            Signature::try_from(signature_bytes).map_err(|_| CklError::InvalidSignature)?;

        verifying_key
            .verify(&hash, &signature)
            .map_err(|_| CklError::SignatureVerificationFailed)?;

        // Check depositor's balance
        let depositor_balance = match &asset {
            PoolAsset::CkBTC => &mut depositor_info.ckbtc_amount,
            PoolAsset::BTC => &mut depositor_info.btc_amount,
        };

        if *depositor_balance < *amount {
            return Err(CklError::InsufficientLiquidity);
        }

        // Check total pool holdings
        let total_holding = self
            .liq_pool
            .holdings_total
            .get_mut(&asset)
            .ok_or_else(|| CklError::InsufficientLiquidity)?;

        if *total_holding < *amount {
            return Err(CklError::InsufficientLiquidity);
        }

        // Deduct from depositor and total holdings
        *depositor_balance -= amount.clone();
        *total_holding -= amount.clone();

        // Placeholder: Send funds back to L1 address
        let _ = self
            .send_funds_to_l1(receiver, &pubkey_l1, amount.clone(), &asset)
            .await;

        Ok(())
    }
    async fn get_btc_address(&self, address_type: BtcAddressType) -> ResultBtc<String> {
        let result = match address_type {
            BtcAddressType::P2PKH => get_p2pkh_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2PKH error: {}", e))),
            BtcAddressType::P2WPKH => get_p2wpkh_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2WPKH error: {}", e))),
            BtcAddressType::P2TR => get_p2tr_key_path_only_address()
                .await
                .map_err(|e| BtcError::BtcAddressFetchError(format!("P2TR error: {}", e))),
        };

        result
    }

    async fn send_funds_to_l1(
        &self,
        receiver: Principal,
        pubkey: &Vec<u8>,
        amount: Amount,
        asset: &PoolAsset,
    ) -> ResultCkl<()> {
        // TODO: Implement transfer logic here

        let transfer_arg = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: receiver,
                subaccount: None,
            },
            amount: Nat(amount.clone().0),
            fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
            memo: None,
            created_at_time: None,
        };

        let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

        let call_result: CallResult<(
            std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
        )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

        match call_result {
            Ok((inner_result,)) => match inner_result {
                Ok(_block_height) => Ok(()),
                Err(_e) => Err(CklError::LedgerError),
            },
            Err((_code, _msg)) => Err(CklError::LedgerError),
        }
    }

    // Correct usage:
    pub fn withdraw_channel(&mut self, funding: Funding, amount: Amount) -> ResultCkl<()> {
        // TODO: withdrawal logic as part of the L2 Lightning protocol

        return Ok(());
    }

    pub fn deposit_liq_pool(
        &mut self,
        amount: Amount,
        asset: PoolAsset,
        depositor: L1Account,
        pubkey_bytes: Vec<u8>,
        funding: &Funding,      // Added funding ref for verification
        signature_bytes: &[u8], // Added signature bytes for verification
    ) -> ResultCkl<()> {
        // Step 1: Serialize funding exactly as signed
        let funding_serialized = Encode!(funding).map_err(|_| CklError::SerializationError)?;

        // Step 2: Hash serialized data with SHA-256
        let hash = Sha256::digest(&funding_serialized);

        // Step 3: Parse the public key from DER or raw bytes
        let verifying_key = VerifyingKey::from_public_key_der(&pubkey_bytes)
            .map_err(|_| CklError::InvalidPubKey)?;

        // Step 4: Convert signature bytes (assumed DER encoded)
        let signature =
            Signature::try_from(signature_bytes).map_err(|_| CklError::InvalidSignature)?;

        // Step 5: Verify the signature on the hashed data
        verifying_key
            .verify(&hash, &signature)
            .map_err(|_| CklError::SignatureVerificationFailed)?;

        // Step 6: Proceed with existing pubkey matching and depositing logic
        use std::collections::hash_map::Entry;
        match self.liq_pool.depositors.entry(depositor.clone()) {
            Entry::Occupied(mut entry) => {
                let depositor_info = entry.get_mut();
                if depositor_info.pubkey != pubkey_bytes {
                    return Err(CklError::PubKeyMismatch);
                }
                depositor_info.deposit(asset.clone(), amount.clone());
            }
            Entry::Vacant(entry) => {
                let mut info = DepositorInfo {
                    pubkey: pubkey_bytes.clone(),
                    ckbtc_amount: Amount::default(),
                    btc_amount: Amount::default(),
                };
                info.deposit(asset.clone(), amount.clone());
                entry.insert(info);
            }
        }
        // Update total holdings for the asset
        *self.liq_pool.holdings_total.get_mut(&asset).unwrap() += amount.clone();

        Ok(())
    }
    pub fn deposit_icrc(
        &mut self,
        time: Timestamp,
        funding: Funding,
        signature_bytes: &[u8], // added signature argument
    ) -> ResultCkl<()> {
        let memo = funding.memo();
        // Drain the receiver for the amount associated with this memo.
        let amount = self.icrc_receiver.drain(memo);

        match &funding {
            Funding::Channel(_) => {
                self.deposit_channel(funding.clone(), amount)?;
            }
            Funding::Pool(_) => {
                let depositor = funding.get_depositor().unwrap().clone();
                let pool_asset = funding.get_asset().unwrap().clone();
                let pubkey = funding.get_pubkey().unwrap().clone();

                // New call, now passing funding reference and signature bytes
                self.deposit_liq_pool(
                    amount,
                    pool_asset,
                    depositor,
                    pubkey,
                    &funding,        // pass reference for verification
                    signature_bytes, // pass signature bytes for verification
                )?;
            }
        }
        //     // events::STATE
        //     //     .write()
        //     //     .unwrap()
        //     //     .register_event(
        //     //         time,
        //     //         funding.channel.clone(),
        //     //         Event::Funded {
        //     //             who: funding.participant.clone(),
        //     //             total: self.user_holdings.get(&funding).cloned().unwrap(),
        //     //             timestamp: time,
        //     //         },
        //     //     )
        //     //     .await;
        Ok(())
    }

    // Optionally handle events if needed
    pub async fn process_icrc_tx(
        &mut self,
        tx: receiver::BlockHeight,
        amount: u64,
        funding: Funding,
    ) -> std::result::Result<TransactionICRCNotification, ICPReceiverError> {
        self.icrc_receiver.verify_icrc(tx, amount, funding).await
    }

    pub fn query_holdings(
        &self,
        funding: FundingLPQueryArgs,
    ) -> std::result::Result<HoldingsResponse, CklError> {
        let sig = funding.funding_query_sig.clone();
        let l1_account_principal = funding.funding_query.address.clone();
        let caller_principal = msg_caller();

        if l1_account_principal.0 != caller_principal {
            return Err(CklError::UnauthorizedCaller);
        }

        let depositor_info = self
            .liq_pool
            .depositors
            .get(&funding.funding_query.address)
            .ok_or(CklError::NoHoldingsFound)?;

        // 3. Serialize funding_query exactly as signed
        let serialized_query =
            Encode!(&funding.funding_query).map_err(|_| CklError::SerializationError)?;

        // 4. Hash the serialized bytes with SHA256
        let hash = Sha256::digest(&serialized_query);

        // 5. Parse public key from stored DepositorInfo pubkey bytes (DER format)
        let verifying_key = VerifyingKey::from_public_key_der(&depositor_info.pubkey)
            .map_err(|_| CklError::InvalidPubKey)?;

        // 6. Parse signature bytes (DER encoded)
        let signature = Signature::try_from(funding.funding_query_sig.as_slice())
            .map_err(|_| CklError::InvalidSignature)?;

        // 7. Verify signature on the hash matches stored public key
        verifying_key
            .verify(&hash, &signature)
            .map_err(|_| CklError::SignatureVerificationFailed)?;

        // 8. Signature valid, return holdings for this depositor
        Ok(HoldingsResponse {
            ckbtc_amount: depositor_info.ckbtc_amount.clone(),
            btc_amount: depositor_info.btc_amount.clone(),
        })
    }

    pub fn query_liq_holdings(&self, asset: PoolAsset) -> Option<Amount> {
        self.liq_pool.holdings_total.get(&asset).cloned()
    }

    /// Queries a registered state.
    pub fn state(&self, id: &ChannelId) -> Option<RegisteredState> {
        self.channels.get(&id).cloned()
    }

    /// Updates the holdings associated with a channel to the outcome of the
    /// supplied state, then registers the state. If the state is the channel's
    /// initial state, the holdings are not updated, as initial states are
    /// allowed to be under-funded and are otherwise expected to match the
    /// deposit distribution exactly if fully funded.
    fn register_channel(&mut self, params: &Params, state: RegisteredState) -> ResultCkl<()> {
        let total = &self.holdings_total(&params);
        if total < &state.state.total() {
            require!(
                state.state.may_be_underfunded(),
                CklError::InsufficientFunding
            );
        } else {
            self.update_channel_holdings(&params, &state.state);
        }

        self.channels.insert(state.state.channel.clone(), state);
        Ok(())
    }

    /// Pushes a state's funding allocation into the channel's holdings mapping
    /// in the canister.
    fn update_channel_holdings(&mut self, params: &Params, state: &State) {
        for (i, outcome) in state.allocation.iter().enumerate() {
            // let amt = outcome.clone();
            self.user_holdings.insert(
                Funding::new_channel(state.channel.clone(), params.participants[i].clone()),
                outcome.clone(),
            );
        }
    }

    /// Calculates the total funds held in a channel. If the channel is unknown
    /// and there are no deposited funds for the channel, returns 0.
    pub fn holdings_total(&self, params: &Params) -> Amount {
        let mut acc = Amount::default();
        for pk in params.participants.iter() {
            let funding = Funding::new_channel(params.id(), pk.clone());
            acc += self
                .user_holdings
                .get(&funding)
                .unwrap_or(&Amount::default())
                .clone();
        }
        acc
    }

    pub async fn withdraw_from_liq_pool(
        &mut self,
        req: WithdrawalReq,
    ) -> std::result::Result<Nat, CklError> {
        let amount = req.amount.clone();

        let (total_deducted, to_deduct) = match self.calculate_required_deductions(&amount) {
            Ok(res) => res,
            Err(_) => {
                return Err(CklError::InsufficientLiquidity);
            }
        };

        let transfer_result = execute_ledger_transfer(&req, total_deducted).await;

        match transfer_result {
            Ok(block_height) => {
                self.apply_deductions(to_deduct);
                Ok(block_height)
            }
            Err(error_msg) => Err(error_msg),
        }
    }

    fn calculate_required_deductions(
        &self,
        amount: &Nat,
    ) -> std::result::Result<(u64, Vec<(Funding, Nat)>), CklError> {
        let mut needed = amount.clone();
        let mut to_deduct = Vec::new();
        let zero = Nat::from(0u32);

        for (acc, available) in &self.user_holdings {
            if needed == zero {
                break;
            }

            let take = available.min(&needed);
            if *take > zero {
                to_deduct.push((acc.clone(), take.clone()));
                needed -= take.clone();
            }
        }

        if needed > zero {
            return Err(CklError::InsufficientLiquidity);
        }

        let total = amount.clone() - needed;
        let total_u64 = total.0.to_u64_digits()[0];
        Ok((total_u64, to_deduct))
    }

    pub fn finalize_withdrawal(&mut self, to_deduct: Vec<(Funding, Nat)>) {
        self.apply_deductions(to_deduct);
    }

    fn apply_deductions(&mut self, to_deduct: Vec<(Funding, Nat)>) {
        let zero = Nat(0u64.into());

        for (acc, take) in to_deduct {
            if let Some(entry) = self.user_holdings.get_mut(&acc) {
                *entry -= take;
                if *entry == zero {
                    self.user_holdings.remove(&acc);
                }
            }
        }
    }
}

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
        memo: None,
        created_at_time: None,
    };

    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

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
// Lightning → ckBTC Swap Implementation
// =============================================================================

/// Register a new Lightning → ckBTC swap
///
/// Called by the relay node when an invoice is created with an IC principal.
/// Stores the swap info so it can be verified and completed later.
pub fn register_swap_impl(request: RegisterSwapRequest) -> RegisterSwapResponse {
    // Validate payment_hash length
    if request.payment_hash.len() != 32 {
        return RegisterSwapResponse {
            success: false,
            error: Some("Invalid payment_hash length (must be 32 bytes)".to_string()),
        };
    }

    // Convert to fixed array
    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    // Check if swap already exists
    {
        let state = STATE.read().unwrap();
        if state.swaps.contains_key(&payment_hash_arr) {
            return RegisterSwapResponse {
                success: false,
                error: Some("Swap with this payment_hash already exists".to_string()),
            };
        }
    }

    // Create swap info
    let swap_info = SwapInfo {
        payment_hash: request.payment_hash.clone(),
        amount_msat: request.amount_msat,
        recipient: request.recipient,
        created_at: blocktime(),
        expiry_timestamp: request.expiry_timestamp,
        state: SwapState::Pending,
    };

    // Store swap
    {
        let mut state = STATE.write().unwrap();
        state.swaps.insert(payment_hash_arr, swap_info);
    }

    RegisterSwapResponse {
        success: true,
        error: None,
    }
}

/// Complete a Lightning → ckBTC swap
///
/// Called by the relay node when a Lightning payment is received.
/// Verifies the preimage, then transfers ckBTC to the recipient.
pub async fn complete_swap_impl(request: CompleteSwapRequest) -> CompleteSwapResponse {
    // Validate lengths
    if request.payment_hash.len() != 32 {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Invalid payment_hash length".to_string()),
        };
    }
    if request.preimage.len() != 32 {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Invalid preimage length".to_string()),
        };
    }

    // Verify preimage matches payment_hash
    let computed_hash = sha256::Hash::hash(&request.preimage);
    if computed_hash.as_byte_array() != request.payment_hash.as_slice() {
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Preimage does not match payment_hash".to_string()),
        };
    }

    let mut payment_hash_arr = [0u8; 32];
    payment_hash_arr.copy_from_slice(&request.payment_hash);

    // Get swap info and verify state
    let swap_info = {
        let state = STATE.read().unwrap();
        match state.swaps.get(&payment_hash_arr) {
            Some(info) => info.clone(),
            None => {
                return CompleteSwapResponse {
                    success: false,
                    block_index: None,
                    error: Some("Swap not found for this payment_hash".to_string()),
                };
            }
        }
    };

    // Check swap state
    match &swap_info.state {
        SwapState::Pending => {} // OK to proceed
        SwapState::Completed { .. } => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some("Swap already completed".to_string()),
            };
        }
        SwapState::Expired => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some("Swap has expired".to_string()),
            };
        }
        SwapState::Failed { reason } => {
            return CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some(format!("Swap failed: {}", reason)),
            };
        }
    }

    // Convert amount from millisatoshis to satoshis
    let amount_sat = swap_info.amount_msat / 1000;
    if amount_sat == 0 {
        // Mark as failed
        {
            let mut state = STATE.write().unwrap();
            if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                swap.state = SwapState::Failed {
                    reason: "Amount too small".to_string(),
                };
            }
        }
        return CompleteSwapResponse {
            success: false,
            block_index: None,
            error: Some("Amount too small (< 1000 msat)".to_string()),
        };
    }

    // Execute ckBTC transfer
    let transfer_arg = TransferArg {
        from_subaccount: None,
        to: Account {
            owner: swap_info.recipient,
            subaccount: None,
        },
        amount: Nat(amount_sat.into()),
        fee: Some(Nat(DEFAULT_CKBTC_FEE.into())),
        memo: Some(icrc_ledger_types::icrc1::transfer::Memo::from(
            request.payment_hash.clone(),
        )),
        created_at_time: None,
    };

    let ckbtc_ledger_id = Principal::from_text(DEVNET_CKBTC_LEDGER).expect("parsing principal");

    let call_result: CallResult<(
        std::result::Result<Nat, icrc_ledger_types::icrc1::transfer::TransferError>,
    )> = ic_cdk::call(ckbtc_ledger_id, "icrc1_transfer", (transfer_arg,)).await;

    match call_result {
        Ok((inner_result,)) => match inner_result {
            Ok(block_index) => {
                // Mark swap as completed
                {
                    let mut state = STATE.write().unwrap();
                    if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                        swap.state = SwapState::Completed {
                            block_index: block_index.clone(),
                        };
                    }
                }
                CompleteSwapResponse {
                    success: true,
                    block_index: Some(block_index),
                    error: None,
                }
            }
            Err(e) => {
                // Mark as failed
                {
                    let mut state = STATE.write().unwrap();
                    if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                        swap.state = SwapState::Failed {
                            reason: format!("Transfer error: {:?}", e),
                        };
                    }
                }
                CompleteSwapResponse {
                    success: false,
                    block_index: None,
                    error: Some(format!("ckBTC transfer failed: {:?}", e)),
                }
            }
        },
        Err((code, msg)) => {
            // Mark as failed
            {
                let mut state = STATE.write().unwrap();
                if let Some(swap) = state.swaps.get_mut(&payment_hash_arr) {
                    swap.state = SwapState::Failed {
                        reason: format!("Call error: {:?} - {}", code, msg),
                    };
                }
            }
            CompleteSwapResponse {
                success: false,
                block_index: None,
                error: Some(format!("Canister call failed: {:?} - {}", code, msg)),
            }
        }
    }
}

// =============================================================================
// Lightning Channel Funding Verification Implementation
// =============================================================================

/// Register a new Lightning channel for funding verification
///
/// Called by the relay node when a channel is opened.
/// Stores the channel info so the funding UTXO can be verified on-chain.
pub fn register_ln_channel_impl(request: RegisterLnChannelRequest) -> RegisterLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    // Validate funding_txid length
    if request.funding_txid.len() != 32 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid funding_txid length (must be 32 bytes)".to_string()),
        };
    }

    // Validate node IDs (33 bytes compressed pubkey)
    if request.local_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid local_node_id length (must be 33 bytes)".to_string()),
        };
    }
    if request.remote_node_id.len() != 33 {
        return RegisterLnChannelResponse {
            success: false,
            error: Some("Invalid remote_node_id length (must be 33 bytes)".to_string()),
        };
    }

    // Convert to fixed array
    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Check if channel already exists
    {
        let state = STATE.read().unwrap();
        if state.ln_channels.contains_key(&channel_id_arr) {
            return RegisterLnChannelResponse {
                success: false,
                error: Some("Channel with this channel_id already registered".to_string()),
            };
        }
    }

    // Create channel info
    let channel_info = LnChannelInfo {
        channel_id: request.channel_id.clone(),
        funding_outpoint: BtcOutpoint {
            txid: request.funding_txid.clone(),
            vout: request.funding_vout,
        },
        capacity_sats: request.capacity_sats,
        local_node_id: request.local_node_id.clone(),
        remote_node_id: request.remote_node_id.clone(),
        registered_at: blocktime(),
        last_verified_at: None,
        status: LnChannelStatus::Pending,
    };

    // Store channel
    {
        let mut state = STATE.write().unwrap();
        state.ln_channels.insert(channel_id_arr, channel_info);
    }

    RegisterLnChannelResponse {
        success: true,
        error: None,
    }
}

/// Build a 2-of-2 multisig witness script for Lightning channel funding.
///
/// The script is: OP_2 <pubkey1> <pubkey2> OP_2 OP_CHECKMULTISIG
/// Where pubkeys are sorted lexicographically (by byte comparison).
fn build_funding_witness_script(pubkey1: &[u8], pubkey2: &[u8]) -> Result<ScriptBuf, String> {
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
fn derive_funding_address(
    pubkey1: &[u8],
    pubkey2: &[u8],
    network: bitcoin::Network,
) -> Result<Address, String> {
    let witness_script = build_funding_witness_script(pubkey1, pubkey2)?;
    Ok(Address::p2wsh(&witness_script, network))
}

/// Verify a Lightning channel's funding UTXO on-chain
///
/// Queries the Bitcoin canister to check if the funding UTXO exists
/// and has sufficient confirmations.
pub async fn verify_ln_channel_impl(
    request: QueryLnChannelRequest,
) -> VerifyLnChannelResponse {
    // Validate channel_id length
    if request.channel_id.len() != 32 {
        return VerifyLnChannelResponse {
            verified: false,
            confirmations: None,
            utxo_value_sats: None,
            error: Some("Invalid channel_id length (must be 32 bytes)".to_string()),
        };
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    // Get channel info
    let channel_info = {
        let state = STATE.read().unwrap();
        match state.ln_channels.get(&channel_id_arr) {
            Some(info) => info.clone(),
            None => {
                return VerifyLnChannelResponse {
                    verified: false,
                    confirmations: None,
                    utxo_value_sats: None,
                    error: Some("Channel not found".to_string()),
                };
            }
        }
    };

    // Get Bitcoin context
    let ctx = crate::BTC_CONTEXT.with(|ctx| ctx.get());

    // Derive the P2WSH funding address from the two node pubkeys
    let funding_address = match derive_funding_address(
        &channel_info.local_node_id,
        &channel_info.remote_node_id,
        ctx.bitcoin_network,
    ) {
        Ok(addr) => addr,
        Err(e) => {
            return VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!("Failed to derive funding address: {}", e)),
            };
        }
    };

    // Query UTXOs for the funding address
    let utxos_result = bitcoin_get_utxos(&GetUtxosRequest {
        address: funding_address.to_string(),
        network: ctx.network,
        filter: None, // Get all UTXOs including unconfirmed
    })
    .await;

    let utxos_response = match utxos_result {
        Ok(response) => response,
        Err(e) => {
            return VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!("Failed to query UTXOs: {:?}", e)),
            };
        }
    };

    // Get current tip height to calculate confirmations
    let tip_height = utxos_response.tip_height;

    // Look for the specific funding UTXO by matching txid and vout
    // Note: The txid in the UTXO response is in internal byte order (little-endian)
    // while Lightning typically uses big-endian (display order)
    let funding_txid = &channel_info.funding_outpoint.txid;
    let funding_vout = channel_info.funding_outpoint.vout;

    let mut found_utxo: Option<(u64, u32)> = None; // (value, confirmations)

    for utxo in &utxos_response.utxos {
        // Compare txid (both should be in the same byte order from the canister)
        if utxo.outpoint.txid.as_slice() == funding_txid.as_slice()
            && utxo.outpoint.vout == funding_vout
        {
            // Found the funding UTXO
            let confirmations = if utxo.height > 0 {
                tip_height.saturating_sub(utxo.height) + 1
            } else {
                0 // Unconfirmed
            };
            found_utxo = Some((utxo.value, confirmations));
            break;
        }
    }

    match found_utxo {
        Some((value, confirmations)) => {
            // Verify the value matches the claimed capacity
            let value_matches = value == channel_info.capacity_sats;

            // Update channel status
            let current_time = blocktime();
            {
                let mut state = STATE.write().unwrap();
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    if value_matches && confirmations >= 3 {
                        channel.status = LnChannelStatus::Verified {
                            confirmations: confirmations as u32,
                        };
                    } else if !value_matches {
                        channel.status = LnChannelStatus::Failed {
                            reason: format!(
                                "Value mismatch: expected {} sats, found {} sats",
                                channel_info.capacity_sats, value
                            ),
                        };
                    } else {
                        // Not enough confirmations yet, keep as pending
                        channel.status = LnChannelStatus::Pending;
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: value_matches && confirmations >= 3,
                confirmations: Some(confirmations as u32),
                utxo_value_sats: Some(value),
                error: if !value_matches {
                    Some(format!(
                        "Value mismatch: expected {} sats, found {} sats",
                        channel_info.capacity_sats, value
                    ))
                } else if confirmations < 3 {
                    Some(format!(
                        "Insufficient confirmations: {} (need at least 3)",
                        confirmations
                    ))
                } else {
                    None
                },
            }
        }
        None => {
            // UTXO not found - channel might be closed or funding tx not yet confirmed
            let current_time = blocktime();
            {
                let mut state = STATE.write().unwrap();
                if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
                    channel.last_verified_at = Some(current_time);
                    // Check if channel was previously verified - if so, it's now closed
                    match &channel.status {
                        LnChannelStatus::Verified { .. } => {
                            channel.status = LnChannelStatus::Closed;
                        }
                        _ => {
                            // Keep current status, UTXO might not be confirmed yet
                        }
                    }
                }
            }

            VerifyLnChannelResponse {
                verified: false,
                confirmations: None,
                utxo_value_sats: None,
                error: Some(format!(
                    "Funding UTXO not found at address {}. Channel may be closed or funding tx not yet confirmed.",
                    funding_address
                )),
            }
        }
    }
}

/// Query a specific Lightning channel
pub fn query_ln_channel_impl(request: QueryLnChannelRequest) -> Option<LnChannelInfo> {
    if request.channel_id.len() != 32 {
        return None;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&request.channel_id);

    let state = STATE.read().unwrap();
    state.ln_channels.get(&channel_id_arr).cloned()
}

/// Query all registered Lightning channels
pub fn query_ln_channels_impl() -> QueryLnChannelsResponse {
    let state = STATE.read().unwrap();
    let channels: Vec<LnChannelInfo> = state.ln_channels.values().cloned().collect();
    QueryLnChannelsResponse { channels }
}

/// Update a Lightning channel's status (e.g., when closed)
pub fn update_ln_channel_status_impl(channel_id: Vec<u8>, status: LnChannelStatus) -> bool {
    if channel_id.len() != 32 {
        return false;
    }

    let mut channel_id_arr = [0u8; 32];
    channel_id_arr.copy_from_slice(&channel_id);

    let mut state = STATE.write().unwrap();
    if let Some(channel) = state.ln_channels.get_mut(&channel_id_arr) {
        channel.status = status;
        true
    } else {
        false
    }
}
