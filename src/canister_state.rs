//  Copyright 2025 PolyCrypt GmbH
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
use crate::error::{BtcError, CklError, ResultBtc};
use crate::ic_types::PoolAsset;
use crate::ic_types::{
    Amount, ChannelFunding, ChannelId, DEVNET_CKBTC_LEDGER, DEVNET_CKBTC_MINTER, DepositorInfo,
    Funding, FundingLPArgs, FundingLPQueryArgs, GetBtcAddressArgs, HoldingsResponse, L2Account,
    NotifyArgs, PoolWithdrawal, RegisteredState, SetBtcAddressArgs, SetBtcAddressMsg,
    SetBtcAddressResponse, WithdrawalLPArgs, WithdrawalReq,
};
use crate::liquidity_pool::LiquidityPool;
use crate::receiver::ICPReceiverError;
use crate::receiver::TransactionICRCNotification;
use candid::Encode;
use ic_cdk::api::call::CallResult;
use ic_cdk::api::canister_self;
use ic_cdk::api::msg_caller;
use ic_cdk::api::time as blocktime;
use icrc_ledger_types::icrc1::account::Account;
use icrc_ledger_types::icrc1::transfer::TransferArg;
use k256::ecdsa::Signature;
use k256::ecdsa::VerifyingKey;
use k256::ecdsa::signature::Verifier;
use k256::pkcs8::DecodePublicKey;
use k256::sha2::{Digest, Sha256};

use crate::error::ResultCkl;
use crate::ic_types::{DEFAULT_CKBTC_FEE, L1Account, Params, State, Timestamp};
use crate::require;

use crate::receiver;
use candid::{Nat, Principal};

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
    own_principal: Principal,
    own_btc_address: Option<String>,
    icrc_receiver: receiver::Receiver<Q>,
    user_holdings: HashMap<Funding, Amount>,
    channels: HashMap<ChannelId, RegisteredState>,
    liq_pool: LiquidityPool,
}

pub async fn set_btc_address_impl(
    set_btc_address_args: SetBtcAddressArgs,
) -> std::result::Result<SetBtcAddressResponse, BtcError> {
    let mut state = STATE.write().unwrap();
    let current_btc_address = state.own_btc_address.clone();

    // If address already exists, return that result immediately
    if let Some(address) = current_btc_address {
        return Ok(SetBtcAddressResponse {
            address,
            msg: SetBtcAddressMsg::BtcAddressAlreadySet,
        });
    }

    // If None, fetch the address asynchronously
    let address = match state.get_btc_address().await {
        Ok(addr) => addr,
        Err(e) => return Err(e),
    };

    // Update the state now that address was fetched
    state.own_btc_address = Some(address.clone());

    // Return proper response indicating success
    Ok(SetBtcAddressResponse {
        address,
        msg: SetBtcAddressMsg::BtcAddressSetNow,
    })
}

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
            own_principal: canister_self(),
            own_btc_address: None, // this will be initialized later by an authorized call
            icrc_receiver: receiver::Receiver::new(q, my_principal),
            user_holdings: Default::default(),
            channels: Default::default(),
            liq_pool: LiquidityPool::new(),
        }
    }

    pub fn set_btc_address_impl(&mut self, address: String) -> () {
        self.own_btc_address = Some(address);
    }

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

    async fn get_btc_address(&self) -> ResultBtc<String> {
        let ckbtc_minter_id = Principal::from_text(DEVNET_CKBTC_MINTER).expect("parsing principal");

        let own_principal = Some(self.own_principal);

        let get_btc_address_args = GetBtcAddressArgs {
            principal: own_principal,
            subaccount: None,
        };

        let call_result: CallResult<(String,)> =
            ic_cdk::call(ckbtc_minter_id, "get_btc_address", (get_btc_address_args,)).await;

        match call_result {
            Ok((address,)) => Ok(address),
            Err((_code, msg)) => Err(BtcError::BtcAddressFetchError(msg)),
        }
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
