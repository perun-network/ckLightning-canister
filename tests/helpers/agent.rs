// Copyright 2025 - See NOTICE file for copyright holders.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
use cklightning::btc::address::derive_btc_address;
extern crate cklightning;
use super::id::{
    self, BTC_LEDGER_DEFAULT_FEE, BTC_LEDGER_ID, BTC_MINTER_ID, CKLIGHTNING_LEDGER_ID,
    DEVNET_BASIC_BITCOIN,
};
pub use candid::{Deserialize, Nat, types::Serializer};
use cklightning::error::{BtcError, CklError, ResultBtc};
use cklightning::ic_types::{
    BtcAddressType, Funding, FundingLPArgs, FundingLPQuery, FundingLPQueryArgs,
    GetBtcAddressArgs, GetBtcBalancesResponse, HoldingsResponse,
    PoolWithdrawal, SendFromP2pkhAddressArgs, SetBtcAddressArgs,
    SetBtcAddressResponse, WithdrawalLPArgs,
};
use cklightning::ic_types::{LnInvoiceRequest, SignedCandidInvoice};
use cklightning::receiver::ICPReceiverError;
use cklightning::receiver::TransactionICRCNotification;
use digest::{FixedOutput, Update};
use ed25519_dalek::Sha512 as Hasher;
use icrc_ledger_types::icrc1::{
    account::Account,
    transfer::{Memo, TransferArg},
};
use icrc_ledger_types::icrc3::blocks::{GetBlocksRequest, GetBlocksResult};

use candid::{CandidType, Decode, Encode, Principal};
use ic_agent::identity::Secp256k1Identity;
use ic_ledger_types::{Timestamp, TransferError};
use serde::Serialize;

#[cfg(test)]
use ic_agent::{Agent, AgentError};

pub struct ICAgent {
    pub agent: Agent,
    pub signer: Secp256k1Identity,
}

#[cfg(test)]
use super::id::{PEM_NODE_ACC_PATH, PEM_USER_ACC_PATH};

#[derive(CandidType, Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub enum ApproveError {
    GenericError { message: String, error_code: Nat },
    TemporarilyUnavailable,
    Duplicate { duplicate_of: Nat },
    BadFee { expected_fee: Nat },
    AllowanceChanged { current_allowance: Nat },
    CreatedInFuture { ledger_time: Timestamp },
    TooOld,
    Expired { ledger_time: Timestamp },
    InsufficientFunds { balance: Nat },
}

#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Default, Clone)]
/// A hash as used by the signature scheme.
pub struct Hash(pub digest::Output<Hasher>);

fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

impl Hash {
    pub fn digest(msg: &[u8]) -> Self {
        let mut h = Hasher::default();
        h.update(msg);
        let mut out: Hash = Hash::default();
        h.finalize_into(&mut out.0);
        out
    }
}

impl ICAgent {
    pub fn new_from_pem_file(pem_path: Option<String>) -> Result<Self, AgentError> {
        let pem_path_static: Option<&'static str> = pem_path.map(|s| string_to_static_str(s));
        let secp_id = id::create_secp_identity(pem_path_static);
        let agent = Agent::builder()
            .with_url("http://127.0.0.1:4943")
            .with_identity(id::create_identity(pem_path_static))
            .build()?;
        Ok(ICAgent {
            agent,
            signer: secp_id,
        })
    }
    pub async fn fetch_root_key(&self) -> Result<(), AgentError> {
        self.agent.fetch_root_key().await
    }
    pub async fn tx_icrc1_transfer(
        &self,
        to: Principal,
        from: Principal,
        amount: u64,
        memo: std::vec::Vec<u8>,
    ) -> Result<Nat, AgentError> {
        let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

        let tx_args = TransferArg {
            from_subaccount: None,
            to: Account {
                owner: to,
                subaccount: None,
            },
            amount: Nat(amount.into()),
            fee: Nat::from(BTC_LEDGER_DEFAULT_FEE).into(),
            memo: Some(Memo::from(memo)),
            created_at_time: None,
        };

        let tx_args_encoded = Encode!(&tx_args).unwrap();

        let resp = self
            .agent
            .update(&can_btcldg_id, "icrc1_transfer")
            .with_arg(tx_args_encoded)
            .call_and_wait()
            .await?;

        let res = Decode!(&resp, Result<Nat, TransferError>).unwrap();

        let block_index = res.unwrap();
        println!("Block index from transfer: {:?}", block_index);

        Ok(block_index)
    }

    pub async fn tx_icrc2_approve(&self, to: Principal, amount: u64) -> Result<Nat, AgentError> {
        let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

        let tx_args = ApproveIcrc2 {
            amount: Nat(amount.into()),
            spender: Account {
                owner: to,
                subaccount: None,
            },
            expected_allowance: Some(amount),
            from_subaccount: None,
            expires_at: None,
            fee: None,
            memo: None,
            created_at_time: None,
        };

        let tx_args_encoded = Encode!(&tx_args).unwrap();

        let resp = self
            .agent
            .update(&can_btcldg_id, "icrc2_approve")
            .with_arg(tx_args_encoded)
            .call_and_wait()
            .await?;

        let res = Decode!(&resp, Result<Nat, ApproveError>)
            .map_err(|e| AgentError::CandidError(Box::new(e)))?;
        let block_index = res.unwrap();
        println!("Block index from transfer: {:?}", block_index);
        Ok(block_index)
    }

    pub async fn icrc1_balance_of(&self, pr: Principal) -> Result<Nat, Box<dyn std::error::Error>> {
        let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let acc_id = pr.clone();

        let resp = self
            .agent
            .query(&can_btcldg_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: acc_id,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let balance = Decode!(&resp, Option<Nat>).unwrap();
        let bal_res = balance.unwrap();
        Ok(bal_res)
    }

    pub async fn query_block(
        &self,
        ledger_canister_id: &str,
        block_idx: Nat,
    ) -> Result<GetBlocksResult, Box<dyn std::error::Error>> {
        let ledger_id = Principal::from_text(ledger_canister_id)?;

        let getblocks_args = vec![GetBlocksRequest {
            start: block_idx,
            length: Nat::from(50u64),
        }];

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let arg = Encode!(&getblocks_args).map_err(|e| Box::<dyn std::error::Error>::from(e))?;

        let resp = self
            .agent
            .query(&ledger_id, "icrc3_get_blocks")
            .with_arg(arg)
            .call()
            .await
            .map_err(|e| Box::<dyn std::error::Error>::from(e))?;
        let blocks_result: GetBlocksResult = Decode!(&resp, GetBlocksResult)?;

        if blocks_result.blocks.is_empty() {
            return Err("No blocks found in ledger block".into());
        }

        // Return the block ID (as Nat)
        Ok(blocks_result.clone())
    }

    pub async fn deposit(
        &self,
        funding: Funding,
        signed_funding: Vec<u8>,
    ) -> Result<String, CklError> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| CklError::Other(format!("Invalid Principal: {}", e)))?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| CklError::Other(format!("Failed to fetch root key: {}", e)))?;

        let pool_funding = match &funding {
            Funding::Pool(pf) => pf.clone(),
            _ => return Err(CklError::Other("Expected Pool funding".to_string())),
        };

        let funding_lp_args = FundingLPArgs {
            pool_funding: pool_funding.clone(),
            signature: signed_funding,
        };

        let resp = self
            .agent
            .update(&can_ckl_id, "deposit_lp")
            .with_arg(Encode!(&funding_lp_args).unwrap())
            .call_and_wait()
            .await
            .map_err(|e| CklError::Other(format!("Update call failed: {}", e)))?;

        // Decode as Result<(), CklError>
        let deposit_result = Decode!(&resp, Result<(), CklError>)
            .map_err(|e| CklError::Other(format!("Decode failed: {}", e)))?;

        match deposit_result {
            Ok(()) => Ok("Deposit successful".to_string()),
            Err(e) => Err(e),
        }
    }
    pub async fn query_user_lp_holdings(
        &self,
        funding_lp_query: FundingLPQuery,
        sig_funding: Vec<u8>,
    ) -> Result<HoldingsResponse, CklError> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| CklError::Other(format!("Invalid principal: {}", e)))?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| CklError::Other(format!("Failed to fetch root key: {}", e)))?;

        let fundingqueryargs = FundingLPQueryArgs {
            funding_query: funding_lp_query.clone(),
            funding_query_sig: sig_funding.clone(),
        };

        let resp = self
            .agent
            .query(&can_ckl_id, "query_user_lp_holdings")
            .with_arg(Encode!(&fundingqueryargs).unwrap())
            .call()
            .await
            .map_err(|e| CklError::Other(format!("Query call failed: {}", e)))?;

        let balance_result = Decode!(&resp, std::result::Result<HoldingsResponse, CklError>)
            .map_err(|e| CklError::Other(format!("Decode failed: {}", e)))?;

        match balance_result {
            Ok(holdings) => Ok(holdings),
            Err(e) => Err(e),
        }
    }

    pub async fn get_btc_balance(
        &self,
        confirmations: Option<u64>,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid principal: {}", e)))?;

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let own_prince = self.agent.get_principal().map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Get principal failed: {}", e))
        })?;

        let resp = self
            .agent
            .update(&can_ckl_id, "get_btc_balance")
            .with_arg(Encode!(&confirmations).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Encoding failed: {}", e))
            })?)
            .call_and_wait()
            .await
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("get_btc_balance call failed: {}", e))
            })?;

        let decoded_response = Decode!(&resp, std::result::Result<GetBtcBalancesResponse, BtcError>)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decode failed: {}", e)))?;

        let response = decoded_response?;

        Ok(response
            .balances
            .get(&own_prince)
            .unwrap_or(&None)
            .unwrap_or(0)
            .clone())
    }

    pub async fn get_btc_balance_from_bitcoin_canister(
        &self,
        balance_of: Principal,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid principal: {}", e)))?;

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let setbtcaddressargs = SetBtcAddressArgs {
            principal: Some(can_ckl_id.clone()),
            subaccount: None,
            address_type: cklightning::ic_types::BtcAddressType::P2WPKH,
        };

        let resp = self
            .agent
            .update(&can_ckl_id, "get_balance")
            .with_arg(Encode!(&setbtcaddressargs).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Encoding failed: {}", e))
            })?)
            .call_and_wait()
            .await
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("set_btc_address call failed: {}", e))
            })?;

        // Decode as SetBtcAddressResponse directly:
        let decoded_response = Decode!(&resp, std::result::Result<SetBtcAddressResponse, BtcError>) //std::result::Result<SetBtcAddressResponse, BtcError>
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decode failed: {}", e)))?;

        // Extract the String address field (adjust field name):
        // let msg_string = decoded_response.unwrap().msg;
        let response = decoded_response.unwrap();
        // Now response is SetBtcAddressResponse
        let address_string = response.address;
        let msg = response.msg;

        println!(
            "Decoded Response: address = {}, msg = {:?}",
            address_string, msg
        );

        Ok(address_string)
    }

    pub async fn set_btc_address(
        &self,
        address_type: BtcAddressType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid principal: {}", e)))?;

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let caller_principal = self.agent.get_principal()
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Get principal failed: {}", e)))?;

        let setbtcaddressargs = SetBtcAddressArgs {
            principal: Some(caller_principal),
            subaccount: None,
            address_type,
        };

        let resp = self
            .agent
            .update(&can_ckl_id, "set_btc_address")
            .with_arg(Encode!(&setbtcaddressargs).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Encoding failed: {}", e))
            })?)
            .call_and_wait()
            .await
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("set_btc_address call failed: {}", e))
            })?;

        // Decode as SetBtcAddressResponse directly:
        let decoded_response = Decode!(&resp, std::result::Result<SetBtcAddressResponse, BtcError>) //std::result::Result<SetBtcAddressResponse, BtcError>
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decode failed: {}", e)))?;

        // Extract the String address field (adjust field name):
        // let msg_string = decoded_response.unwrap().msg;
        let response = decoded_response.unwrap();
        // Now response is SetBtcAddressResponse
        let address_string = response.address;
        let msg = response.msg;

        println!(
            "Decoded Response: address = {}, msg = {:?}",
            address_string, msg
        );

        Ok(address_string)
    }

    pub async fn transaction_notification(
        &self,
        funding: Funding,
        block: u64,
        amount: u64,
    ) -> Result<Result<TransactionICRCNotification, ICPReceiverError>, Box<dyn std::error::Error>>
    {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let args_notify = NotifyArgs {
            block_height: block,
            amount,
            funding,
        };

        let blockres = self
            .agent
            .update(&can_ckl_id, "transaction_notification")
            .with_arg(Encode!(&args_notify).unwrap())
            .call_and_wait()
            .await?;
        // let blockres_decoded = Decode!(&blockres, Option<Nat>).unwrap();
        let blockres_decoded =
            Decode!(&blockres, Result<TransactionICRCNotification, ICPReceiverError>).unwrap();

        Ok(blockres_decoded)
    }

    pub async fn withdraw_lp(
        &self,
        // amount: u64,
        withdraw: PoolWithdrawal,
        signed_witdrawal: Vec<u8>,
        receiver: Principal,
    ) -> Result<Result<(), CklError>, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let withdraw_args = WithdrawalLPArgs {
            pool_withdrawal: withdraw,
            signature: signed_witdrawal,
        };

        let resp = self
            .agent
            .update(&can_ckl_id, "withdraw_lp")
            .with_arg(Encode!(&withdraw_args).unwrap())
            .call_and_wait()
            .await?;

        let res = Decode!(&resp, Result<(), CklError>).unwrap();
        Ok(res)
    }

    pub async fn get_btc_bb_balance(
        &self,
        receiver: String,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        let can_basic_bitcoin_id = Principal::from_text(DEVNET_BASIC_BITCOIN)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        // let send_from_p2pkh_address_args = SendFromP2pkhAddressArgs {
        //     destination_address: receiver, //send_btc_args.to_address.clone(),
        //     amount_in_satoshi: amount_sat, //send_btc_args.amount_sat.clone(),
        // };

        let resp = self
            .agent
            .update(&can_basic_bitcoin_id, "get_balance")
            .with_arg(Encode!(&receiver).unwrap())
            .call_and_wait()
            .await?;

        let tx_id = Decode!(&resp, u64).map_err(|e| format!("Decoding failed: {}", e))?;

        Ok(tx_id)
    }

    pub async fn send_btc(
        &self,
        // withdraw: PoolWithdrawal,
        amount_sat: u64,
        receiver: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_basic_bitcoin_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        // let send_btc_args = SendBtcArgs {
        //     to_address: receiver,
        //     amount_sat,
        // };

        let send_from_p2pkh_address_args = SendFromP2pkhAddressArgs {
            destination_address: receiver, //send_btc_args.to_address.clone(),
            amount_in_satoshi: amount_sat, //send_btc_args.amount_sat.clone(),
        };

        let resp = self
            .agent
            .update(&can_basic_bitcoin_id, "send_from_p2pkh_address")
            .with_arg(Encode!(&send_from_p2pkh_address_args).unwrap())
            .call_and_wait()
            .await?;

        let tx_id = Decode!(&resp, String).map_err(|e| format!("Decoding failed: {}", e))?;

        Ok(tx_id)
    }

    pub async fn req_ln_invoice(
        &self,
        invoice_req: LnInvoiceRequest,
    ) -> Result<SignedCandidInvoice, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;
        let args = invoice_req.clone();
        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let resp = self
            .agent
            .update(&can_ckl_id, "query_ln_invoice")
            .with_arg(Encode!(&args).unwrap())
            .call_and_wait()
            .await?;

        let invoice = Decode!(&resp, SignedCandidInvoice).unwrap();
        Ok(invoice)
    }

    pub async fn get_own_btc_address_depr(
        &self,
        address_type: BtcAddressType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        derive_btc_address(address_type).await
    }

    pub async fn get_ckl_btc_address(
        &self,
        address_type: BtcAddressType,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_basic_btc_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        let principal = self.agent.get_principal().clone()?;
        let method_name = match address_type {
            BtcAddressType::P2PKH => "get_p2pkh_address",
            BtcAddressType::P2WPKH => "get_p2wpkh_address",
            BtcAddressType::P2TR => "get_p2tr_key_only_address",
        };
        let args = SetBtcAddressArgs {
            principal: Some(principal),
            subaccount: None,
            address_type,
        };

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let resp = self
            .agent
            .update(&can_basic_btc_id, method_name)
            .with_arg(Encode!(&args).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Encoding failed: {}", e))
            })?)
            .call_and_wait()
            .await?;

        let btc_address = Decode!(&resp, ResultBtc<String>)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decoding failed: {}", e)))
            .and_then(|v| v.map_err(|e| Box::<dyn std::error::Error>::from(e)))?;
        Ok(btc_address)
        // btc_address
    }

    pub async fn get_own_btc_address(&self) -> Result<String, Box<dyn std::error::Error>> {
        let btc_minter_id = Principal::from_text(BTC_MINTER_ID)?;

        let principal = self.agent.get_principal().clone()?;

        let args = GetBtcAddressArgs {
            principal: Some(principal),
            subaccount: None,
        };

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let resp = self
            .agent
            .update(&btc_minter_id, "get_btc_address")
            .with_arg(Encode!(&args).map_err(|e| {
                Box::<dyn std::error::Error>::from(format!("Encoding failed: {}", e))
            })?)
            .call_and_wait()
            .await?;

        let btc_address = Decode!(&resp, String)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decoding failed: {}", e)))?;

        Ok(btc_address)
    }

    pub async fn get_btc_liquidity_address(
        &self,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)
            .map_err(|e| Box::<dyn std::error::Error>::from(format!("Invalid principal: {}", e)))?;

        self.agent.fetch_root_key().await.map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Failed to fetch root key: {}", e))
        })?;

        let resp = self
            .agent
            .update(&can_ckl_id, "get_btc_liquidity_address_for_caller")
            .with_arg(Encode!().unwrap())
            .call_and_wait()
            .await
            .map_err(|e| {
                Box::<dyn std::error::Error>::from(format!(
                    "get_btc_liquidity_address_for_caller call failed: {}",
                    e
                ))
            })?;

        let decoded_response =
            Decode!(&resp, std::result::Result<String, BtcError>)
                .map_err(|e| Box::<dyn std::error::Error>::from(format!("Decode failed: {}", e)))?;

        let address = decoded_response?;
        println!("BTC liquidity address: {}", address);
        Ok(address)
    }
}

#[derive(CandidType)]
struct ApproveIcrc2 {
    fee: Option<u64>,
    amount: Nat,
    memo: Option<Vec<u8>>,
    from_subaccount: Option<Vec<u8>>,
    created_at_time: Option<u64>,
    expected_allowance: Option<u64>,
    expires_at: Option<u64>,
    spender: Account,
}

#[derive(CandidType)]
pub struct TransferIcrc1 {
    pub from: Account,
    pub to: Account,
    pub amount: Nat,
    pub fee: Option<u64>,
    pub memo: std::vec::Vec<u8>,
    pub created_at_time: Option<u64>,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct NotifyArgs {
    pub block_height: u64,
    pub amount: u64,
    pub funding: Funding,
}
