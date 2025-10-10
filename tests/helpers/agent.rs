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
use super::id::{self, BTC_LEDGER_DEFAULT_FEE, BTC_LEDGER_ID, CKLIGHTNING_LEDGER_ID};
use bitcoin::secp256k1::PublicKey as SecpPublicKey;
use bitcoin::secp256k1::SecretKey as SecpSecretKey;
use bitcoin::secp256k1::{self, Secp256k1};
pub use candid::{
    Deserialize, Int, Nat,
    types::{Serializer, Type, TypeInner, TypeInner::Nat8},
};
use digest::{FixedOutput, Update};
use ed25519_dalek::Sha512 as Hasher;
use rand::rngs::StdRng;
use rand::thread_rng;

use candid::{CandidType, Principal};
use candid::{Decode, Encode};
use ic_ledger_types::{Timestamp, TransferError};
use rand::SeedableRng;
use serde::Serialize;
use serde::de::{Deserializer, Error as _};
use serde_bytes::ByteBuf;

use ic_agent::Agent;
use ic_agent::AgentError;
#[cfg(test)]
use ic_agent::identity::Identity;

pub struct ICAgent {
    pub agent: Agent,
}

#[cfg(test)]
use super::id::{PEM_NODE_ACC_PATH, PEM_USER_ACC_PATH};

#[derive(CandidType)]
pub struct Account {
    pub owner: Principal,
    pub subaccount: Option<Vec<u8>>,
}

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

#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct L2Account(pub SecpPublicKey);

#[derive(PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct ChannelId(pub [u8; 32]);

#[derive(PartialEq, Clone, Default, Deserialize, Eq, Hash, CandidType)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct Funding {
    /// The channel's unique identifier.
    pub channel: ChannelId,
    /// The funds' owner's layer-2 identity within the channel.
    pub participant: L2Account,
}

#[derive(PartialEq, Clone, Deserialize, Eq, Hash, CandidType)]

pub struct WithdrawalReq {
    /// The funds to be withdrawn.
    pub channel: ChannelId,
    pub participant: L2Account,
    pub amount: Nat,
    /// The layer-1 identity to send the funds to.
    pub receiver: Principal,
    // pub signature: L2Signature,
    // pub time: Timestamp,
}
fn string_to_static_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}
impl Funding {
    pub fn new(channel: ChannelId, participant: L2Account) -> Self {
        Self {
            channel,
            participant,
        }
    }

    pub fn memo(&self) -> u64 {
        let mut data = Vec::new();
        data.extend_from_slice(&self.channel.0);
        data.extend_from_slice(&self.participant.0.serialize());

        let h = Hash::digest(&data);
        let arr: [u8; 8] = [
            h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7],
        ];
        u64::from_le_bytes(arr)
    }
}

impl Clone for ChannelId {
    fn clone(&self) -> Self {
        ChannelId(self.0.clone())
    }
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

impl Default for ChannelId {
    fn default() -> Self {
        ChannelId([0; 32])
    }
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        // require!(bytes.len() == 32, D::Error::invalid_length(bytes.len(), &"32-byte ChannelId"));
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(ChannelId(arr))
    }
}

impl Default for L2Account {
    fn default() -> Self {
        // Create a random secret key
        let secp = Secp256k1::new();
        let mut rng = thread_rng();
        let (secret_key, public_key) = secp.generate_keypair(&mut rng);
        let secret_key = SecpSecretKey::new(&mut rng);
        let public_key = SecpPublicKey::from_secret_key(&secp, &secret_key);
        L2Account(public_key)
    }
}

impl<'de> Deserialize<'de> for L2Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = ByteBuf::deserialize(deserializer)?;
        let pk = SecpPublicKey::from_slice(bytes.as_slice())
            .ok()
            .ok_or(D::Error::invalid_length(bytes.len(), &"public key"))?;
        Ok(L2Account(pk))
    }
}

impl CandidType for L2Account {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> core::result::Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&self.0.serialize())
    }
}

impl CandidType for ChannelId {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> core::result::Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&self.0)
    }
}

impl ICAgent {
    // pub fn new_from_pem_file(pem_path: Option<&str>) -> Result<Self, AgentError> {
    //     let agent = Agent::builder()
    //         .with_url("http://127.0.0.1:4943")
    //         .with_identity(id::create_identity(pem_path))
    //         .build()?;
    //     Ok(ICAgent { agent })
    // }

    // pub fn new_from_pem_file(pem_path: Option<&'static str>) -> Result<Self, AgentError> {
    //     let agent = Agent::builder()
    //         .with_url("http://127.0.0.1:4943")
    //         .with_identity(id::create_identity(pem_path))
    //         .build()?;
    //     Ok(ICAgent { agent })
    // }
    pub fn new_from_pem_file(pem_path: Option<String>) -> Result<Self, AgentError> {
        let pem_path_static: Option<&'static str> = pem_path.map(|s| string_to_static_str(s));
        let agent = Agent::builder()
            .with_url("http://127.0.0.1:4943")
            .with_identity(id::create_identity(pem_path_static))
            .build()?;
        Ok(ICAgent { agent })
    }
    pub async fn fetch_root_key(&self) -> Result<(), AgentError> {
        self.agent.fetch_root_key().await
    }

    pub async fn tx_icrc1_transfer(
        &self,
        to: Principal,
        from: Principal,
        amount: u64,
        memo: u64,
    ) -> Result<Nat, AgentError> {
        let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

        let tx_args = TransferIcrc1 {
            from: Account {
                owner: from,
                subaccount: None,
            },
            to: Account {
                owner: to,
                subaccount: None,
            },
            amount: amount.into(),
            fee: BTC_LEDGER_DEFAULT_FEE.into(),
            memo,
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

    pub async fn deposit(&self, funding: Funding) -> Result<String, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let resp = self
            .agent
            .update(&can_ckl_id, "deposit")
            .with_arg(
                Encode!(&Funding {
                    channel: funding.channel,
                    participant: funding.participant
                })
                .unwrap(),
            )
            .call_and_wait()
            .await?;

        let deposit_result = Decode!(&resp, Option<String>).unwrap();

        match deposit_result {
            Some(error_message) => Err(error_message.into()),
            None => Ok("Deposit successful".to_string()),
        }
    }

    pub async fn query_contract_holdings(
        &self,
        funding: Funding,
    ) -> Result<Option<Nat>, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let resp = self
            .agent
            .query(&can_ckl_id, "query_holdings")
            .with_arg(Encode!(&funding).unwrap())
            .call()
            .await?;

        let balance = Decode!(&resp, Option<Nat>).unwrap();
        Ok(balance)
    }

    pub async fn transaction_notification(
        &self,
        funding: Funding,
        block: u64,
        amount: u64,
    ) -> Result<Option<Nat>, Box<dyn std::error::Error>> {
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
        let blockres_decoded = Decode!(&blockres, Option<Nat>).unwrap();

        Ok(blockres_decoded)
    }

    pub async fn trigger_withdraw(
        &self,
        amount: u64,
        funding: Funding,
        receiver: Principal,
    ) -> Result<Nat, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let withdraw_args = WithdrawalReq {
            amount: Nat(amount.into()),
            channel: funding.channel,
            participant: funding.participant,
            receiver,
        };

        let resp = self
            .agent
            .update(&can_ckl_id, "trigger_withdraw")
            .with_arg(Encode!(&withdraw_args).unwrap())
            .call_and_wait()
            .await?;

        let res = Decode!(&resp, Nat).unwrap();
        Ok(res)
    }

    pub async fn req_ln_invoice(
        &self,
        amount: u64,
        memo: String,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID)?;

        self.agent
            .fetch_root_key()
            .await
            .map_err(|e| format!("Failed to fetch root key: {}", e))?;

        let resp = self
            .agent
            .update(&can_ckl_id, "request_invoice")
            .with_arg(Encode!(&(amount, memo)).unwrap())
            .call_and_wait()
            .await?;

        let invoice = Decode!(&resp, String).unwrap();
        Ok(invoice)
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
struct TransferIcrc1 {
    from: Account,
    to: Account,
    amount: Nat,
    fee: Option<u64>,
    memo: u64, //Option<Vec<u8>>,
    created_at_time: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]

    async fn test_ic_minter_client_creation() -> Result<(), AgentError> {
        let client = ICAgent::new_from_pem_file(None)?;
        client.fetch_root_key().await?;
        client.agent.status().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_ic_user_client_creation() -> Result<(), AgentError> {
        let str_home = id::str_home_from_path(PEM_USER_ACC_PATH); // returns String
        let client = ICAgent::new_from_pem_file(Some(str_home))?;
        client.fetch_root_key().await?;
        client.agent.status().await?;
        Ok(())
    }

    #[tokio::test]
    async fn test_ic_operator_client_creation() -> Result<(), AgentError> {
        let str_home = id::str_home_from_path(PEM_NODE_ACC_PATH);
        let client = ICAgent::new_from_pem_file(Some(str_home))?;
        client.fetch_root_key().await?;
        client.agent.status().await?;

        Ok(())
    }

    #[tokio::test]
    async fn test_ckbtc_balance_lnpd_l1() -> Result<(), AgentError> {
        let nat_amount = Nat(5000u64.into());

        println!(
            "\nTransfer {:?} msat from Lightning user to Lightning node\n",
            nat_amount
        );

        let client = ICAgent::new_from_pem_file(Some(id::str_home_from_path(PEM_NODE_ACC_PATH)))?;
        client.fetch_root_key().await?;

        let can_btcldg_id = Principal::from_text(BTC_LEDGER_ID).unwrap();
        let node_path = id::str_home_from_path(PEM_NODE_ACC_PATH);
        let usr_node_id = id::create_identity(Some(&node_path));

        // let usr_node_id = id::create_identity(Some(&id::str_home_from_path(PEM_NODE_ACC_PATH)));

        let user_path = id::str_home_from_path(PEM_USER_ACC_PATH);
        let usr_user_id = id::create_identity(Some(&user_path));

        // let usr_user_id = id::create_identity(Some(&id::str_home_from_path(PEM_USER_ACC_PATH)));

        let usr_node_pr = usr_node_id.sender().unwrap();
        let usr_user_pr = usr_user_id.sender().unwrap();

        let resp_node = client
            .agent
            .query(&can_btcldg_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_node_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let resp_user = client
            .agent
            .query(&can_btcldg_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_user_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let res_user = Decode!(&resp_user, Option<Nat>).unwrap();
        let res_node = Decode!(&resp_node, Option<Nat>).unwrap();

        println!("Balance of node before tx: {:?}", res_node.unwrap());
        println!("Balance of user before tx: {:?}", res_user.unwrap());

        let tx_args = TransferIcrc1 {
            from: Account {
                owner: usr_node_pr,
                subaccount: None,
            },
            to: Account {
                owner: usr_user_pr,
                subaccount: None,
            },
            amount: nat_amount,
            fee: 10u64.into(),
            memo: 1u64, //Some(0u64.to_be_bytes().to_vec()),
            created_at_time: None,
        };

        let transfer_some_tx = client
            .agent
            .update(&can_btcldg_id, "icrc1_transfer")
            .with_arg(Encode!(&tx_args).unwrap())
            .call_and_wait()
            .await?;

        let resp_user_after_tx = client
            .agent
            .query(&can_btcldg_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_user_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let resp_user_after_tx_dec = Decode!(&resp_user_after_tx, Option<Nat>).unwrap();

        let resp_node_after_tx = client
            .agent
            .query(&can_btcldg_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_node_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;
        let resp_node_after_tx_dec = Decode!(&resp_node_after_tx, Option<Nat>).unwrap();

        println!(
            "Balance of node after tx: {:?}",
            resp_node_after_tx_dec.unwrap()
        );
        println!(
            "Balance of user after tx: {:?}",
            resp_user_after_tx_dec.unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_ckbtc_balance_cklightning_l1() -> Result<(), AgentError> {
        let nat_amount = Nat(10000u64.into());

        println!(
            "\nTransfer {:?} msat from Lightning user to Lightning node\n",
            nat_amount
        );

        let client = ICAgent::new_from_pem_file(Some(id::str_home_from_path(PEM_NODE_ACC_PATH)))?;
        client.fetch_root_key().await?;

        let can_ckl_id = Principal::from_text(BTC_LEDGER_ID).unwrap();

        let user_path = id::str_home_from_path(PEM_USER_ACC_PATH);
        let usr_user_id = id::create_identity(Some(&user_path));
        // let usr_user_id = id::create_identity(Some(id::str_home_from_path(PEM_USER_ACC_PATH)));

        let usr_user_pr = usr_user_id.sender().unwrap();

        let (sk, pk) = create_keypair();

        let funding = Funding {
            channel: ChannelId([0; 32]), // Use a dummy channel ID for this test
            participant: L2Account(pk.clone()),
        };

        let resp_user = client
            .agent
            .query(&can_ckl_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_user_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let res_user = Decode!(&resp_user, Option<Nat>).unwrap();
        println!("Balance of user before tx: {:?}", res_user.unwrap());

        let tx_args = TransferIcrc1 {
            from: Account {
                owner: can_ckl_id,
                subaccount: None,
            },
            to: Account {
                owner: usr_user_pr,
                subaccount: None,
            },
            amount: nat_amount,
            fee: 1000u64.into(),
            memo: 1u64, //Some(0u64.to_be_bytes().to_vec()),
            created_at_time: None,
        };

        let transfer_some_tx = client
            .agent
            .update(&can_ckl_id, "icrc1_transfer")
            .with_arg(Encode!(&tx_args).unwrap())
            .call_and_wait()
            .await?;

        let transfer_some_tx_decoded =
            Decode!(&transfer_some_tx, Result<Nat,TransferError>).unwrap();

        let resp_user_after_tx = client
            .agent
            .query(&can_ckl_id, "icrc1_balance_of")
            .with_arg(
                Encode!(&Account {
                    owner: usr_user_pr,
                    subaccount: None
                })
                .unwrap(),
            )
            .call()
            .await?;

        let resp_user_after_tx_dec = Decode!(&resp_user_after_tx, Option<Nat>).unwrap();

        println!(
            "Balance of user after tx: {:?}",
            resp_user_after_tx_dec.unwrap()
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_ckbtc_deposit_cklightning_contract() -> Result<(), AgentError> {
        let mut amount_u64 = 10000u64;
        amount_u64 += 2 * BTC_LEDGER_DEFAULT_FEE; // Add fee to the amount
        let nat_amount = Nat(amount_u64.into());

        let client = ICAgent::new_from_pem_file(Some(id::str_home_from_path(PEM_USER_ACC_PATH)))?;
        client.fetch_root_key().await?;

        let can_ckl_id = Principal::from_text(CKLIGHTNING_LEDGER_ID).unwrap();

        // let usr_user_id = id::create_identity(Some(&id::str_home_from_path(PEM_USER_ACC_PATH)));
        let user_path = id::str_home_from_path(PEM_USER_ACC_PATH);
        let usr_user_id = id::create_identity(Some(&user_path));

        let usr_user_pr = usr_user_id.sender().unwrap();

        // Query user's ckBTC balance

        let resp_user_balance_result = client.icrc1_balance_of(usr_user_pr).await;
        let resp_contract_balance_result = client.icrc1_balance_of(can_ckl_id).await;
        let resp_contract_balance = resp_contract_balance_result.unwrap();

        let resp_user_balance = resp_user_balance_result.unwrap();

        println!("\nUser ckBTC Balance in Wallet: {:?}", resp_user_balance);
        println!("\nContract ckBTC Balance: {:?}", resp_contract_balance);

        // Prepare funding and deposit to contract
        let (_, pk) = create_keypair();
        let funding = Funding {
            channel: ChannelId([0; 32]),
            participant: L2Account(pk.clone()),
        };

        let resp_user_before_deposit_query_tx =
            client.query_contract_holdings(funding.clone()).await;

        let resp_user_before_deposit_tx = resp_user_before_deposit_query_tx.unwrap();

        println!(
            "\nUser ckBTC Balance in ckLightning Canister: {:?}",
            resp_user_before_deposit_tx
        );

        let memo_transfer = funding.memo();

        let transfer_some_tx_decoded = client
            .tx_icrc1_transfer(can_ckl_id, usr_user_pr, amount_u64.clone(), memo_transfer)
            .await
            .map_err(|e| format!("Failed to get user balance: {}", e));

        println!(
            "\nUser -> ckLightning icrc1_transfer in Block: {:?} with amount: {:?}",
            transfer_some_tx_decoded.clone().unwrap(),
            nat_amount.clone()
        );

        let resp_contract_balance_result2 = client.icrc1_balance_of(can_ckl_id).await;
        let resp_contract_balance2 = resp_contract_balance_result2.unwrap();
        println!(
            "\nContract ckBTC Balance after transfer: {:?}",
            resp_contract_balance2
        );

        // Notify contract of receipt
        let block = transfer_some_tx_decoded.clone().unwrap();
        let blocku64 = block.0.to_u64_digits()[0];

        let tx_notification_result = client
            .transaction_notification(funding.clone(), blocku64, amount_u64)
            .await;

        println!(
            "\nNotification Result of User Deposit to Contract: {:?}",
            tx_notification_result.unwrap()
        );

        let resp_contract_deposit = client.deposit(funding.clone()).await;

        println!("Deposit Response: {:?}", resp_contract_deposit);

        // Query user's balance after deposit

        let resp_user_after_tx = client.icrc1_balance_of(usr_user_pr).await;

        println!(
            "\nUser ckBTC balance after deposit: {:?}",
            resp_user_after_tx.unwrap()
        );

        let user_contract_balance_after = client.query_contract_holdings(funding.clone()).await;

        println!(
            "\nUser contract balance after deposit: {:?}",
            user_contract_balance_after
        );

        // User balance before withdrawal

        let user_balance_before_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

        println!(
            "User ckBTC balance before withdrawal: {:?}",
            user_balance_before_withdrawal
        );

        // // Trigger withdraw

        let trigger_withdraw_tx = client
            .trigger_withdraw(200u64.into(), funding.clone(), usr_user_pr)
            .await;

        println!("trigger_withdraw tx decoded: {:?}", trigger_withdraw_tx);

        let resp_user_after_withdrawal = client.icrc1_balance_of(usr_user_pr).await;

        println!(
            "\nUser's ckBTC balance after withdrawal: {:?}",
            resp_user_after_withdrawal
        );

        // Final contract holdings

        let resp_user_after_withdrawal_query_tx =
            client.query_contract_holdings(funding.clone()).await;

        println!(
            "\nFinal User holdings in Contract: {:?}",
            resp_user_after_withdrawal_query_tx
        );

        let resp_contract_final_query_tx = client.icrc1_balance_of(can_ckl_id).await;

        println!(
            "Contract final ckBTC Balance in ckLightning Canister: {:?}",
            resp_contract_final_query_tx.unwrap()
        );

        Ok(())
    }
}

fn create_keypair() -> (SecpSecretKey, SecpPublicKey) {
    let secp = Secp256k1::new();
    let mut rng = StdRng::seed_from_u64(89899);
    secp.generate_keypair(&mut rng)
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct NotifyArgs {
    pub block_height: u64,
    pub amount: u64,
    pub funding: Funding,
}
