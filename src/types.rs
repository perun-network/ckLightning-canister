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
use digest::{FixedOutputDirty, Update};

use crate::{
    error::{Error, Result as CanisterResult},
    require,
};
use ed25519_dalek::{PublicKey, Sha512 as Hasher, Signature};

use bitcoin::{
    hashes::hex::ToHex,
    secp256k1::{self, PublicKey as SecpPublicKey, Secp256k1},
};
use candid::Encode;
pub use candid::{
    types::{Serializer, Type, TypeInner, TypeInner::Nat8},
    Deserialize, Int, Nat,
};
use candid::{CandidType, Principal};
use core::cmp::*;
use core::convert::*;

use serde::de::{Deserializer, Error as _};
use serde_bytes::ByteBuf;

// Type definitions start here.

/// A layer-2 account identifier.
#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct L2Account(pub SecpPublicKey);
#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Default, Clone)]
/// A hash as used by the signature scheme.
pub struct Hash(pub digest::Output<Hasher>);

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
/// Identifies the funds belonging to a certain layer 2 identity within a
/// certain channel.
pub struct Funding {
    /// The channel's unique identifier.
    pub channel: ChannelId,
    /// The funds' owner's layer-2 identity within the channel.
    pub participant: L2Account,
    // pub receiver: L1Account,
}

#[derive(PartialEq, Clone, Deserialize, Eq, CandidType, Hash)]
pub struct PoolFunding {
    /// The funds' owner's layer-2 identity within the channel.
    pub participant: L2Account,
    /// The layer-1 identity to send the funds to.
    pub depositor: L1Account,
}

/// An amount of a currency.
pub type Amount = Nat;
/// Duration in nanoseconds (same as ICP timestamps).
pub type Duration = u64;
/// Timestamp in nanoseconds (same as ICP timestamps).
pub type Timestamp = u64;
/// Unique Perun channel identifier.
#[derive(PartialEq, Eq, Ord, PartialOrd, Hash)] //Hash
pub struct ChannelId(pub [u8; 32]);

#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Clone, Deserialize, CandidType)] //Hash,
pub struct L1Account(pub Principal);

/// A channel's unique nonce.
#[derive(PartialEq, Eq, Ord, PartialOrd)] //Hash,

pub struct Nonce(pub [u8; 32]);

/// Channel state version identifier.
pub type Version = u64;

#[derive(Deserialize, CandidType, Clone)]
/// The immutable parameters and state of a Perun channel.
pub struct Params {
    /// The channel's unique nonce, to protect against replay attacks.
    pub nonce: Nonce,
    /// The channel's participants' layer-2 identities.
    pub participants: Vec<L2Account>,
    /// When a dispute occurs, how long to wait for responses.
    pub challenge_duration: Duration,
}

#[derive(Deserialize, CandidType, Default, Clone)]
/// The mutable parameters and state of a Perun channel. Contains
pub struct State {
    /// The cannel's unique identifier.
    pub channel: ChannelId,
    /// The channel's current state revision number.
    pub version: Version,
    /// The channel's asset allocation. Contains each participant's current
    /// balance in the order of the channel parameters' participant list.
    pub allocation: Vec<Amount>,
    /// Whether the channel is finalized, i.e., no more updates can be made and
    /// funds can be withdrawn immediately. A non-finalized channel has to be
    /// finalized via the canister after the channel's challenge duration
    /// elapses.
    // pub l1_accounts: Vec<L1Account>,
    pub finalized: bool,
    // shows the phase the channel is in
}

#[derive(Clone, Deserialize, CandidType)]
/// A registered channel's state, as seen by the canister. Represents a channel
/// after a call to "conclude" or "dispute" on the canister. The timeout, in
/// combination with the state's "finalized" flag determine whether a channel is
/// concluded and its funds ready for withdrawing.
pub struct RegisteredState {
    /// The channel's state, containing challenge duration, outcomes, and
    /// whether the channel is already finalized.
    pub state: State,
    /// The challenge timeout after which the currently registered state becomes
    /// available for withdrawing. Ignored for finalized channels.
    pub timeout: Timestamp,
}

#[derive(Deserialize, CandidType, Clone)]
// / Contains the payload of a request to withdraw a participant's funds from a
// / registered channel. Does not contain the authorization signature.
pub struct WithdrawalRequest {
    /// The funds to be withdrawn.
    pub funding: Funding,
    pub amount: Amount,
    pub participant: L2Account,
    pub time: Timestamp,

    /// The layer-1 identity to send the funds to.
    pub receiver: L1Account,
}

impl<'de> Deserialize<'de> for ChannelId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        require!(
            bytes.len() == 32,
            D::Error::invalid_length(bytes.len(), &"32-byte ChannelId")
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(ChannelId(arr))
    }
}

impl<'de> Deserialize<'de> for Nonce {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        require!(
            bytes.len() == 32,
            D::Error::invalid_length(bytes.len(), &"32-byte Nonce")
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(Nonce(arr))
    }
}

impl CandidType for Hash {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(
            Type::from(TypeInner::Nat8), // Inner type: nat8
        ))
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(&*self.0)
    }
}

impl std::fmt::Display for Hash {
    /// Formats the first 4 byte of a hash as lower case hex with 0x prefix.
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let data = &self.0[..4];
        write!(f, "0x{}…", hex::encode(data))
    }
}

impl std::hash::Hash for Hash {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.as_slice().hash(state);
    }
}

impl Hash {
    pub fn digest(msg: &[u8]) -> Self {
        let mut h = Hasher::default();
        h.update(msg);
        let mut out: Hash = Hash::default();
        h.finalize_into_dirty(&mut out.0);
        out
    }
}

// L2Account

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

impl CandidType for Nonce {
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

impl Default for ChannelId {
    fn default() -> Self {
        ChannelId([0; 32])
    }
}

impl Default for L2Account {
    fn default() -> Self {
        // Create a zero-initialized public key (use with caution!)
        let zero_pk =
            SecpPublicKey::from_slice(&[0u8; 33]).expect("Hardcoded valid zero public key");
        L2Account(zero_pk)
    }
}

impl Default for Nonce {
    fn default() -> Self {
        Nonce([0; 32])
    }
}

impl Clone for ChannelId {
    fn clone(&self) -> Self {
        ChannelId(self.0.clone())
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        Nonce(self.0.clone())
    }
}

impl State {
    pub fn total(&self) -> Amount {
        self.allocation
            .iter()
            .fold(Amount::default(), |x, y| x + y.clone())
    }

    /// Channels that are in their initial state may not yet be fully funded,
    /// but may be registered already for disputes. This is to retrieve funds of
    /// channels where the funding phase does not complete.
    pub fn may_be_underfunded(&self) -> bool {
        self.version == 0 && !self.finalized
    }
}

impl Params {
    pub fn id(&self) -> ChannelId {
        let mut params_bytes = Vec::new();
        params_bytes.extend_from_slice(&self.nonce.0);

        for participant in &self.participants {
            params_bytes.extend_from_slice(&participant.0.serialize()); //.to_bytes());
        }

        let challenge_duration_bytes = self.challenge_duration.to_le_bytes();
        params_bytes.extend_from_slice(&challenge_duration_bytes);

        let hash = Hash::digest(&params_bytes);
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&hash.0[..32]); // Take only first 32 bytes
        ChannelId(arr)
    }
}

// RegisteredState

impl RegisteredState {
    pub fn settled(&self, now: Timestamp) -> bool {
        self.state.finalized || now >= self.timeout
    }
}

// Funding

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
        data.extend_from_slice(&self.participant.0.serialize()); //.to_bytes());

        let h = Hash::digest(&data);
        let arr: [u8; 8] = [
            h.0[0], h.0[1], h.0[2], h.0[3], h.0[4], h.0[5], h.0[6], h.0[7],
        ];
        u64::from_le_bytes(arr)
    }
}

pub fn to_nanoseconds(seconds: u64) -> u64 {
    seconds * 1_000_000_000
}
