use crate::require;
use digest::{FixedOutputReset, Update};
use sha2::Sha512 as Hasher;
use k256::EncodedPoint;
use k256::PublicKey as SecpPublicKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;

use candid::CandidType;
pub use candid::{
    Deserialize, Int, Nat,
    types::{Serializer, Type},
    types::{TypeInner, TypeInner::Nat8},
};

use serde::de::{Deserializer, Error as _};
use serde_bytes::ByteBuf;


// =============================================================================
// Core Primitives
// =============================================================================

/// A hash as used by the signature scheme.
#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Default, Clone)]
pub struct Hash(pub digest::Output<Hasher>);

#[derive(PartialEq, Debug, Clone, Eq)]
pub struct L2Account(pub SecpPublicKey);

#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Clone, Deserialize, CandidType, Debug)]
pub struct L1Account(pub candid::Principal);

/// Duration in nanoseconds (same as ICP timestamps).
pub type Duration = u64;
/// Timestamp in nanoseconds (same as ICP timestamps).
pub type Timestamp = u64;

/// Unique channel identifier.
#[derive(PartialEq, Eq, Ord, PartialOrd, Hash, Debug)]
pub struct ChannelId(pub [u8; 32]);

/// A channel's unique nonce.
#[derive(PartialEq, Eq, Ord, PartialOrd)]
pub struct Nonce(pub [u8; 32]);

/// Channel state version identifier.
pub type Version = u64;

// =============================================================================
// Impl blocks
// =============================================================================

impl Clone for ChannelId {
    fn clone(&self) -> Self {
        ChannelId(self.0.clone())
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
        require!(
            bytes.len() == 32,
            D::Error::invalid_length(bytes.len(), &"32-byte ChannelId")
        );
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        Ok(ChannelId(arr))
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

impl Default for Nonce {
    fn default() -> Self {
        Nonce([0; 32])
    }
}

impl Clone for Nonce {
    fn clone(&self) -> Self {
        Nonce(self.0.clone())
    }
}

impl CandidType for Hash {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
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
        h.finalize_into_reset(&mut out.0);
        out
    }
}

impl std::hash::Hash for L2Account {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let encoded_point: EncodedPoint = self.0.to_encoded_point(false); // false for uncompressed
        encoded_point.as_bytes().hash(state);
    }
}

impl<'de> Deserialize<'de> for L2Account {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = ByteBuf::deserialize(deserializer)?;
        let pk = SecpPublicKey::from_sec1_bytes(bytes.as_slice()).map_err(|_| {
            D::Error::invalid_length(bytes.len(), &"valid secp256k1 public key bytes")
        })?;
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
        let encoded = self.0.to_encoded_point(false); // false for uncompressed
        serializer.serialize_blob(encoded.as_bytes())
    }
}

impl Default for L2Account {
    fn default() -> Self {
        // 33-byte compressed public key of all zeros
        let zero_pk_bytes = [0u8; 33];
        let zero_pk = SecpPublicKey::from_sec1_bytes(&zero_pk_bytes)
            .expect("Hardcoded valid zero public key");
        L2Account(zero_pk)
    }
}
