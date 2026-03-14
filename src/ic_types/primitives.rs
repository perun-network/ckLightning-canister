use digest::{FixedOutputReset, Update};
use sha2::Sha512 as Hasher;

use candid::CandidType;
pub use candid::{
    Deserialize, Int, Nat,
    types::{Serializer, Type},
    types::{TypeInner, TypeInner::Nat8},
};

// =============================================================================
// Core Primitives
// =============================================================================

/// A hash as used by the signature scheme.
#[derive(PartialEq, Debug, Eq, PartialOrd, Ord, Default, Clone)]
pub struct Hash(pub digest::Output<Hasher>);

#[derive(Hash, PartialEq, Eq, Ord, PartialOrd, Clone, Deserialize, CandidType, Debug)]
pub struct L1Account(pub candid::Principal);

/// Timestamp in nanoseconds (same as ICP timestamps).
pub type Timestamp = u64;

// =============================================================================
// Impl blocks
// =============================================================================

impl CandidType for Hash {
    fn _ty() -> Type {
        Type::from(TypeInner::Vec(Type::from(TypeInner::Nat8)))
    }

    fn idl_serialize<S>(&self, serializer: S) -> Result<(), S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_blob(self.0.as_slice())
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
