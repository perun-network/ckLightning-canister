// =============================================================================
// BOLT-3 Key Derivation Functions
//
// Pure functions for deriving per-commitment secrets and channel keys
// as specified in BOLT-3 (Lightning Network Transactions).
// =============================================================================

use bitcoin::hashes::{sha256, Hash, HashEngine};
use bitcoin::secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey};

/// Derive a per-commitment secret from the commitment_seed using the
/// BOLT-3 48-bit tree traversal algorithm.
///
/// Each commitment has a unique index (counting down from 2^48 - 1).
/// The secret for index `idx` is derived by selectively XORing bits
/// and hashing, starting from the commitment_seed.
pub fn derive_per_commitment_secret(commitment_seed: &[u8; 32], idx: u64) -> [u8; 32] {
    let mut res = *commitment_seed;
    for i in 0..48 {
        let bitpos = 47 - i;
        if idx & (1 << bitpos) == (1 << bitpos) {
            res[bitpos / 8] ^= 1 << (bitpos & 7);
            res = sha256::Hash::hash(&res).to_byte_array();
        }
    }
    res
}

/// Derive a private key from a base secret and per-commitment point.
///
/// BOLT-3 formula:
///   derived_key = base_secret + SHA256(per_commitment_point || basepoint)
///
/// This is used to derive the HTLC key, delayed payment key, etc.
pub fn derive_private_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    per_commitment_point: &PublicKey,
    base_secret: &SecretKey,
) -> Result<SecretKey, String> {
    // Compute the basepoint from the secret
    let basepoint = base_secret.public_key(secp);

    // SHA256(per_commitment_point || basepoint)
    let mut engine = sha256::Hash::engine();
    engine.input(&per_commitment_point.serialize());
    engine.input(&basepoint.serialize());
    let tweak_bytes = sha256::Hash::from_engine(engine).to_byte_array();

    let tweak = Scalar::from_be_bytes(tweak_bytes)
        .map_err(|e| format!("Invalid scalar from SHA256: {e:?}"))?;

    // derived_key = base_secret + tweak
    base_secret
        .add_tweak(&tweak)
        .map_err(|e| format!("Failed to add tweak: {e:?}"))
}

/// Derive a private revocation key from the per-commitment secret and
/// the revocation base secret.
///
/// BOLT-3 formula:
///   revocation_key = per_commitment_secret * SHA256(revocation_basepoint || per_commitment_point)
///                  + revocation_base_secret * SHA256(per_commitment_point || revocation_basepoint)
///
/// This is used to sign justice/penalty transactions.
pub fn derive_private_revocation_key(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    per_commitment_secret: &SecretKey,
    revocation_base_secret: &SecretKey,
) -> Result<SecretKey, String> {
    let per_commitment_point = per_commitment_secret.public_key(secp);
    let revocation_basepoint = revocation_base_secret.public_key(secp);

    // SHA256(revocation_basepoint || per_commitment_point)
    let mut engine1 = sha256::Hash::engine();
    engine1.input(&revocation_basepoint.serialize());
    engine1.input(&per_commitment_point.serialize());
    let factor_a_bytes = sha256::Hash::from_engine(engine1).to_byte_array();

    // SHA256(per_commitment_point || revocation_basepoint)
    let mut engine2 = sha256::Hash::engine();
    engine2.input(&per_commitment_point.serialize());
    engine2.input(&revocation_basepoint.serialize());
    let factor_b_bytes = sha256::Hash::from_engine(engine2).to_byte_array();

    let factor_a = Scalar::from_be_bytes(factor_a_bytes)
        .map_err(|e| format!("Invalid scalar A: {e:?}"))?;
    let factor_b = Scalar::from_be_bytes(factor_b_bytes)
        .map_err(|e| format!("Invalid scalar B: {e:?}"))?;

    // part_a = per_commitment_secret * factor_a
    let part_a = per_commitment_secret
        .mul_tweak(&factor_a)
        .map_err(|e| format!("Failed mul_tweak A: {e:?}"))?;

    // part_b = revocation_base_secret * factor_b
    let part_b = revocation_base_secret
        .mul_tweak(&factor_b)
        .map_err(|e| format!("Failed mul_tweak B: {e:?}"))?;

    // revocation_key = part_a + part_b
    // SecretKey doesn't have direct add, so we use add_tweak with part_b's bytes
    let part_b_scalar = Scalar::from_be_bytes(part_b.secret_bytes())
        .map_err(|e| format!("Invalid scalar from part_b: {e:?}"))?;

    part_a
        .add_tweak(&part_b_scalar)
        .map_err(|e| format!("Failed to combine revocation key parts: {e:?}"))
}

/// Compute the BOLT-3 commitment number obscuring factor from both sides'
/// payment basepoints and the channel direction.
///
/// Per BOLT-3: `SHA256(opener_payment_basepoint || accepter_payment_basepoint)`
/// The last 6 bytes of the hash form the obscuring factor.
pub fn compute_obscure_factor(
    our_payment_basepoint: &PublicKey,
    counterparty_payment_basepoint: &PublicKey,
    is_outbound: bool,
) -> u64 {
    let mut engine = sha256::Hash::engine();
    if is_outbound {
        engine.input(&our_payment_basepoint.serialize());
        engine.input(&counterparty_payment_basepoint.serialize());
    } else {
        engine.input(&counterparty_payment_basepoint.serialize());
        engine.input(&our_payment_basepoint.serialize());
    }
    let res = sha256::Hash::from_engine(engine);
    let bytes: &[u8] = res.as_ref();
    ((bytes[26] as u64) << 40)
        | ((bytes[27] as u64) << 32)
        | ((bytes[28] as u64) << 24)
        | ((bytes[29] as u64) << 16)
        | ((bytes[30] as u64) << 8)
        | (bytes[31] as u64)
}

/// Extract the forward-counting commitment number from a commitment transaction.
///
/// Per BOLT-3, the obscured commitment number is encoded in:
/// - `lock_time` field: bits 0-23 of the obscured commitment number
/// - `sequence` field of input 0: bits 24-47 of the obscured commitment number
///
/// On the wire, `obscured = obscure_factor XOR commitment_number`, where
/// `commitment_number` counts forward (state 0 → 0, state N → N).
/// To recover: `commitment_number = obscured XOR obscure_factor`.
///
/// Note: LDK's internal API exposes a "backwards-counting commitment number"
/// (state 0 → INITIAL_COMMITMENT_NUMBER = 2^48 - 1, state N → INITIAL - N) and
/// encodes via `factor XOR (INITIAL - backwards_number)`. The two formulations
/// are equivalent on the wire; this function returns the forward form so that
/// downstream monotonicity checks ("newer commitments have larger numbers")
/// read naturally.
pub fn extract_commitment_number(
    tx: &bitcoin::Transaction,
    obscure_factor: u64,
) -> Result<u64, String> {
    if tx.input.is_empty() {
        return Err("Transaction has no inputs".into());
    }
    let lock_time_bits = (tx.lock_time.to_consensus_u32() & 0x00FFFFFF) as u64;
    let sequence_bits = (tx.input[0].sequence.0 & 0x00FFFFFF) as u64;
    let obscured = lock_time_bits | (sequence_bits << 24);
    Ok(obscured ^ obscure_factor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_per_commitment_secret_deterministic() {
        let seed = [42u8; 32];
        let secret1 = derive_per_commitment_secret(&seed, 0);
        let secret2 = derive_per_commitment_secret(&seed, 0);
        assert_eq!(secret1, secret2, "Same seed+idx must produce same secret");
    }

    #[test]
    fn test_per_commitment_secret_different_indices() {
        let seed = [42u8; 32];
        let secret0 = derive_per_commitment_secret(&seed, 0);
        let secret1 = derive_per_commitment_secret(&seed, 1);
        assert_ne!(secret0, secret1, "Different indices must produce different secrets");
    }

    #[test]
    fn test_derive_private_key_produces_valid_key() {
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
        let per_commitment_secret = SecretKey::from_slice(&[2u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);

        let derived = derive_private_key(&secp, &per_commitment_point, &base_secret);
        assert!(derived.is_ok(), "Key derivation should succeed");
    }

    #[test]
    fn test_derive_revocation_key_produces_valid_key() {
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let revocation_base_secret = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let revocation_key = derive_private_revocation_key(
            &secp,
            &per_commitment_secret,
            &revocation_base_secret,
        );
        assert!(revocation_key.is_ok(), "Revocation key derivation should succeed");
    }

    #[test]
    fn test_per_commitment_secret_different_seeds() {
        let seed_a = [10u8; 32];
        let seed_b = [20u8; 32];
        let secret_a = derive_per_commitment_secret(&seed_a, 5);
        let secret_b = derive_per_commitment_secret(&seed_b, 5);
        assert_ne!(secret_a, secret_b, "Different seeds at same index must produce different secrets");
    }

    #[test]
    fn test_per_commitment_secret_max_index() {
        let seed = [42u8; 32];
        let max_idx = (1u64 << 48) - 1;
        let secret = derive_per_commitment_secret(&seed, max_idx);
        // Must be a valid 32-byte secret (non-zero)
        assert_ne!(secret, [0u8; 32], "Max index secret must not be all zeros");
        // Must be deterministic
        let secret2 = derive_per_commitment_secret(&seed, max_idx);
        assert_eq!(secret, secret2);
    }

    #[test]
    fn test_per_commitment_secret_sequential_unique() {
        let seed = [42u8; 32];
        let mut seen = std::collections::HashSet::new();
        for idx in 0..100u64 {
            let secret = derive_per_commitment_secret(&seed, idx);
            assert!(seen.insert(secret), "Index {idx} produced a duplicate secret");
        }
    }

    #[test]
    fn test_derive_private_key_deterministic() {
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let per_commitment_secret = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);

        let key1 = derive_private_key(&secp, &per_commitment_point, &base_secret).unwrap();
        let key2 = derive_private_key(&secp, &per_commitment_point, &base_secret).unwrap();
        assert_eq!(key1, key2, "Same inputs must produce same derived key");
    }

    #[test]
    fn test_derive_private_key_different_bases() {
        let secp = Secp256k1::new();
        let base_a = SecretKey::from_slice(&[5u8; 32]).unwrap();
        let base_b = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let per_commitment_secret = SecretKey::from_slice(&[6u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);

        let key_a = derive_private_key(&secp, &per_commitment_point, &base_a).unwrap();
        let key_b = derive_private_key(&secp, &per_commitment_point, &base_b).unwrap();
        assert_ne!(key_a, key_b, "Different base secrets must produce different derived keys");
    }

    #[test]
    fn test_derive_private_key_pubkey_matches() {
        // Verify: derived_key.public_key() matches the BOLT-3 public key formula:
        // derived_pubkey = basepoint + SHA256(per_commitment_point || basepoint) * G
        let secp = Secp256k1::new();
        let base_secret = SecretKey::from_slice(&[8u8; 32]).unwrap();
        let per_commitment_secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
        let per_commitment_point = per_commitment_secret.public_key(&secp);
        let basepoint = base_secret.public_key(&secp);

        // Derive private key and get its public key
        let derived_key = derive_private_key(&secp, &per_commitment_point, &base_secret).unwrap();
        let derived_pubkey = derived_key.public_key(&secp);

        // Compute expected public key via the BOLT-3 public formula
        let mut engine = sha256::Hash::engine();
        engine.input(&per_commitment_point.serialize());
        engine.input(&basepoint.serialize());
        let tweak_bytes = sha256::Hash::from_engine(engine).to_byte_array();
        let tweak_scalar = Scalar::from_be_bytes(tweak_bytes).unwrap();

        // expected = basepoint + tweak * G
        // In secp256k1: PublicKey::add_exp_tweak is basepoint + scalar*G
        let expected_pubkey = basepoint.add_exp_tweak(&secp, &tweak_scalar).unwrap();

        assert_eq!(derived_pubkey, expected_pubkey,
            "Derived private key's pubkey must match BOLT-3 public derivation formula");
    }

    #[test]
    fn test_derive_revocation_key_deterministic() {
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let revocation_base_secret = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let key1 = derive_private_revocation_key(&secp, &per_commitment_secret, &revocation_base_secret).unwrap();
        let key2 = derive_private_revocation_key(&secp, &per_commitment_secret, &revocation_base_secret).unwrap();
        assert_eq!(key1, key2, "Same inputs must produce same revocation key");
    }

    #[test]
    fn test_derive_revocation_key_pubkey_matches() {
        // Verify: derived revocation pubkey matches BOLT-3 public formula:
        // revocation_pubkey = per_commitment_point * SHA256(rev_basepoint || per_commitment_point)
        //                   + rev_basepoint * SHA256(per_commitment_point || rev_basepoint)
        let secp = Secp256k1::new();
        let per_commitment_secret = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let revocation_base_secret = SecretKey::from_slice(&[4u8; 32]).unwrap();

        let per_commitment_point = per_commitment_secret.public_key(&secp);
        let revocation_basepoint = revocation_base_secret.public_key(&secp);

        // Derive private revocation key and get its pubkey
        let rev_key = derive_private_revocation_key(
            &secp, &per_commitment_secret, &revocation_base_secret,
        ).unwrap();
        let rev_pubkey = rev_key.public_key(&secp);

        // Compute expected pubkey via the BOLT-3 public formula
        // factor_a = SHA256(revocation_basepoint || per_commitment_point)
        let mut engine1 = sha256::Hash::engine();
        engine1.input(&revocation_basepoint.serialize());
        engine1.input(&per_commitment_point.serialize());
        let factor_a = Scalar::from_be_bytes(sha256::Hash::from_engine(engine1).to_byte_array()).unwrap();

        // factor_b = SHA256(per_commitment_point || revocation_basepoint)
        let mut engine2 = sha256::Hash::engine();
        engine2.input(&per_commitment_point.serialize());
        engine2.input(&revocation_basepoint.serialize());
        let factor_b = Scalar::from_be_bytes(sha256::Hash::from_engine(engine2).to_byte_array()).unwrap();

        // part_a = per_commitment_point * factor_a
        let part_a = per_commitment_point.mul_tweak(&secp, &factor_a).unwrap();
        // part_b = revocation_basepoint * factor_b
        let part_b = revocation_basepoint.mul_tweak(&secp, &factor_b).unwrap();

        // expected = part_a + part_b
        let expected_pubkey = part_a.combine(&part_b).unwrap();

        assert_eq!(rev_pubkey, expected_pubkey,
            "Derived revocation private key's pubkey must match BOLT-3 public revocation formula");
    }

    /// Build a minimal commitment-style transaction whose locktime+sequence
    /// encode the given obscured number per BOLT-3 (LDK 0.1.x convention:
    /// locktime high byte 0x20, sequence high byte 0x80).
    fn make_obscured_tx(obscured: u64) -> bitcoin::Transaction {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
        let lock_time = LockTime::from_consensus(((0x20u32) << 24) | ((obscured & 0x00FFFFFF) as u32));
        let sequence = Sequence(((0x80u32) << 24) | ((obscured >> 24) as u32));
        Transaction {
            version: Version::TWO,
            lock_time,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new() }],
        }
    }

    #[test]
    fn test_extract_commitment_number_state_zero() {
        let factor: u64 = 0x123456789ABC;
        let tx = make_obscured_tx(factor ^ 0);
        assert_eq!(extract_commitment_number(&tx, factor).unwrap(), 0);
    }

    #[test]
    fn test_extract_commitment_number_small_states() {
        let factor: u64 = 0x0F0E0D0C0B0A;
        for state in [1u64, 2, 3, 7, 100, 1_000_000] {
            let tx = make_obscured_tx(factor ^ state);
            let got = extract_commitment_number(&tx, factor).unwrap();
            assert_eq!(got, state, "state {state} must round-trip");
        }
    }

    #[test]
    fn test_extract_commitment_number_zero_factor() {
        // Degenerate factor=0: extracted equals the obscured value directly.
        let factor: u64 = 0;
        for state in [0u64, 1, 5, 42] {
            let tx = make_obscured_tx(state);
            assert_eq!(extract_commitment_number(&tx, factor).unwrap(), state);
        }
    }

    #[test]
    fn test_extract_commitment_number_high_state() {
        // A state number that occupies all 48 bits of the obscured field.
        let factor: u64 = 0xAABBCCDDEEFF;
        let state: u64 = (1u64 << 48) - 1;
        let tx = make_obscured_tx(factor ^ state);
        assert_eq!(extract_commitment_number(&tx, factor).unwrap(), state);
    }

    #[test]
    fn test_extract_commitment_number_empty_inputs_errs() {
        use bitcoin::{absolute::LockTime, transaction::Version, Amount, ScriptBuf, Transaction, TxOut};
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![],
            output: vec![TxOut { value: Amount::from_sat(0), script_pubkey: ScriptBuf::new() }],
        };
        assert!(extract_commitment_number(&tx, 0).is_err());
    }
}
