//! Nullifier generation for double-spend prevention
//!
//! The nullifier is derived using a circuit-safe approach:
//! 1. spending_key = Poseidon(secret, domain_separator)
//! 2. nullifier = Poseidon(spending_key, leaf_index)
//!
//! This ensures:
//! - The secret is never directly exposed in the nullifier computation
//! - The nullifier is deterministic for a given (secret, leaf_index) pair
//! - Each commitment has a unique nullifier tied to its Merkle tree position
//!
//! Security properties:
//! - Given a nullifier, an attacker cannot recover the secret
//! - Given a spending_key, an attacker cannot recover the secret
//! - Different leaf indices produce different nullifiers (even for same secret)

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

use super::poseidon::poseidon_hash2;

/// Domain separator for spending key derivation
const SPENDING_KEY_DOMAIN: &[u8] = b"NYX_SPENDING_KEY";
/// Domain separator for nullifier derivation
const NULLIFIER_DOMAIN: &[u8] = b"NYX_NULLIFIER";

#[derive(Error, Debug)]
pub enum NullifierError {
    #[error("Invalid secret length: expected 32 bytes")]
    InvalidSecretLength,
    #[error("Invalid spending key format")]
    InvalidSpendingKey,
    #[error("Computation error")]
    ComputationError,
}

/// Spending key derived from a secret
///
/// The spending key is derived using Poseidon hash and can be safely
/// used in circuits without exposing the underlying secret.
#[derive(Clone, Debug)]
pub struct SpendingKey {
    key: Fr,
}

impl SpendingKey {
    /// Derive spending key from a 32-byte secret
    pub fn from_secret(secret: &[u8; 32]) -> Self {
        let secret_fr = Fr::from_le_bytes_mod_order(secret);
        let domain_fr = Fr::from_le_bytes_mod_order(SPENDING_KEY_DOMAIN);

        let key = poseidon_hash2(&secret_fr, &domain_fr);

        Self { key }
    }

    /// Create from an existing field element
    pub fn from_field(key: Fr) -> Self {
        Self { key }
    }

    /// Get the underlying field element
    pub fn as_field(&self) -> &Fr {
        &self.key
    }

    /// Serialize to 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.key.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32]);
        result
    }

    /// Deserialize from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let key = Fr::from_le_bytes_mod_order(bytes);
        Self { key }
    }
}

/// A nullifier that can be used to prevent double-spending
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Nullifier {
    value: Fr,
}

impl Nullifier {
    /// Derive nullifier from spending key and leaf index
    ///
    /// nullifier = Poseidon(spending_key, leaf_index || domain)
    pub fn derive(spending_key: &SpendingKey, leaf_index: u64) -> Self {
        // Combine leaf index with domain separator
        let index_with_domain = {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&leaf_index.to_le_bytes());
            hasher.update(NULLIFIER_DOMAIN);
            let hash = hasher.finalize();
            Fr::from_le_bytes_mod_order(hash.as_bytes())
        };

        let value = poseidon_hash2(&spending_key.key, &index_with_domain);

        Self { value }
    }

    /// Derive nullifier directly from secret and leaf index
    ///
    /// This is a convenience method that:
    /// 1. Derives the spending key from the secret
    /// 2. Derives the nullifier from the spending key and leaf index
    pub fn from_secret(secret: &[u8; 32], leaf_index: u64) -> Self {
        let spending_key = SpendingKey::from_secret(secret);
        Self::derive(&spending_key, leaf_index)
    }

    /// Get the underlying field element
    pub fn as_field(&self) -> &Fr {
        &self.value
    }

    /// Serialize to 32 bytes
    pub fn to_bytes(&self) -> [u8; 32] {
        let bytes = self.value.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32]);
        result
    }

    /// Deserialize from 32 bytes
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let value = Fr::from_le_bytes_mod_order(bytes);
        Self { value }
    }

    /// Create from an existing field element
    pub fn from_field(value: Fr) -> Self {
        Self { value }
    }
}

/// Note: a complete representation of a shielded note
///
/// Contains all the information needed to spend a note:
/// - The secret (for deriving spending key and nullifier)
/// - The blinding factor (for reconstructing the commitment)
/// - The amount
/// - The leaf index (for Merkle proofs and nullifier derivation)
#[derive(Clone, Debug)]
pub struct Note {
    /// The secret used to derive the spending key
    pub secret: [u8; 32],
    /// The blinding factor for the commitment
    pub blinding: Fr,
    /// The committed amount
    pub amount: u64,
    /// The asset identifier (0 for native SOL)
    pub asset_id: Fr,
    /// The leaf index in the Merkle tree (set after insertion)
    pub leaf_index: Option<u64>,
}

impl Note {
    /// Create a new note with random secret
    pub fn new_random(amount: u64, asset_id: Fr, blinding: Fr) -> Self {
        use rand::RngCore;
        let mut secret = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut secret);

        Self {
            secret,
            blinding,
            amount,
            asset_id,
            leaf_index: None,
        }
    }

    /// Create a note with explicit secret
    pub fn new(secret: [u8; 32], amount: u64, asset_id: Fr, blinding: Fr) -> Self {
        Self {
            secret,
            blinding,
            amount,
            asset_id,
            leaf_index: None,
        }
    }

    /// Set the leaf index after the note is inserted into the tree
    pub fn set_leaf_index(&mut self, index: u64) {
        self.leaf_index = Some(index);
    }

    /// Get the spending key for this note
    pub fn spending_key(&self) -> SpendingKey {
        SpendingKey::from_secret(&self.secret)
    }

    /// Get the nullifier for this note
    ///
    /// Panics if leaf_index is not set
    pub fn nullifier(&self) -> Nullifier {
        let leaf_index = self.leaf_index
            .expect("Cannot compute nullifier without leaf_index");
        Nullifier::from_secret(&self.secret, leaf_index)
    }

    /// Compute the note commitment using Poseidon
    ///
    /// commitment = Poseidon(spending_key, amount, blinding, asset_id)
    pub fn commitment(&self) -> Fr {
        let spending_key = self.spending_key();

        // Hash the note components
        // Using multiple hash2 calls to handle 4 inputs
        let amount_fr = Fr::from(self.amount);

        let h1 = poseidon_hash2(spending_key.as_field(), &amount_fr);
        let h2 = poseidon_hash2(&self.blinding, &self.asset_id);
        poseidon_hash2(&h1, &h2)
    }

    /// Serialize note to bytes (for storage)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(32 + 32 + 8 + 32 + 8);
        bytes.extend_from_slice(&self.secret);
        bytes.extend_from_slice(&self.blinding.into_bigint().to_bytes_le()[..32]);
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        bytes.extend_from_slice(&self.asset_id.into_bigint().to_bytes_le()[..32]);
        if let Some(idx) = self.leaf_index {
            bytes.extend_from_slice(&idx.to_le_bytes());
        }
        bytes
    }
}

// ============================================================================
// Legacy API (deprecated)
// ============================================================================

/// Generate nullifier hash (DEPRECATED)
///
/// This legacy function uses Blake3 and exposes the secret directly.
/// Use Nullifier::from_secret() instead for circuit-safe nullifier derivation.
#[deprecated(note = "Use Nullifier::from_secret() for circuit-safe nullifier derivation")]
pub fn generate_nullifier_hash(commitment: &[u8], secret: &[u8]) -> Result<Vec<u8>, NullifierError> {
    if commitment.len() != 32 {
        return Err(NullifierError::InvalidSecretLength);
    }
    if secret.len() < 32 {
        return Err(NullifierError::InvalidSecretLength);
    }

    let mut hasher = blake3::Hasher::new();
    hasher.update(commitment);
    hasher.update(secret);
    hasher.update(b"nullifier");

    Ok(hasher.finalize().as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_spending_key_derivation() {
        let secret = [1u8; 32];

        let sk1 = SpendingKey::from_secret(&secret);
        let sk2 = SpendingKey::from_secret(&secret);

        // Same secret should produce same spending key
        assert_eq!(sk1.to_bytes(), sk2.to_bytes());

        // Different secrets should produce different spending keys
        let secret2 = [2u8; 32];
        let sk3 = SpendingKey::from_secret(&secret2);
        assert_ne!(sk1.to_bytes(), sk3.to_bytes());
    }

    #[test]
    fn test_spending_key_serialization() {
        let secret = [42u8; 32];
        let sk = SpendingKey::from_secret(&secret);

        let bytes = sk.to_bytes();
        let sk2 = SpendingKey::from_bytes(&bytes);

        assert_eq!(sk.to_bytes(), sk2.to_bytes());
    }

    #[test]
    fn test_nullifier_derivation() {
        let secret = [1u8; 32];
        let leaf_index = 42u64;

        let n1 = Nullifier::from_secret(&secret, leaf_index);
        let n2 = Nullifier::from_secret(&secret, leaf_index);

        // Same inputs should produce same nullifier
        assert_eq!(n1.to_bytes(), n2.to_bytes());
    }

    #[test]
    fn test_nullifier_unique_per_leaf() {
        let secret = [1u8; 32];

        let n1 = Nullifier::from_secret(&secret, 0);
        let n2 = Nullifier::from_secret(&secret, 1);

        // Different leaf indices should produce different nullifiers
        assert_ne!(n1.to_bytes(), n2.to_bytes());
    }

    #[test]
    fn test_nullifier_unique_per_secret() {
        let secret1 = [1u8; 32];
        let secret2 = [2u8; 32];
        let leaf_index = 42u64;

        let n1 = Nullifier::from_secret(&secret1, leaf_index);
        let n2 = Nullifier::from_secret(&secret2, leaf_index);

        // Different secrets should produce different nullifiers
        assert_ne!(n1.to_bytes(), n2.to_bytes());
    }

    #[test]
    fn test_nullifier_serialization() {
        let secret = [99u8; 32];
        let nullifier = Nullifier::from_secret(&secret, 100);

        let bytes = nullifier.to_bytes();
        let nullifier2 = Nullifier::from_bytes(&bytes);

        assert_eq!(nullifier.to_bytes(), nullifier2.to_bytes());
    }

    #[test]
    fn test_note_creation() {
        let blinding = Fr::rand(&mut OsRng);
        let asset_id = Fr::from(0u64); // Native SOL
        let amount = 1000u64;

        let note = Note::new_random(amount, asset_id, blinding);

        assert_eq!(note.amount, amount);
        assert!(note.leaf_index.is_none());
    }

    #[test]
    fn test_note_commitment_deterministic() {
        let secret = [1u8; 32];
        let blinding = Fr::from(12345u64);
        let asset_id = Fr::from(0u64);
        let amount = 1000u64;

        let note1 = Note::new(secret, amount, asset_id, blinding);
        let note2 = Note::new(secret, amount, asset_id, blinding);

        assert_eq!(note1.commitment(), note2.commitment());
    }

    #[test]
    fn test_note_nullifier_requires_leaf_index() {
        let blinding = Fr::rand(&mut OsRng);
        let note = Note::new_random(1000, Fr::from(0u64), blinding);

        // Should panic without leaf_index
        let result = std::panic::catch_unwind(|| note.nullifier());
        assert!(result.is_err());
    }

    #[test]
    fn test_note_nullifier_with_leaf_index() {
        let blinding = Fr::rand(&mut OsRng);
        let mut note = Note::new_random(1000, Fr::from(0u64), blinding);
        note.set_leaf_index(42);

        let nullifier = note.nullifier();
        assert_eq!(nullifier.to_bytes().len(), 32);
    }

    #[test]
    fn test_spending_key_hidden() {
        let secret = [1u8; 32];
        let sk = SpendingKey::from_secret(&secret);

        // Spending key should be different from the secret
        // (it's a hash of the secret)
        assert_ne!(sk.to_bytes(), secret);

        // Spending key should not be derivable back to secret
        // (Poseidon is a one-way function)
    }
}
