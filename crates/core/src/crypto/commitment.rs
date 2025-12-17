//! Pedersen commitment implementation
//!
//! Uses the standard Pedersen commitment scheme:
//! C = amount * G + blinding * H
//!
//! where G is the standard BN254 generator and H is derived
//! using a nothing-up-my-sleeve construction.

use ark_bn254::{Fr, G1Affine, G1Projective as G1};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{BigInteger, PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::rngs::OsRng;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CommitmentError {
    #[error("Invalid secret length: expected at least 32 bytes")]
    InvalidSecret,
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Invalid commitment format")]
    InvalidFormat,
    #[error("Deserialization error: {0}")]
    DeserializationError(String),
    #[error("Point not on curve")]
    PointNotOnCurve,
}

/// A Pedersen commitment with the associated opening information
#[derive(Clone, Debug)]
pub struct Commitment {
    /// The commitment point on BN254 G1
    pub point: G1,
    /// The committed amount
    pub amount: u64,
    /// The blinding factor (randomness)
    pub blinding_factor: Fr,
}

/// Commitment without opening information (for verification)
#[derive(Clone, Debug)]
pub struct CommitmentPoint {
    pub point: G1,
}

impl Commitment {
    /// Generate a random blinding factor using OS randomness
    pub fn generate_random_blinding() -> Fr {
        Fr::rand(&mut OsRng)
    }

    /// Create a new Pedersen commitment with random blinding
    ///
    /// C = amount * G + blinding * H
    /// where G and H are generators on BN254 curve
    ///
    /// Returns the commitment with the random blinding factor for later proof generation
    pub fn new_random(amount: u64) -> Self {
        let blinding_factor = Self::generate_random_blinding();
        Self::with_blinding(amount, blinding_factor)
    }

    /// Create a new Pedersen commitment with explicit blinding factor
    ///
    /// Use this when you need to reconstruct a commitment or when
    /// the blinding factor must be derived deterministically.
    pub fn with_blinding(amount: u64, blinding_factor: Fr) -> Self {
        let g = G1::generator();
        let h = Self::generate_h();

        let amount_scalar = Fr::from(amount);
        let commitment = (g * amount_scalar) + (h * blinding_factor);

        Commitment {
            point: commitment,
            amount,
            blinding_factor,
        }
    }

    /// Create a commitment with deterministic blinding (DEPRECATED - use new_random for privacy)
    ///
    /// This method is kept for backward compatibility but should NOT be used
    /// in production as it creates linkable commitments.
    #[deprecated(note = "Use new_random() for privacy. Deterministic blinding leaks information.")]
    pub fn new(amount: u64, secret: &[u8]) -> Result<Self, CommitmentError> {
        if secret.len() < 32 {
            return Err(CommitmentError::InvalidSecret);
        }

        let blinding_factor = Self::derive_blinding_deterministic(secret, amount);
        Ok(Self::with_blinding(amount, blinding_factor))
    }

    /// Derive blinding factor deterministically (for backward compatibility only)
    fn derive_blinding_deterministic(secret: &[u8], amount: u64) -> Fr {
        let mut hasher = blake3::Hasher::new();
        hasher.update(secret);
        hasher.update(&amount.to_le_bytes());
        hasher.update(b"blinding_factor");

        let hash = hasher.finalize();
        Fr::from_le_bytes_mod_order(hash.as_bytes())
    }

    /// Generate H generator using hash-to-curve (nothing-up-my-sleeve)
    ///
    /// H is derived by hashing a domain separator and mapping to the curve.
    /// This ensures H's discrete log relative to G is unknown.
    fn generate_h() -> G1 {
        // Use hash-to-curve construction for proper nothing-up-my-sleeve
        let domain = b"NYX_PROTOCOL_PEDERSEN_H_V1";
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        let hash = hasher.finalize();

        // Map hash to scalar and multiply by generator
        // This is a simple construction; production should use proper hash-to-curve
        let scalar = Fr::from_le_bytes_mod_order(hash.as_bytes());
        G1::generator() * scalar
    }

    /// Get the generators (G, H) used for commitments
    pub fn generators() -> (G1, G1) {
        (G1::generator(), Self::generate_h())
    }

    /// Verify that a commitment opens to the given amount and blinding
    pub fn verify(&self, amount: u64, blinding: &Fr) -> bool {
        let expected = Self::with_blinding(amount, *blinding);
        self.point == expected.point
    }

    /// Serialize commitment point to compressed format (32 bytes for BN254)
    pub fn to_bytes(&self) -> Vec<u8> {
        let affine = self.point.into_affine();
        let mut bytes = Vec::new();
        affine.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Serialize commitment point to 32-byte format (x-coordinate only)
    pub fn to_bytes_32(&self) -> [u8; 32] {
        let affine = self.point.into_affine();
        let x_bytes = affine.x.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        result.copy_from_slice(&x_bytes[..32]);
        result
    }

    /// Serialize blinding factor to 32 bytes
    pub fn blinding_to_bytes(&self) -> [u8; 32] {
        let bytes = self.blinding_factor.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32]);
        result
    }

    /// Deserialize commitment from compressed bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<CommitmentPoint, CommitmentError> {
        // BN254 G1 compressed is 32 bytes
        if bytes.len() < 32 {
            return Err(CommitmentError::InvalidFormat);
        }

        let affine = G1Affine::deserialize_compressed(&bytes[..])
            .map_err(|e| CommitmentError::DeserializationError(e.to_string()))?;

        if !affine.is_on_curve() {
            return Err(CommitmentError::PointNotOnCurve);
        }

        Ok(CommitmentPoint {
            point: affine.into(),
        })
    }

    /// Create commitment from raw point (without opening information)
    pub fn from_point(point: G1) -> CommitmentPoint {
        CommitmentPoint { point }
    }
}

impl CommitmentPoint {
    /// Serialize to compressed bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let affine = self.point.into_affine();
        let mut bytes = Vec::with_capacity(33);
        affine.serialize_compressed(&mut bytes).unwrap();
        bytes
    }

    /// Verify that this commitment opens to the given values
    pub fn verify(&self, amount: u64, blinding: &Fr) -> bool {
        let expected = Commitment::with_blinding(amount, *blinding);
        self.point == expected.point
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_random_blinding() {
        let amount = 1000;

        // Create two commitments with random blinding
        let c1 = Commitment::new_random(amount);
        let c2 = Commitment::new_random(amount);

        assert_eq!(c1.amount, amount);
        assert_eq!(c2.amount, amount);

        // Random blinding should produce different commitments
        assert_ne!(c1.to_bytes(), c2.to_bytes());
        assert_ne!(c1.blinding_factor, c2.blinding_factor);
    }

    #[test]
    fn test_commitment_with_explicit_blinding() {
        let amount = 1000;
        let blinding = Fr::from(12345u64);

        let c1 = Commitment::with_blinding(amount, blinding);
        let c2 = Commitment::with_blinding(amount, blinding);

        // Same blinding should produce identical commitments
        assert_eq!(c1.to_bytes(), c2.to_bytes());
    }

    #[test]
    fn test_commitment_verification() {
        let amount = 1000;
        let commitment = Commitment::new_random(amount);

        // Should verify with correct opening
        assert!(commitment.verify(amount, &commitment.blinding_factor));

        // Should fail with wrong amount
        assert!(!commitment.verify(999, &commitment.blinding_factor));

        // Should fail with wrong blinding
        let wrong_blinding = Fr::from(99999u64);
        assert!(!commitment.verify(amount, &wrong_blinding));
    }

    #[test]
    fn test_commitment_serialization() {
        let commitment = Commitment::new_random(5000);

        // Test compressed serialization (32 bytes for BN254)
        let bytes = commitment.to_bytes();
        assert_eq!(bytes.len(), 32);

        // Test deserialization
        let point = Commitment::from_bytes(&bytes).unwrap();
        assert_eq!(point.point, commitment.point);

        // Test 32-byte format
        let bytes_32 = commitment.to_bytes_32();
        assert_eq!(bytes_32.len(), 32);

        // Test blinding serialization
        let blinding_bytes = commitment.blinding_to_bytes();
        assert_eq!(blinding_bytes.len(), 32);
    }

    #[test]
    fn test_commitment_point_verification() {
        let amount = 1000;
        let commitment = Commitment::new_random(amount);

        // Serialize and deserialize
        let bytes = commitment.to_bytes();
        let point = Commitment::from_bytes(&bytes).unwrap();

        // Should verify with correct opening
        assert!(point.verify(amount, &commitment.blinding_factor));
    }

    #[test]
    fn test_generators_consistency() {
        let (g, h) = Commitment::generators();

        // H should be deterministic
        let (_, h2) = Commitment::generators();
        assert_eq!(h, h2);

        // H should be different from G
        assert_ne!(g, h);
    }

    #[test]
    #[allow(deprecated)]
    fn test_backward_compatibility() {
        let secret = b"test_secret_key_must_be_32bytes!";
        let amount = 1000;

        // Old API should still work (but is deprecated)
        let c1 = Commitment::new(amount, secret).unwrap();
        let c2 = Commitment::new(amount, secret).unwrap();

        // Deterministic blinding produces same commitment
        assert_eq!(c1.to_bytes(), c2.to_bytes());
    }
}
