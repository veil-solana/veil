//! Unified Error Types for Veil
//!
//! This module provides a comprehensive error hierarchy for the SDK.

use thiserror::Error;

/// Top-level error type for the Veil SDK
#[derive(Error, Debug)]
pub enum VeilError {
    /// Cryptographic operation error
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    /// Proof generation/verification error
    #[error("Proof error: {0}")]
    Proof(#[from] ProofError),

    /// Relayer communication error
    #[error("Relayer error: {0}")]
    Relayer(#[from] RelayerError),

    /// Serialization/deserialization error
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Invalid input error
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
}

/// Result type alias for Veil operations
pub type VeilResult<T> = Result<T, VeilError>;

/// Errors from cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Invalid secret key: must be at least 32 bytes")]
    InvalidSecretKey,

    #[error("Invalid public key")]
    InvalidPublicKey,

    #[error("Invalid commitment")]
    InvalidCommitment,

    #[error("Invalid nullifier")]
    InvalidNullifier,

    #[error("Invalid Merkle proof")]
    InvalidMerkleProof,

    #[error("Merkle tree is full")]
    MerkleTreeFull,

    #[error("Poseidon hash error: {0}")]
    PoseidonError(String),

    #[error("Encryption failed: {0}")]
    EncryptionError(String),

    #[error("Decryption failed")]
    DecryptionFailed,
}

/// Errors from proof operations
#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid witness data")]
    InvalidWitness,

    #[error("Circuit constraint not satisfied: {0}")]
    ConstraintNotSatisfied(String),

    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),

    #[error("Proof verification failed")]
    VerificationFailed,

    #[error("Invalid proving key")]
    InvalidProvingKey,

    #[error("Invalid verifying key")]
    InvalidVerifyingKey,

    #[error("Setup failed: {0}")]
    SetupFailed(String),

    #[error("Serialization error: {0}")]
    SerializationError(String),
}

/// Errors from relayer operations
#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("No relayers available")]
    NoRelayersAvailable,

    #[error("Relayer fee too high: {0} bps")]
    FeeTooHigh(u16),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Transaction rejected: {0}")]
    TransactionRejected(String),

    #[error("Timeout waiting for confirmation")]
    Timeout,

    #[error("Invalid response: {0}")]
    InvalidResponse(String),
}

/// Input validation utilities
pub mod validation {
    use super::*;

    /// Validate a secret key (must be at least 32 bytes)
    pub fn validate_secret(secret: &[u8]) -> Result<(), VeilError> {
        if secret.len() < 32 {
            return Err(VeilError::InvalidInput(
                "Secret must be at least 32 bytes".to_string()
            ));
        }

        // Check it's not all zeros
        if secret.iter().all(|&b| b == 0) {
            return Err(VeilError::InvalidInput(
                "Secret cannot be all zeros".to_string()
            ));
        }

        Ok(())
    }

    /// Validate an amount (must be positive and within range)
    pub fn validate_amount(amount: u64) -> Result<(), VeilError> {
        if amount == 0 {
            return Err(VeilError::InvalidInput(
                "Amount must be greater than zero".to_string()
            ));
        }

        // Maximum amount to prevent overflow (100 billion lamports = 100 SOL)
        const MAX_AMOUNT: u64 = 100_000_000_000_000;
        if amount > MAX_AMOUNT {
            return Err(VeilError::InvalidInput(
                format!("Amount exceeds maximum: {} > {}", amount, MAX_AMOUNT)
            ));
        }

        Ok(())
    }

    /// Validate a 32-byte hash/commitment/nullifier
    pub fn validate_hash32(hash: &[u8], name: &str) -> Result<(), VeilError> {
        if hash.len() != 32 {
            return Err(VeilError::InvalidInput(
                format!("{} must be exactly 32 bytes, got {}", name, hash.len())
            ));
        }
        Ok(())
    }

    /// Validate a Merkle proof
    pub fn validate_merkle_proof(
        siblings: &[[u8; 32]],
        indices: &[bool],
        expected_depth: usize,
    ) -> Result<(), VeilError> {
        if siblings.len() != expected_depth {
            return Err(VeilError::InvalidInput(
                format!("Merkle proof has wrong depth: {} != {}", siblings.len(), expected_depth)
            ));
        }
        if indices.len() != expected_depth {
            return Err(VeilError::InvalidInput(
                format!("Merkle indices has wrong length: {} != {}", indices.len(), expected_depth)
            ));
        }
        Ok(())
    }

    /// Validate a proof size (MVP: 96 bytes, Groth16: 256 bytes)
    pub fn validate_proof_size(proof: &[u8]) -> Result<(), VeilError> {
        const MVP_SIZE: usize = 96;
        const GROTH16_SIZE: usize = 256;

        if proof.len() != MVP_SIZE && proof.len() != GROTH16_SIZE {
            return Err(VeilError::InvalidInput(
                format!(
                    "Invalid proof size: {} bytes (expected {} or {})",
                    proof.len(), MVP_SIZE, GROTH16_SIZE
                )
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use validation::*;

    #[test]
    fn test_validate_secret() {
        // Valid secret
        assert!(validate_secret(&[1u8; 32]).is_ok());

        // Too short
        assert!(validate_secret(&[1u8; 16]).is_err());

        // All zeros
        assert!(validate_secret(&[0u8; 32]).is_err());
    }

    #[test]
    fn test_validate_amount() {
        // Valid amounts
        assert!(validate_amount(1).is_ok());
        assert!(validate_amount(1_000_000_000).is_ok());

        // Zero
        assert!(validate_amount(0).is_err());

        // Too large
        assert!(validate_amount(u64::MAX).is_err());
    }

    #[test]
    fn test_validate_hash32() {
        // Valid
        assert!(validate_hash32(&[0u8; 32], "test").is_ok());

        // Wrong size
        assert!(validate_hash32(&[0u8; 31], "test").is_err());
        assert!(validate_hash32(&[0u8; 33], "test").is_err());
    }

    #[test]
    fn test_validate_proof_size() {
        // MVP proof
        assert!(validate_proof_size(&[0u8; 96]).is_ok());

        // Groth16 proof
        assert!(validate_proof_size(&[0u8; 256]).is_ok());

        // Invalid sizes
        assert!(validate_proof_size(&[0u8; 64]).is_err());
        assert!(validate_proof_size(&[0u8; 128]).is_err());
    }
}
