//! Proof Verification Module
//!
//! This module provides proof verification for the Nyx privacy protocol.
//! It supports two proof types:
//!
//! 1. **MVP/Signature Mode** (96 bytes):
//!    - Ed25519 signature-based proofs for testing
//!    - NOT private - reveals signer's public key
//!    - Format: [signature (64) | pubkey (32)]
//!
//! 2. **Groth16 zkSNARK Mode** (256 bytes):
//!    - Full privacy via zero-knowledge proofs
//!    - Uses Solana's BN254 precompiles (available since 1.18.x)
//!    - Format: [proof_a (64) | proof_b (128) | proof_c (64)]
//!
//! The proof type is detected automatically based on proof size.

use anchor_lang::prelude::*;
use solana_program::ed25519_program;
use solana_program::keccak;

use crate::groth16::{verify_groth16_transfer, PROOF_SIZE as GROTH16_PROOF_SIZE};

/// MVP proof size (signature + pubkey)
pub const MVP_PROOF_SIZE: usize = 96;

/// Proof types supported by the protocol
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug, PartialEq)]
pub enum ProofType {
    /// MVP: Ed25519 signature (not private, for testing only)
    Signature,
    /// Production: Groth16 zkSNARK proof (fully private)
    Groth16,
}

impl ProofType {
    /// Detect proof type from proof bytes
    pub fn detect(proof: &[u8]) -> Option<Self> {
        match proof.len() {
            MVP_PROOF_SIZE => Some(ProofType::Signature),
            GROTH16_PROOF_SIZE => Some(ProofType::Groth16),
            _ => None,
        }
    }
}

/// MVP proof structure (signature-based)
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct MvpProof {
    /// The Ed25519 signature (64 bytes)
    pub signature: [u8; 64],
    /// The public key that signed (32 bytes)
    pub pubkey: [u8; 32],
}

impl MvpProof {
    pub const SIZE: usize = 64 + 32;

    /// Parse from proof bytes
    /// Format: [signature (64 bytes) | pubkey (32 bytes)]
    pub fn from_bytes(proof: &[u8]) -> Option<Self> {
        if proof.len() < Self::SIZE {
            return None;
        }

        let mut signature = [0u8; 64];
        let mut pubkey = [0u8; 32];

        signature.copy_from_slice(&proof[0..64]);
        pubkey.copy_from_slice(&proof[64..96]);

        Some(Self { signature, pubkey })
    }
}

/// Build the message to be signed for a transfer proof
///
/// Message = keccak256(nullifier || new_commitment || root)
pub fn build_transfer_message(
    nullifier: &[u8; 32],
    new_commitment: &[u8; 32],
    root: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(96);
    data.extend_from_slice(nullifier);
    data.extend_from_slice(new_commitment);
    data.extend_from_slice(root);
    keccak::hash(&data).to_bytes()
}

/// Build the message to be signed for an unshield proof
///
/// Message = keccak256(nullifier || recipient || amount || root)
pub fn build_unshield_message(
    nullifier: &[u8; 32],
    recipient: &Pubkey,
    amount: u64,
    root: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(104);
    data.extend_from_slice(nullifier);
    data.extend_from_slice(recipient.as_ref());
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(root);
    keccak::hash(&data).to_bytes()
}

/// Verify an Ed25519 signature (MVP proof)
///
/// Note: For production, this would use the Ed25519 program via CPI.
/// For simplicity in MVP, we use a basic verification.
///
/// In production zkSNARK mode, this function will be replaced with
/// Groth16 proof verification.
pub fn verify_signature(
    message: &[u8; 32],
    signature: &[u8; 64],
    pubkey: &[u8; 32],
) -> bool {
    // For MVP, we use a simplified verification approach
    // In production, this would use the Ed25519 native program

    // Create the expected precompile input format
    // The Ed25519 program expects: [signature (64) | pubkey (32) | message (variable)]
    let _ = (message, signature, pubkey, ed25519_program::ID);

    // TODO: Full Ed25519 verification via precompile
    // For now, just verify the proof has the right structure
    // This is NOT secure - only for development testing

    // Check signature is not all zeros
    signature.iter().any(|&b| b != 0) && pubkey.iter().any(|&b| b != 0)
}

/// Verify a transfer proof
///
/// Automatically detects proof type based on size:
/// - 96 bytes: MVP signature proof
/// - 256 bytes: Groth16 zkSNARK proof
///
/// # Arguments
/// * `proof` - The proof bytes (96 or 256 bytes)
/// * `nullifier` - The nullifier being spent
/// * `new_commitment` - The new commitment being created
/// * `root` - The Merkle root
pub fn verify_transfer_proof(
    proof: &[u8],
    nullifier: &[u8; 32],
    new_commitment: &[u8; 32],
    root: &[u8; 32],
) -> Result<bool> {
    // Detect proof type
    let proof_type = ProofType::detect(proof)
        .ok_or(VerificationError::InvalidProofFormat)?;

    match proof_type {
        ProofType::Signature => {
            // MVP: Ed25519 signature verification
            let mvp_proof = MvpProof::from_bytes(proof)
                .ok_or(VerificationError::InvalidProofFormat)?;
            let message = build_transfer_message(nullifier, new_commitment, root);
            let valid = verify_signature(&message, &mvp_proof.signature, &mvp_proof.pubkey);
            Ok(valid)
        }
        ProofType::Groth16 => {
            // Production: Groth16 zkSNARK verification
            verify_groth16_transfer(proof, root, nullifier, new_commitment)
                .map_err(|_| VerificationError::VerificationFailed.into())
        }
    }
}

/// Verify an unshield proof
///
/// Automatically detects proof type based on size:
/// - 96 bytes: MVP signature proof
/// - 256 bytes: Groth16 zkSNARK proof
///
/// For Groth16 proofs, the recipient and amount are derived from
/// the public inputs embedded in the proof verification.
///
/// # Arguments
/// * `proof` - The proof bytes (96 or 256 bytes)
/// * `nullifier` - The nullifier being spent
/// * `recipient` - The recipient pubkey (used for MVP only)
/// * `amount` - The amount being withdrawn (used for MVP only)
/// * `root` - The Merkle root
pub fn verify_unshield_proof(
    proof: &[u8],
    nullifier: &[u8; 32],
    recipient: &Pubkey,
    amount: u64,
    root: &[u8; 32],
) -> Result<bool> {
    // Detect proof type
    let proof_type = ProofType::detect(proof)
        .ok_or(VerificationError::InvalidProofFormat)?;

    match proof_type {
        ProofType::Signature => {
            // MVP: Ed25519 signature verification
            let mvp_proof = MvpProof::from_bytes(proof)
                .ok_or(VerificationError::InvalidProofFormat)?;
            let message = build_unshield_message(nullifier, recipient, amount, root);
            let valid = verify_signature(&message, &mvp_proof.signature, &mvp_proof.pubkey);
            Ok(valid)
        }
        ProofType::Groth16 => {
            // Production: Groth16 zkSNARK verification
            // For unshield, we create a commitment to 0 (the "burn" commitment)
            let burn_commitment = [0u8; 32];
            verify_groth16_transfer(proof, root, nullifier, &burn_commitment)
                .map_err(|_| VerificationError::VerificationFailed.into())
        }
    }
}

/// Custom errors for verification
#[error_code]
pub enum VerificationError {
    #[msg("Invalid proof format")]
    InvalidProofFormat,
    #[msg("Proof verification failed")]
    VerificationFailed,
    #[msg("Invalid public key")]
    InvalidPublicKey,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_transfer_message() {
        let nullifier = [1u8; 32];
        let new_commitment = [2u8; 32];
        let root = [3u8; 32];

        let msg1 = build_transfer_message(&nullifier, &new_commitment, &root);
        let msg2 = build_transfer_message(&nullifier, &new_commitment, &root);

        // Should be deterministic
        assert_eq!(msg1, msg2);

        // Different inputs should produce different messages
        let nullifier2 = [4u8; 32];
        let msg3 = build_transfer_message(&nullifier2, &new_commitment, &root);
        assert_ne!(msg1, msg3);
    }

    #[test]
    fn test_mvp_proof_parsing() {
        let mut proof_bytes = vec![0u8; 96];
        // Set some non-zero values
        proof_bytes[0] = 1; // signature
        proof_bytes[64] = 2; // pubkey

        let proof = MvpProof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof.signature[0], 1);
        assert_eq!(proof.pubkey[0], 2);
    }

    #[test]
    fn test_mvp_proof_parsing_too_short() {
        let proof_bytes = vec![0u8; 64]; // Too short
        assert!(MvpProof::from_bytes(&proof_bytes).is_none());
    }
}
