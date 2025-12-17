//! Program instructions
//!
//! Defines the instructions that can be sent to the privacy program.
//!
//! Proof sizes:
//! - MVP (signature): 96 bytes [signature (64) | pubkey (32)]
//! - Groth16 (zkSNARK): 256 bytes [proof_a (64) | proof_b (128) | proof_c (64)]

use anchor_lang::prelude::*;

use crate::verification::{MVP_PROOF_SIZE, ProofType};
use crate::groth16::PROOF_SIZE as GROTH16_PROOF_SIZE;

/// Instruction data for Shield
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ShieldData {
    /// Pedersen commitment
    pub commitment: [u8; 32],
    /// Amount to shield (in token smallest unit)
    pub amount: u64,
}

/// Instruction data for Transfer
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct TransferData {
    /// Nullifier to spend
    pub nullifier: [u8; 32],
    /// New commitment for recipient
    pub new_commitment: [u8; 32],
    /// Proof (MVP: 96 bytes, Groth16: 256 bytes)
    pub proof: Vec<u8>,
}

/// Instruction data for Unshield
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct UnshieldData {
    /// Nullifier to spend
    pub nullifier: [u8; 32],
    /// Amount to withdraw
    pub amount: u64,
    /// Proof (MVP: 96 bytes, Groth16: 256 bytes)
    pub proof: Vec<u8>,
}

/// Custom error codes for the privacy program
#[error_code]
pub enum NyxError {
    #[msg("Invalid amount")]
    InvalidAmount,
    #[msg("Invalid proof size: expected 96 (MVP) or 256 (Groth16) bytes")]
    InvalidProof,
    #[msg("Nullifier already spent")]
    NullifierSpent,
    #[msg("Invalid commitment")]
    InvalidCommitment,
    #[msg("Pool is full")]
    PoolFull,
    #[msg("Proof verification failed")]
    ProofVerificationFailed,
}

impl ShieldData {
    pub fn validate(&self) -> Result<()> {
        require!(self.amount > 0, NyxError::InvalidAmount);
        Ok(())
    }
}

impl TransferData {
    pub fn validate(&self) -> Result<()> {
        // Accept both MVP (96 bytes) and Groth16 (256 bytes) proofs
        let valid_size = self.proof.len() == MVP_PROOF_SIZE
            || self.proof.len() == GROTH16_PROOF_SIZE;
        require!(valid_size, NyxError::InvalidProof);
        Ok(())
    }

    /// Get the detected proof type
    pub fn proof_type(&self) -> Option<ProofType> {
        ProofType::detect(&self.proof)
    }
}

impl UnshieldData {
    pub fn validate(&self) -> Result<()> {
        require!(self.amount > 0, NyxError::InvalidAmount);
        // Accept both MVP (96 bytes) and Groth16 (256 bytes) proofs
        let valid_size = self.proof.len() == MVP_PROOF_SIZE
            || self.proof.len() == GROTH16_PROOF_SIZE;
        require!(valid_size, NyxError::InvalidProof);
        Ok(())
    }

    /// Get the detected proof type
    pub fn proof_type(&self) -> Option<ProofType> {
        ProofType::detect(&self.proof)
    }
}
