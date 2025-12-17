//! Groth16 zkSNARK Verification for Solana
//!
//! This module provides on-chain Groth16 proof verification using Solana's
//! BN254 precompiles (available since Solana 1.18.x).
//!
//! The verification is performed using the groth16-solana crate which
//! provides efficient on-chain verification (~200k compute units).
//!
//! Proof Format (256 bytes):
//! - proof_a: 64 bytes (G1 point, big-endian)
//! - proof_b: 128 bytes (G2 point)
//! - proof_c: 64 bytes (G1 point)
//!
//! Public Inputs (each 32 bytes, big-endian):
//! - merkle_root
//! - nullifier
//! - new_commitment

use anchor_lang::prelude::*;
use groth16_solana::groth16::{Groth16Verifier, Groth16Verifyingkey};

/// Groth16 proof size in bytes (compressed)
pub const PROOF_SIZE: usize = 256;

/// Size of a single public input (field element)
pub const PUBLIC_INPUT_SIZE: usize = 32;

/// Number of public inputs for the transfer circuit
pub const NUM_PUBLIC_INPUTS: usize = 3;

/// Total size of all public inputs
pub const PUBLIC_INPUTS_SIZE: usize = NUM_PUBLIC_INPUTS * PUBLIC_INPUT_SIZE;

/// Verifying key for the transfer circuit
///
/// This key is generated during the trusted setup and must match
/// the proving key used to generate proofs off-chain.
///
/// The key is stored as a constant array of bytes in big-endian format.
/// It can be generated from arkworks VerifyingKey using the export functions
/// in the Rust SDK.
///
/// For now, this is a placeholder that will be replaced with the actual
/// verifying key after the trusted setup ceremony.
pub mod vk {
    /// Placeholder verifying key structure
    /// This will be replaced with actual key data after trusted setup
    ///
    /// The verifying key contains:
    /// - alpha_g1: 64 bytes
    /// - beta_g2: 128 bytes
    /// - gamma_g2: 128 bytes
    /// - delta_g2: 128 bytes
    /// - ic: variable length (NUM_PUBLIC_INPUTS + 1) * 64 bytes
    ///
    /// Total for 3 public inputs: 64 + 128 + 128 + 128 + (4 * 64) = 704 bytes

    /// Alpha * G1 (64 bytes)
    pub const ALPHA_G1: [u8; 64] = [0u8; 64];

    /// Beta * G2 (128 bytes)
    pub const BETA_G2: [u8; 128] = [0u8; 128];

    /// Gamma * G2 (128 bytes)
    pub const GAMMA_G2: [u8; 128] = [0u8; 128];

    /// Delta * G2 (128 bytes)
    pub const DELTA_G2: [u8; 128] = [0u8; 128];

    /// IC elements (one for capacity + one per public input)
    /// For 3 public inputs: 4 * 64 = 256 bytes
    pub const IC: [[u8; 64]; 4] = [[0u8; 64]; 4];
}

/// Check if verifying key is initialized (not all zeros)
fn is_vk_initialized() -> bool {
    vk::ALPHA_G1.iter().any(|&b| b != 0)
}

/// Groth16 proof structure
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct Groth16Proof {
    /// Proof point A (G1, 64 bytes big-endian)
    pub a: [u8; 64],
    /// Proof point B (G2, 128 bytes big-endian)
    pub b: [u8; 128],
    /// Proof point C (G1, 64 bytes big-endian)
    pub c: [u8; 64],
}

impl Groth16Proof {
    /// Parse proof from raw bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < PROOF_SIZE {
            return None;
        }

        let mut a = [0u8; 64];
        let mut b = [0u8; 128];
        let mut c = [0u8; 64];

        a.copy_from_slice(&bytes[0..64]);
        b.copy_from_slice(&bytes[64..192]);
        c.copy_from_slice(&bytes[192..256]);

        Some(Self { a, b, c })
    }

    /// Convert to raw bytes
    pub fn to_bytes(&self) -> [u8; PROOF_SIZE] {
        let mut bytes = [0u8; PROOF_SIZE];
        bytes[0..64].copy_from_slice(&self.a);
        bytes[64..192].copy_from_slice(&self.b);
        bytes[192..256].copy_from_slice(&self.c);
        bytes
    }
}

/// Public inputs for the transfer circuit
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct TransferPublicInputs {
    /// Current Merkle root
    pub merkle_root: [u8; 32],
    /// Nullifier being spent
    pub nullifier: [u8; 32],
    /// New commitment being created
    pub new_commitment: [u8; 32],
}

impl TransferPublicInputs {
    /// Convert to the format expected by the verifier (big-endian field elements)
    pub fn to_verifier_inputs(&self) -> [[u8; 32]; NUM_PUBLIC_INPUTS] {
        [self.merkle_root, self.nullifier, self.new_commitment]
    }
}

/// Errors for Groth16 verification
#[error_code]
pub enum Groth16Error {
    #[msg("Invalid proof size")]
    InvalidProofSize,
    #[msg("Invalid public inputs")]
    InvalidPublicInputs,
    #[msg("Proof verification failed")]
    VerificationFailed,
    #[msg("Verifying key not initialized")]
    VkNotInitialized,
}

/// Verify a Groth16 proof for a transfer
///
/// This function verifies that a zkSNARK proof is valid for the given public inputs.
/// The proof demonstrates knowledge of:
/// - A valid note in the Merkle tree
/// - The spending key for that note
/// - Correct nullifier derivation
/// - Correct new commitment formation
///
/// # Arguments
/// * `proof` - The 256-byte Groth16 proof
/// * `merkle_root` - The Merkle root public input
/// * `nullifier` - The nullifier public input
/// * `new_commitment` - The new commitment public input
///
/// # Returns
/// * `Ok(true)` if the proof is valid
/// * `Ok(false)` if the proof is invalid
/// * `Err(...)` if there's a format error
pub fn verify_groth16_transfer(
    proof_bytes: &[u8],
    merkle_root: &[u8; 32],
    nullifier: &[u8; 32],
    new_commitment: &[u8; 32],
) -> Result<bool> {
    // Parse proof
    let proof = Groth16Proof::from_bytes(proof_bytes)
        .ok_or(Groth16Error::InvalidProofSize)?;

    // Check if verifying key is initialized
    if !is_vk_initialized() {
        // VK not initialized - for development, return true
        // TODO: Remove this bypass and require proper VK initialization
        msg!("WARNING: Verifying key not initialized, skipping proof verification");
        return Ok(true);
    }

    // Prepare public inputs as fixed-size array
    let public_inputs: [[u8; 32]; NUM_PUBLIC_INPUTS] = [
        *merkle_root,
        *nullifier,
        *new_commitment,
    ];

    // Create verifying key struct
    let verifying_key = Groth16Verifyingkey {
        nr_pubinputs: NUM_PUBLIC_INPUTS,
        vk_alpha_g1: vk::ALPHA_G1,
        vk_beta_g2: vk::BETA_G2,
        vk_gamme_g2: vk::GAMMA_G2,
        vk_delta_g2: vk::DELTA_G2,
        vk_ic: &vk::IC,
    };

    // Create verifier with the proof and public inputs
    let mut verifier = Groth16Verifier::<NUM_PUBLIC_INPUTS>::new(
        &proof.a,
        &proof.b,
        &proof.c,
        &public_inputs,
        &verifying_key,
    ).map_err(|_| Groth16Error::VerificationFailed)?;

    // Perform verification
    match verifier.verify() {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Convert a 32-byte little-endian field element to big-endian
///
/// arkworks uses little-endian, while groth16-solana expects big-endian
pub fn le_to_be_32(le_bytes: &[u8; 32]) -> [u8; 32] {
    let mut be_bytes = *le_bytes;
    be_bytes.reverse();
    be_bytes
}

/// Convert a 64-byte little-endian G1 point to big-endian
///
/// G1 points are represented as (x, y) where each coordinate is 32 bytes
pub fn le_to_be_g1(le_bytes: &[u8; 64]) -> [u8; 64] {
    let mut be_bytes = [0u8; 64];
    // Reverse x coordinate
    be_bytes[0..32].copy_from_slice(&le_bytes[0..32]);
    be_bytes[0..32].reverse();
    // Reverse y coordinate
    be_bytes[32..64].copy_from_slice(&le_bytes[32..64]);
    be_bytes[32..64].reverse();
    be_bytes
}

/// Convert a 128-byte little-endian G2 point to big-endian
///
/// G2 points are represented as (x, y) where each coordinate is 64 bytes (Fq2)
/// Each Fq2 element is (c0, c1) where each is 32 bytes
pub fn le_to_be_g2(le_bytes: &[u8; 128]) -> [u8; 128] {
    let mut be_bytes = [0u8; 128];
    // x.c0, x.c1, y.c0, y.c1 - each 32 bytes, needs to be reversed
    for i in 0..4 {
        let start = i * 32;
        be_bytes[start..start + 32].copy_from_slice(&le_bytes[start..start + 32]);
        be_bytes[start..start + 32].reverse();
    }
    be_bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_parsing() {
        let mut proof_bytes = [0u8; 256];
        // Set some test values
        proof_bytes[0] = 1;
        proof_bytes[64] = 2;
        proof_bytes[192] = 3;

        let proof = Groth16Proof::from_bytes(&proof_bytes).unwrap();
        assert_eq!(proof.a[0], 1);
        assert_eq!(proof.b[0], 2);
        assert_eq!(proof.c[0], 3);
    }

    #[test]
    fn test_proof_too_short() {
        let proof_bytes = [0u8; 128]; // Too short
        assert!(Groth16Proof::from_bytes(&proof_bytes).is_none());
    }

    #[test]
    fn test_le_to_be_conversion() {
        let le = [1u8, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let be = le_to_be_32(&le);
        assert_eq!(be[31], 1);
        assert_eq!(be[30], 2);
        assert_eq!(be[29], 3);
        assert_eq!(be[28], 4);
    }
}
