//! zkSNARK proof generation and verification
//!
//! This module implements Groth16 proof generation and verification for private transfers.
//!
//! Components:
//! - `circuit`: Legacy circuit definitions (deprecated)
//! - `gadgets`: R1CS constraint gadgets (Poseidon, Merkle)
//! - `transfer_circuit`: Main transfer circuit using arkworks
//! - Proof generation and verification using ark-groth16

pub mod circuit;
pub mod gadgets;
pub mod transfer_circuit;

use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey, VerifyingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_snark::SNARK;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub use transfer_circuit::TransferCircuit;

#[derive(Error, Debug)]
pub enum ProofError {
    #[error("Invalid witness data")]
    InvalidWitness,
    #[error("Proof generation failed: {0}")]
    GenerationFailed(String),
    #[error("Proof verification failed: {0}")]
    VerificationFailed(String),
    #[error("Serialization error: {0}")]
    SerializationError(String),
    #[error("Setup error: {0}")]
    SetupError(String),
    #[error("Invalid proving key")]
    InvalidProvingKey,
    #[error("Invalid verifying key")]
    InvalidVerifyingKey,
}

/// Serialized Groth16 proof (256 bytes)
/// Format: A (64) || B (128) || C (64)
#[derive(Clone, Debug)]
pub struct SerializedProof {
    pub bytes: Vec<u8>,
}

impl SerializedProof {
    /// Expected size of a compressed Groth16 proof
    pub const SIZE: usize = 256; // 64 + 128 + 64 for compressed points

    /// Create from raw bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self, ProofError> {
        if bytes.len() != Self::SIZE {
            return Err(ProofError::SerializationError(format!(
                "Expected {} bytes, got {}",
                Self::SIZE,
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    /// Get the raw bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Groth16 proof system for transfer circuits
pub struct TransferProofSystem {
    proving_key: ProvingKey<Bn254>,
    verifying_key: VerifyingKey<Bn254>,
    prepared_vk: PreparedVerifyingKey<Bn254>,
}

impl TransferProofSystem {
    /// Generate proving and verifying keys for the transfer circuit
    ///
    /// WARNING: This uses a random toxic waste and is suitable only for testing.
    /// For production, use a trusted setup ceremony.
    pub fn setup() -> Result<Self, ProofError> {
        // Create a dummy circuit for setup
        let circuit = TransferCircuit::default();

        let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(circuit, &mut OsRng)
            .map_err(|e| ProofError::SetupError(e.to_string()))?;

        let prepared_vk = Groth16::<Bn254>::process_vk(&vk)
            .map_err(|e| ProofError::SetupError(e.to_string()))?;

        Ok(Self {
            proving_key: pk,
            verifying_key: vk,
            prepared_vk,
        })
    }

    /// Load from serialized keys
    pub fn from_keys(pk_bytes: &[u8], vk_bytes: &[u8]) -> Result<Self, ProofError> {
        let proving_key = ProvingKey::deserialize_compressed(pk_bytes)
            .map_err(|e| ProofError::InvalidProvingKey)?;

        let verifying_key = VerifyingKey::deserialize_compressed(vk_bytes)
            .map_err(|e| ProofError::InvalidVerifyingKey)?;

        let prepared_vk = Groth16::<Bn254>::process_vk(&verifying_key)
            .map_err(|e| ProofError::SetupError(e.to_string()))?;

        Ok(Self {
            proving_key,
            verifying_key,
            prepared_vk,
        })
    }

    /// Serialize the proving key
    pub fn serialize_proving_key(&self) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        self.proving_key
            .serialize_compressed(&mut bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Serialize the verifying key
    pub fn serialize_verifying_key(&self) -> Result<Vec<u8>, ProofError> {
        let mut bytes = Vec::new();
        self.verifying_key
            .serialize_compressed(&mut bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        Ok(bytes)
    }

    /// Generate a proof for a transfer circuit
    pub fn prove(&self, circuit: TransferCircuit) -> Result<SerializedProof, ProofError> {
        let proof = Groth16::<Bn254>::prove(&self.proving_key, circuit, &mut OsRng)
            .map_err(|e| ProofError::GenerationFailed(e.to_string()))?;

        // Serialize the proof
        let mut bytes = Vec::new();
        proof
            .serialize_compressed(&mut bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;

        // Pad to expected size if needed
        bytes.resize(SerializedProof::SIZE, 0);

        SerializedProof::from_bytes(bytes)
    }

    /// Verify a proof with public inputs
    pub fn verify(
        &self,
        proof_bytes: &[u8],
        public_inputs: &[Fr],
    ) -> Result<bool, ProofError> {
        // Deserialize proof
        let proof = Proof::deserialize_compressed(proof_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;

        // Verify
        let valid = Groth16::<Bn254>::verify_with_processed_vk(
            &self.prepared_vk,
            public_inputs,
            &proof,
        )
        .map_err(|e| ProofError::VerificationFailed(e.to_string()))?;

        Ok(valid)
    }

    /// Get the verifying key
    pub fn verifying_key(&self) -> &VerifyingKey<Bn254> {
        &self.verifying_key
    }

    /// Export verifying key in Solana-compatible format (big-endian)
    ///
    /// This exports the verifying key components in the format expected by
    /// groth16-solana for on-chain verification.
    ///
    /// Returns a SolanaVerifyingKey struct containing all components.
    pub fn export_solana_vk(&self) -> Result<SolanaVerifyingKey, ProofError> {
        use ark_ec::AffineRepr;
        use ark_serialize::CanonicalSerialize;

        let vk = &self.verifying_key;

        // Serialize alpha_g1 (G1 point, 64 bytes compressed in arkworks)
        let mut alpha_g1_bytes = Vec::new();
        vk.alpha_g1.serialize_uncompressed(&mut alpha_g1_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let alpha_g1 = g1_le_to_be(&alpha_g1_bytes)?;

        // Serialize beta_g2 (G2 point, 128 bytes)
        let mut beta_g2_bytes = Vec::new();
        vk.beta_g2.serialize_uncompressed(&mut beta_g2_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let beta_g2 = g2_le_to_be(&beta_g2_bytes)?;

        // Serialize gamma_g2 (G2 point, 128 bytes)
        let mut gamma_g2_bytes = Vec::new();
        vk.gamma_g2.serialize_uncompressed(&mut gamma_g2_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let gamma_g2 = g2_le_to_be(&gamma_g2_bytes)?;

        // Serialize delta_g2 (G2 point, 128 bytes)
        let mut delta_g2_bytes = Vec::new();
        vk.delta_g2.serialize_uncompressed(&mut delta_g2_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let delta_g2 = g2_le_to_be(&delta_g2_bytes)?;

        // Serialize IC elements (variable number of G1 points)
        let mut ic = Vec::with_capacity(vk.gamma_abc_g1.len());
        for point in &vk.gamma_abc_g1 {
            let mut point_bytes = Vec::new();
            point.serialize_uncompressed(&mut point_bytes)
                .map_err(|e| ProofError::SerializationError(e.to_string()))?;
            ic.push(g1_le_to_be(&point_bytes)?);
        }

        Ok(SolanaVerifyingKey {
            alpha_g1,
            beta_g2,
            gamma_g2,
            delta_g2,
            ic,
        })
    }

    /// Export proof in Solana-compatible format (big-endian)
    ///
    /// Converts an arkworks Groth16 proof to the format expected by groth16-solana.
    /// Note: The proof.a point must have its y-coordinate negated for groth16-solana.
    pub fn export_solana_proof(&self, proof_bytes: &[u8]) -> Result<SolanaProof, ProofError> {
        use ark_ec::AffineRepr;
        use ark_serialize::CanonicalSerialize;

        // Deserialize the arkworks proof
        let proof = Proof::<Bn254>::deserialize_compressed(proof_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;

        // Serialize and convert proof_a (G1 point)
        // Note: groth16-solana uses -A in the pairing equation
        let mut a_bytes = Vec::new();
        (-proof.a).serialize_uncompressed(&mut a_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let proof_a = g1_le_to_be(&a_bytes)?;

        // Serialize and convert proof_b (G2 point)
        let mut b_bytes = Vec::new();
        proof.b.serialize_uncompressed(&mut b_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let proof_b = g2_le_to_be(&b_bytes)?;

        // Serialize and convert proof_c (G1 point)
        let mut c_bytes = Vec::new();
        proof.c.serialize_uncompressed(&mut c_bytes)
            .map_err(|e| ProofError::SerializationError(e.to_string()))?;
        let proof_c = g1_le_to_be(&c_bytes)?;

        Ok(SolanaProof {
            a: proof_a,
            b: proof_b,
            c: proof_c,
        })
    }
}

/// Solana-compatible verifying key format (big-endian)
#[derive(Clone, Debug)]
pub struct SolanaVerifyingKey {
    /// Alpha * G1 (64 bytes)
    pub alpha_g1: [u8; 64],
    /// Beta * G2 (128 bytes)
    pub beta_g2: [u8; 128],
    /// Gamma * G2 (128 bytes)
    pub gamma_g2: [u8; 128],
    /// Delta * G2 (128 bytes)
    pub delta_g2: [u8; 128],
    /// IC elements (one per public input + 1)
    pub ic: Vec<[u8; 64]>,
}

impl SolanaVerifyingKey {
    /// Export as Rust code for embedding in Solana program
    pub fn to_rust_code(&self) -> String {
        let mut code = String::new();
        code.push_str("// Auto-generated verifying key - DO NOT EDIT\n\n");

        code.push_str(&format!("pub const ALPHA_G1: [u8; 64] = {:?};\n\n", self.alpha_g1));
        code.push_str(&format!("pub const BETA_G2: [u8; 128] = {:?};\n\n", self.beta_g2));
        code.push_str(&format!("pub const GAMMA_G2: [u8; 128] = {:?};\n\n", self.gamma_g2));
        code.push_str(&format!("pub const DELTA_G2: [u8; 128] = {:?};\n\n", self.delta_g2));

        code.push_str(&format!("pub const IC: [[u8; 64]; {}] = [\n", self.ic.len()));
        for ic_elem in &self.ic {
            code.push_str(&format!("    {:?},\n", ic_elem));
        }
        code.push_str("];\n");

        code
    }
}

/// Solana-compatible proof format (big-endian)
#[derive(Clone, Debug)]
pub struct SolanaProof {
    /// Proof point A (G1, 64 bytes, negated for groth16-solana)
    pub a: [u8; 64],
    /// Proof point B (G2, 128 bytes)
    pub b: [u8; 128],
    /// Proof point C (G1, 64 bytes)
    pub c: [u8; 64],
}

impl SolanaProof {
    /// Convert to raw bytes (256 bytes total)
    pub fn to_bytes(&self) -> [u8; 256] {
        let mut bytes = [0u8; 256];
        bytes[0..64].copy_from_slice(&self.a);
        bytes[64..192].copy_from_slice(&self.b);
        bytes[192..256].copy_from_slice(&self.c);
        bytes
    }
}

/// Convert G1 point from arkworks little-endian to big-endian
fn g1_le_to_be(le_bytes: &[u8]) -> Result<[u8; 64], ProofError> {
    if le_bytes.len() != 64 {
        return Err(ProofError::SerializationError(
            format!("G1 point should be 64 bytes, got {}", le_bytes.len())
        ));
    }
    let mut be = [0u8; 64];
    // x coordinate (32 bytes)
    be[0..32].copy_from_slice(&le_bytes[0..32]);
    be[0..32].reverse();
    // y coordinate (32 bytes)
    be[32..64].copy_from_slice(&le_bytes[32..64]);
    be[32..64].reverse();
    Ok(be)
}

/// Convert G2 point from arkworks little-endian to big-endian
fn g2_le_to_be(le_bytes: &[u8]) -> Result<[u8; 128], ProofError> {
    if le_bytes.len() != 128 {
        return Err(ProofError::SerializationError(
            format!("G2 point should be 128 bytes, got {}", le_bytes.len())
        ));
    }
    let mut be = [0u8; 128];
    // x.c0 (32 bytes)
    be[0..32].copy_from_slice(&le_bytes[0..32]);
    be[0..32].reverse();
    // x.c1 (32 bytes)
    be[32..64].copy_from_slice(&le_bytes[32..64]);
    be[32..64].reverse();
    // y.c0 (32 bytes)
    be[64..96].copy_from_slice(&le_bytes[64..96]);
    be[64..96].reverse();
    // y.c1 (32 bytes)
    be[96..128].copy_from_slice(&le_bytes[96..128]);
    be[96..128].reverse();
    Ok(be)
}

// ============================================================================
// Legacy API (kept for backward compatibility)
// ============================================================================

#[derive(Serialize, Deserialize, Debug)]
pub struct TransferWitness {
    pub sender_secret: String,
    pub sender_commitment: String,
    pub recipient: String,
    pub amount: u64,
    pub nullifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PublicInputs {
    pub nullifier: String,
    pub new_commitment: String,
    pub root: String,
}

/// Generate proof for private transfer (Legacy mock implementation)
#[deprecated(note = "Use TransferProofSystem::prove() for real Groth16 proofs")]
pub fn generate_transfer_proof(witness: &TransferWitness) -> Result<Vec<u8>, ProofError> {
    if witness.sender_secret.is_empty() {
        return Err(ProofError::InvalidWitness);
    }

    // Mock proof
    let mut hasher = blake3::Hasher::new();
    hasher.update(witness.sender_secret.as_bytes());
    hasher.update(witness.sender_commitment.as_bytes());
    hasher.update(witness.recipient.as_bytes());
    hasher.update(&witness.amount.to_le_bytes());
    hasher.update(witness.nullifier.as_bytes());
    hasher.update(b"mock_proof_v1");

    let hash1 = hasher.finalize();

    let mut hasher2 = blake3::Hasher::new();
    hasher2.update(hash1.as_bytes());
    hasher2.update(b"second_half");
    let hash2 = hasher2.finalize();

    let mut proof = Vec::with_capacity(64);
    proof.extend_from_slice(hash1.as_bytes());
    proof.extend_from_slice(hash2.as_bytes());

    Ok(proof)
}

/// Verify transfer proof (Legacy mock implementation)
#[deprecated(note = "Use TransferProofSystem::verify() for real Groth16 verification")]
pub fn verify_transfer_proof(proof: &[u8], public_inputs_json: &str) -> Result<bool, ProofError> {
    if proof.len() != 64 {
        return Err(ProofError::VerificationFailed(
            "Invalid proof length".to_string(),
        ));
    }

    let _inputs: PublicInputs = serde_json::from_str(public_inputs_json)
        .map_err(|e| ProofError::SerializationError(e.to_string()))?;

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[allow(deprecated)]
    fn test_legacy_proof_generation() {
        let witness = TransferWitness {
            sender_secret: "secret".to_string(),
            sender_commitment: "commitment".to_string(),
            recipient: "recipient".to_string(),
            amount: 1000,
            nullifier: "nullifier".to_string(),
        };

        let proof = generate_transfer_proof(&witness).unwrap();
        assert_eq!(proof.len(), 64);
    }

    #[test]
    #[allow(deprecated)]
    fn test_legacy_proof_deterministic() {
        let witness = TransferWitness {
            sender_secret: "secret".to_string(),
            sender_commitment: "commitment".to_string(),
            recipient: "recipient".to_string(),
            amount: 1000,
            nullifier: "nullifier".to_string(),
        };

        let proof1 = generate_transfer_proof(&witness).unwrap();
        let proof2 = generate_transfer_proof(&witness).unwrap();
        assert_eq!(proof1, proof2);
    }
}
