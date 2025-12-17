//! Veil - Privacy Core
//!
//! High-performance cryptographic operations for privacy-preserving transactions.
//!
//! # Modules
//! - `crypto`: Cryptographic primitives (commitments, nullifiers, Poseidon hash, Merkle trees)
//! - `proof`: zkSNARK proof generation and verification (Groth16)
//! - `relayer`: Relayer client infrastructure for private transactions

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

pub mod crypto;
pub mod error;
pub mod proof;
pub mod relayer;

// Re-export common types
pub use error::{CryptoError, VeilError, VeilResult, ProofError, RelayerError};

use crypto::{generate_nullifier_hash, Commitment};
use proof::{generate_transfer_proof, verify_transfer_proof, TransferWitness};

/// Generate a Pedersen commitment for shielding assets
///
/// # Arguments
/// * `amount` - Amount to shield (in lamports/smallest unit)
/// * `secret` - User's secret key (32 bytes minimum)
///
/// # Returns
/// * Commitment bytes (32 bytes)
#[pyfunction]
fn generate_commitment(py: Python, amount: u64, secret: &[u8]) -> PyResult<Py<PyBytes>> {
    // Validate inputs
    if secret.len() < 32 {
        return Err(PyValueError::new_err("Secret must be at least 32 bytes"));
    }

    // Generate commitment using Rust (fast!)
    let commitment = Commitment::new(amount, secret)
        .map_err(|e| PyRuntimeError::new_err(format!("Commitment generation failed: {}", e)))?;

    // Serialize commitment
    let bytes = commitment.to_bytes();

    // Return as Python bytes
    Ok(PyBytes::new(py, &bytes).into())
}

/// Generate a nullifier to prevent double-spending
///
/// # Arguments
/// * `commitment` - The commitment bytes
/// * `secret` - User's secret key
///
/// # Returns
/// * Nullifier hash (32 bytes)
#[pyfunction]
fn generate_nullifier(py: Python, commitment: &[u8], secret: &[u8]) -> PyResult<Py<PyBytes>> {
    if commitment.len() != 32 {
        return Err(PyValueError::new_err("Commitment must be 32 bytes"));
    }
    if secret.len() < 32 {
        return Err(PyValueError::new_err("Secret must be at least 32 bytes"));
    }

    let nullifier = generate_nullifier_hash(commitment, secret)
        .map_err(|e| PyRuntimeError::new_err(format!("Nullifier generation failed: {}", e)))?;

    Ok(PyBytes::new(py, &nullifier).into())
}

/// Generate zkSNARK proof for private transfer
///
/// # Arguments
/// * `witness_json` - JSON string containing witness data
///
/// # Returns
/// * Proof bytes
#[pyfunction]
fn generate_proof(py: Python, witness_json: &str) -> PyResult<Py<PyBytes>> {
    // Parse witness from JSON
    let witness: TransferWitness = serde_json::from_str(witness_json)
        .map_err(|e| PyValueError::new_err(format!("Invalid witness JSON: {}", e)))?;

    // Generate proof (this is the expensive operation!)
    let proof = generate_transfer_proof(&witness)
        .map_err(|e| PyRuntimeError::new_err(format!("Proof generation failed: {}", e)))?;

    Ok(PyBytes::new(py, &proof).into())
}

/// Verify zkSNARK proof
///
/// # Arguments
/// * `proof` - Proof bytes
/// * `public_inputs_json` - JSON string containing public inputs
///
/// # Returns
/// * Boolean indicating if proof is valid
#[pyfunction]
fn verify_proof(proof: &[u8], public_inputs_json: &str) -> PyResult<bool> {
    let valid = verify_transfer_proof(proof, public_inputs_json)
        .map_err(|e| PyRuntimeError::new_err(format!("Proof verification failed: {}", e)))?;

    Ok(valid)
}

/// Poseidon hash function (zkSNARK-friendly)
///
/// # Arguments
/// * `inputs` - Array of field elements to hash
///
/// # Returns
/// * Hash output (32 bytes)
#[pyfunction]
fn poseidon_hash(py: Python, inputs: Vec<Vec<u8>>) -> PyResult<Py<PyBytes>> {
    use crypto::poseidon_hash_bytes;

    let hash = poseidon_hash_bytes(&inputs)
        .map_err(|e| PyRuntimeError::new_err(format!("Poseidon hash failed: {}", e)))?;

    Ok(PyBytes::new(py, &hash).into())
}

/// Python module definition
#[pymodule]
fn _rust_core(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(generate_commitment, m)?)?;
    m.add_function(wrap_pyfunction!(generate_nullifier, m)?)?;
    m.add_function(wrap_pyfunction!(generate_proof, m)?)?;
    m.add_function(wrap_pyfunction!(verify_proof, m)?)?;
    m.add_function(wrap_pyfunction!(poseidon_hash, m)?)?;

    // Add version
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;

    Ok(())
}
