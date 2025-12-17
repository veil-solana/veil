//! Poseidon Hash Function
//!
//! A zkSNARK-friendly hash function using the Poseidon permutation.
//! This implementation uses the BN254 scalar field and follows the
//! specification from the Poseidon paper (https://eprint.iacr.org/2019/458).
//!
//! Parameters:
//! - Field: BN254 scalar field (Fr)
//! - Width: 3 (t=3 for 2 inputs)
//! - Full rounds: 8 (4 at start, 4 at end)
//! - Partial rounds: 57
//! - S-box: x^5

use ark_bn254::Fr;
use ark_ff::{BigInteger, Field, PrimeField};
use ark_serialize::CanonicalSerialize;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum PoseidonError {
    #[error("Invalid input length: expected at most {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Conversion error")]
    ConversionError,
    #[error("Empty input")]
    EmptyInput,
}

/// Poseidon parameters for width t=3 (2 inputs + 1 capacity)
pub struct PoseidonParams {
    /// Number of full rounds
    pub full_rounds: usize,
    /// Number of partial rounds
    pub partial_rounds: usize,
    /// Width of the state (t)
    pub width: usize,
    /// Round constants
    pub round_constants: Vec<Fr>,
    /// MDS matrix
    pub mds_matrix: Vec<Vec<Fr>>,
}

impl Default for PoseidonParams {
    fn default() -> Self {
        Self::new()
    }
}

impl PoseidonParams {
    /// Create Poseidon parameters for BN254 with t=3
    /// Uses standard constants from poseidon_constants module
    pub fn new() -> Self {
        use super::poseidon_constants;

        let width = poseidon_constants::WIDTH;
        let full_rounds = poseidon_constants::FULL_ROUNDS;
        let partial_rounds = poseidon_constants::PARTIAL_ROUNDS;

        // Use standard constants from the constants module
        let round_constants = poseidon_constants::get_round_constants();
        let mds_matrix = poseidon_constants::get_mds_matrix();

        Self {
            full_rounds,
            partial_rounds,
            width,
            round_constants,
            mds_matrix,
        }
    }

    /// Create with custom parameters (for testing only)
    #[cfg(test)]
    pub fn with_generated_constants() -> Self {
        let width = 3;
        let full_rounds = 8;
        let partial_rounds = 57;

        let round_constants = generate_round_constants(width, full_rounds, partial_rounds);
        let mds_matrix = generate_mds_matrix(width);

        Self {
            full_rounds,
            partial_rounds,
            width,
            round_constants,
            mds_matrix,
        }
    }
}

/// Poseidon hasher instance
pub struct Poseidon {
    params: PoseidonParams,
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

impl Poseidon {
    /// Create a new Poseidon hasher with default parameters
    pub fn new() -> Self {
        Self {
            params: PoseidonParams::new(),
        }
    }

    /// Hash two field elements
    pub fn hash2(&self, a: &Fr, b: &Fr) -> Fr {
        let mut state = [Fr::from(0u64), *a, *b];
        self.permute(&mut state);
        state[0]
    }

    /// Hash a variable number of field elements
    pub fn hash(&self, inputs: &[Fr]) -> Result<Fr, PoseidonError> {
        if inputs.is_empty() {
            return Err(PoseidonError::EmptyInput);
        }

        if inputs.len() > self.params.width - 1 {
            return Err(PoseidonError::InvalidLength {
                expected: self.params.width - 1,
                got: inputs.len(),
            });
        }

        // Initialize state with capacity element = 0
        let mut state = vec![Fr::from(0u64); self.params.width];

        // Copy inputs into state (after capacity element)
        for (i, input) in inputs.iter().enumerate() {
            state[i + 1] = *input;
        }

        // Apply permutation
        let mut state_arr = [state[0], state[1], state[2]];
        self.permute(&mut state_arr);

        // Return first element of output
        Ok(state_arr[0])
    }

    /// Apply the Poseidon permutation to the state
    fn permute(&self, state: &mut [Fr; 3]) {
        let t = self.params.width;
        let rf = self.params.full_rounds;
        let rp = self.params.partial_rounds;

        let mut round_ctr = 0;

        // First half of full rounds
        for _ in 0..(rf / 2) {
            self.full_round(state, round_ctr);
            round_ctr += t;
        }

        // Partial rounds
        for _ in 0..rp {
            self.partial_round(state, round_ctr);
            round_ctr += t;
        }

        // Second half of full rounds
        for _ in 0..(rf / 2) {
            self.full_round(state, round_ctr);
            round_ctr += t;
        }
    }

    /// Full round: S-box on all elements, then MDS
    fn full_round(&self, state: &mut [Fr; 3], round_ctr: usize) {
        // Add round constants
        for i in 0..3 {
            state[i] += self.params.round_constants[round_ctr + i];
        }

        // S-box (x^5) on all elements
        for elem in state.iter_mut() {
            *elem = sbox(*elem);
        }

        // MDS matrix multiplication
        self.mds_multiply(state);
    }

    /// Partial round: S-box on first element only, then MDS
    fn partial_round(&self, state: &mut [Fr; 3], round_ctr: usize) {
        // Add round constants
        for i in 0..3 {
            state[i] += self.params.round_constants[round_ctr + i];
        }

        // S-box only on first element
        state[0] = sbox(state[0]);

        // MDS matrix multiplication
        self.mds_multiply(state);
    }

    /// Multiply state by MDS matrix
    fn mds_multiply(&self, state: &mut [Fr; 3]) {
        let mut new_state = [Fr::from(0u64); 3];

        for i in 0..3 {
            for j in 0..3 {
                new_state[i] += self.params.mds_matrix[i][j] * state[j];
            }
        }

        *state = new_state;
    }
}

/// S-box function: x^5
#[inline]
fn sbox(x: Fr) -> Fr {
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

/// Generate round constants using a deterministic process
/// In production, use the standard Poseidon constants
fn generate_round_constants(width: usize, full_rounds: usize, partial_rounds: usize) -> Vec<Fr> {
    let num_constants = width * (full_rounds + partial_rounds);
    let mut constants = Vec::with_capacity(num_constants);

    // Use a simple deterministic generator based on the Grain LFSR approach
    // For production, use the official Poseidon constants for BN254
    let seed = b"Poseidon_BN254_t3";
    let mut hasher_state = blake3::Hasher::new();
    hasher_state.update(seed);

    for i in 0..num_constants {
        // Generate each constant deterministically
        let mut h = hasher_state.clone();
        h.update(&(i as u64).to_le_bytes());
        let hash = h.finalize();

        // Convert to field element
        let bytes = hash.as_bytes();
        let constant = Fr::from_le_bytes_mod_order(bytes);
        constants.push(constant);
    }

    constants
}

/// Generate MDS matrix
/// Uses a simple Cauchy matrix construction
fn generate_mds_matrix(width: usize) -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::from(0u64); width]; width];

    // Create x and y vectors for Cauchy matrix
    let x: Vec<Fr> = (0..width).map(|i| Fr::from(i as u64)).collect();
    let y: Vec<Fr> = (width..(2 * width)).map(|i| Fr::from(i as u64)).collect();

    for i in 0..width {
        for j in 0..width {
            // M[i][j] = 1 / (x[i] + y[j])
            let sum = x[i] + y[j];
            matrix[i][j] = sum.inverse().unwrap_or(Fr::from(1u64));
        }
    }

    matrix
}

// ============================================================================
// Public API
// ============================================================================

/// Thread-local Poseidon instance for convenience
thread_local! {
    static POSEIDON: Poseidon = Poseidon::new();
}

/// Hash two field elements using Poseidon
pub fn poseidon_hash2(a: &Fr, b: &Fr) -> Fr {
    POSEIDON.with(|p| p.hash2(a, b))
}

/// Hash field elements using Poseidon
pub fn poseidon_hash_fields(inputs: &[Fr]) -> Result<Fr, PoseidonError> {
    POSEIDON.with(|p| p.hash(inputs))
}

/// Poseidon hash for byte arrays
pub fn poseidon_hash_bytes(inputs: &[Vec<u8>]) -> Result<Vec<u8>, PoseidonError> {
    if inputs.is_empty() {
        return Err(PoseidonError::EmptyInput);
    }

    // Convert bytes to field elements
    let field_inputs: Result<Vec<Fr>, _> = inputs
        .iter()
        .map(|bytes| {
            if bytes.len() > 32 {
                return Err(PoseidonError::InvalidLength {
                    expected: 32,
                    got: bytes.len(),
                });
            }
            Ok(Fr::from_le_bytes_mod_order(bytes))
        })
        .collect();

    let field_inputs = field_inputs?;

    // Compute Poseidon hash
    let hash = poseidon_hash_fields(&field_inputs)?;

    // Convert back to bytes
    let mut bytes = Vec::new();
    hash.serialize_compressed(&mut bytes)
        .map_err(|_| PoseidonError::ConversionError)?;

    Ok(bytes)
}

/// Hash bytes to a 32-byte output
pub fn poseidon_hash_to_bytes32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let a_fr = Fr::from_le_bytes_mod_order(a);
    let b_fr = Fr::from_le_bytes_mod_order(b);

    let hash = poseidon_hash2(&a_fr, &b_fr);

    // Convert to bytes
    let mut result = [0u8; 32];
    let repr = hash.into_bigint();
    let bytes = repr.to_bytes_le();
    result[..bytes.len().min(32)].copy_from_slice(&bytes[..bytes.len().min(32)]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_hash_deterministic() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);

        let hash1 = poseidon_hash2(&a, &b);
        let hash2 = poseidon_hash2(&a, &b);

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_different_inputs() {
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let c = Fr::from(3u64);

        let hash1 = poseidon_hash2(&a, &b);
        let hash2 = poseidon_hash2(&a, &c);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_poseidon_hash_bytes() {
        let inputs = vec![vec![1u8; 32], vec![2u8; 32]];

        let hash = poseidon_hash_bytes(&inputs).unwrap();
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_poseidon_hash_to_bytes32() {
        let a = [1u8; 32];
        let b = [2u8; 32];

        let hash1 = poseidon_hash_to_bytes32(&a, &b);
        let hash2 = poseidon_hash_to_bytes32(&a, &b);

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_poseidon_permutation() {
        let poseidon = Poseidon::new();

        // Test that permutation produces non-zero output
        let mut state = [Fr::from(0u64), Fr::from(1u64), Fr::from(2u64)];
        poseidon.permute(&mut state);

        assert_ne!(state[0], Fr::from(0u64));
    }

    #[test]
    fn test_sbox() {
        let x = Fr::from(2u64);
        let result = sbox(x);
        let expected = Fr::from(32u64); // 2^5 = 32
        assert_eq!(result, expected);
    }

    #[test]
    fn test_poseidon_single_input() {
        let inputs = vec![Fr::from(42u64)];
        let hash = poseidon_hash_fields(&inputs).unwrap();
        assert_ne!(hash, Fr::from(0u64));
    }
}
