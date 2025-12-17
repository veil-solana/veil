//! Standard Poseidon constants for BN254 scalar field
//!
//! These constants are generated using a deterministic process compatible
//! with the Poseidon specification. For production use, these should be
//! replaced with constants from a trusted ceremony or standard implementation
//! like circomlib.
//!
//! Parameters:
//! - Field: BN254 scalar field (Fr)
//! - Width: t = 3 (2 inputs + 1 capacity)
//! - Full rounds: RF = 8 (4 at start, 4 at end)
//! - Partial rounds: RP = 57
//! - S-box: x^5

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

/// Number of full rounds (RF = 8)
pub const FULL_ROUNDS: usize = 8;

/// Number of partial rounds (RP = 57)
pub const PARTIAL_ROUNDS: usize = 57;

/// State width (t = 3 for 2 inputs)
pub const WIDTH: usize = 3;

/// Total number of round constants
pub const NUM_CONSTANTS: usize = WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS);

/// Generate round constants deterministically
/// Uses a hash-based approach similar to Grain LFSR
pub fn get_round_constants() -> Vec<Fr> {
    let mut constants = Vec::with_capacity(NUM_CONSTANTS);

    // Domain separator for Poseidon BN254 t=3
    let domain = b"Poseidon_BN254_t3_RF8_RP57";

    for i in 0..NUM_CONSTANTS {
        let mut hasher = blake3::Hasher::new();
        hasher.update(domain);
        hasher.update(&(i as u64).to_le_bytes());
        hasher.update(b"round_constant");

        let hash = hasher.finalize();
        let constant = Fr::from_le_bytes_mod_order(hash.as_bytes());
        constants.push(constant);
    }

    constants
}

/// Generate MDS matrix
/// Uses a Cauchy matrix construction which is guaranteed to be MDS
pub fn get_mds_matrix() -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::from(0u64); WIDTH]; WIDTH];

    // Create x and y vectors for Cauchy matrix
    // x = [0, 1, 2, ...], y = [WIDTH, WIDTH+1, WIDTH+2, ...]
    let x: Vec<Fr> = (0..WIDTH).map(|i| Fr::from(i as u64)).collect();
    let y: Vec<Fr> = (WIDTH..(2 * WIDTH)).map(|i| Fr::from(i as u64)).collect();

    for i in 0..WIDTH {
        for j in 0..WIDTH {
            // M[i][j] = 1 / (x[i] + y[j])
            let sum = x[i] + y[j];
            matrix[i][j] = sum.inverse().unwrap_or(Fr::from(1u64));
        }
    }

    matrix
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants_count() {
        let constants = get_round_constants();
        assert_eq!(constants.len(), NUM_CONSTANTS);
    }

    #[test]
    fn test_round_constants_nonzero() {
        let constants = get_round_constants();

        // All constants should be non-zero
        for c in &constants {
            assert_ne!(*c, Fr::from(0u64));
        }
    }

    #[test]
    fn test_round_constants_deterministic() {
        let c1 = get_round_constants();
        let c2 = get_round_constants();

        for (a, b) in c1.iter().zip(c2.iter()) {
            assert_eq!(a, b);
        }
    }

    #[test]
    fn test_mds_matrix_dimensions() {
        let matrix = get_mds_matrix();
        assert_eq!(matrix.len(), WIDTH);

        for row in &matrix {
            assert_eq!(row.len(), WIDTH);
        }
    }

    #[test]
    fn test_mds_matrix_nonzero() {
        let matrix = get_mds_matrix();
        for row in &matrix {
            for elem in row {
                assert_ne!(*elem, Fr::from(0u64));
            }
        }
    }

    #[test]
    fn test_mds_matrix_deterministic() {
        let m1 = get_mds_matrix();
        let m2 = get_mds_matrix();

        for i in 0..WIDTH {
            for j in 0..WIDTH {
                assert_eq!(m1[i][j], m2[i][j]);
            }
        }
    }
}
