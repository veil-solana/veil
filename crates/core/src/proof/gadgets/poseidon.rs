//! Poseidon Hash Gadget for R1CS circuits
//!
//! Implements the Poseidon permutation as constraints for use in zkSNARK circuits.
//! This gadget is compatible with the native Poseidon implementation in crypto::poseidon.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use crate::crypto::poseidon_constants::{FULL_ROUNDS, PARTIAL_ROUNDS, WIDTH};

/// Poseidon hash gadget for circuits
pub struct PoseidonGadget {
    /// Round constants as constraint variables
    round_constants: Vec<FpVar<Fr>>,
    /// MDS matrix as constraint variables
    mds_matrix: Vec<Vec<FpVar<Fr>>>,
}

impl PoseidonGadget {
    /// Create a new Poseidon gadget with the standard constants
    pub fn new(cs: ConstraintSystemRef<Fr>) -> Result<Self, SynthesisError> {
        // Load constants from the standard module
        let rc = crate::crypto::poseidon_constants::get_round_constants();
        let mds = crate::crypto::poseidon_constants::get_mds_matrix();

        // Allocate round constants as constants (not witnesses)
        let round_constants: Result<Vec<FpVar<Fr>>, _> = rc
            .iter()
            .map(|c| FpVar::new_constant(cs.clone(), *c))
            .collect();

        // Allocate MDS matrix as constants
        let mds_matrix: Result<Vec<Vec<FpVar<Fr>>>, _> = mds
            .iter()
            .map(|row| {
                row.iter()
                    .map(|c| FpVar::new_constant(cs.clone(), *c))
                    .collect()
            })
            .collect();

        Ok(Self {
            round_constants: round_constants?,
            mds_matrix: mds_matrix?,
        })
    }

    /// Hash two field elements
    pub fn hash2(
        &self,
        cs: ConstraintSystemRef<Fr>,
        a: &FpVar<Fr>,
        b: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        // Initialize state: [0, a, b]
        let zero = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;
        let mut state = vec![zero, a.clone(), b.clone()];

        // Apply permutation
        self.permute(&mut state)?;

        // Return first element
        Ok(state[0].clone())
    }

    /// Hash multiple field elements (sponge construction)
    pub fn hash(
        &self,
        cs: ConstraintSystemRef<Fr>,
        inputs: &[FpVar<Fr>],
    ) -> Result<FpVar<Fr>, SynthesisError> {
        if inputs.is_empty() {
            return Err(SynthesisError::AssignmentMissing);
        }

        if inputs.len() > WIDTH - 1 {
            // For more inputs, use sponge construction
            return self.hash_sponge(cs, inputs);
        }

        // Initialize state with capacity element = 0
        let zero = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;
        let mut state = vec![zero; WIDTH];

        // Copy inputs into state (after capacity element)
        for (i, input) in inputs.iter().enumerate() {
            state[i + 1] = input.clone();
        }

        // Apply permutation
        self.permute(&mut state)?;

        // Return first element
        Ok(state[0].clone())
    }

    /// Hash using sponge construction for arbitrary-length inputs
    fn hash_sponge(
        &self,
        cs: ConstraintSystemRef<Fr>,
        inputs: &[FpVar<Fr>],
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let rate = WIDTH - 1; // Rate is t-1 for capacity 1

        // Initialize state
        let zero = FpVar::new_constant(cs.clone(), Fr::from(0u64))?;
        let mut state = vec![zero; WIDTH];

        // Absorb phase
        for chunk in inputs.chunks(rate) {
            for (i, input) in chunk.iter().enumerate() {
                state[i + 1] = &state[i + 1] + input;
            }
            self.permute(&mut state)?;
        }

        // Squeeze (just return first element for single-output hash)
        Ok(state[0].clone())
    }

    /// Apply the Poseidon permutation to the state
    fn permute(&self, state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
        let t = WIDTH;
        let rf = FULL_ROUNDS;
        let rp = PARTIAL_ROUNDS;

        let mut round_ctr = 0;

        // First half of full rounds
        for _ in 0..(rf / 2) {
            self.full_round(state, round_ctr)?;
            round_ctr += t;
        }

        // Partial rounds
        for _ in 0..rp {
            self.partial_round(state, round_ctr)?;
            round_ctr += t;
        }

        // Second half of full rounds
        for _ in 0..(rf / 2) {
            self.full_round(state, round_ctr)?;
            round_ctr += t;
        }

        Ok(())
    }

    /// Full round: S-box on all elements, then MDS
    fn full_round(
        &self,
        state: &mut [FpVar<Fr>],
        round_ctr: usize,
    ) -> Result<(), SynthesisError> {
        // Add round constants
        for i in 0..WIDTH {
            state[i] = &state[i] + &self.round_constants[round_ctr + i];
        }

        // S-box (x^5) on all elements
        for elem in state.iter_mut() {
            *elem = self.sbox(elem)?;
        }

        // MDS matrix multiplication
        self.mds_multiply(state)?;

        Ok(())
    }

    /// Partial round: S-box on first element only, then MDS
    fn partial_round(
        &self,
        state: &mut [FpVar<Fr>],
        round_ctr: usize,
    ) -> Result<(), SynthesisError> {
        // Add round constants
        for i in 0..WIDTH {
            state[i] = &state[i] + &self.round_constants[round_ctr + i];
        }

        // S-box only on first element
        state[0] = self.sbox(&state[0])?;

        // MDS matrix multiplication
        self.mds_multiply(state)?;

        Ok(())
    }

    /// S-box function: x^5
    fn sbox(&self, x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
        // x^2
        let x2 = x * x;
        // x^4
        let x4 = &x2 * &x2;
        // x^5
        Ok(&x4 * x)
    }

    /// Multiply state by MDS matrix
    fn mds_multiply(&self, state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
        let mut new_state = Vec::with_capacity(WIDTH);

        for i in 0..WIDTH {
            let mut sum = FpVar::zero();
            for j in 0..WIDTH {
                sum = sum + (&self.mds_matrix[i][j] * &state[j]);
            }
            new_state.push(sum);
        }

        // FpVar doesn't implement Copy, so clone each element
        for (i, val) in new_state.into_iter().enumerate() {
            state[i] = val;
        }
        Ok(())
    }
}

/// Standalone function to hash two field element variables
pub fn poseidon_hash2_gadget(
    cs: ConstraintSystemRef<Fr>,
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let gadget = PoseidonGadget::new(cs.clone())?;
    gadget.hash2(cs, a, b)
}

/// Standalone function to hash multiple field element variables
pub fn poseidon_hash_gadget(
    cs: ConstraintSystemRef<Fr>,
    inputs: &[FpVar<Fr>],
) -> Result<FpVar<Fr>, SynthesisError> {
    let gadget = PoseidonGadget::new(cs.clone())?;
    gadget.hash(cs, inputs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;
    use crate::crypto::poseidon::poseidon_hash2;

    #[test]
    fn test_poseidon_gadget_matches_native() {
        // Native computation
        let a = Fr::from(1u64);
        let b = Fr::from(2u64);
        let native_result = poseidon_hash2(&a, &b);

        // Circuit computation
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a_var = FpVar::new_witness(cs.clone(), || Ok(a)).unwrap();
        let b_var = FpVar::new_witness(cs.clone(), || Ok(b)).unwrap();

        let result_var = poseidon_hash2_gadget(cs.clone(), &a_var, &b_var).unwrap();

        // Check result matches
        assert_eq!(result_var.value().unwrap(), native_result);

        // Check constraints are satisfied
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_gadget_different_inputs() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();
        let c = FpVar::new_witness(cs.clone(), || Ok(Fr::from(3u64))).unwrap();

        let hash1 = poseidon_hash2_gadget(cs.clone(), &a, &b).unwrap();
        let hash2 = poseidon_hash2_gadget(cs.clone(), &a, &c).unwrap();

        // Different inputs should produce different outputs
        assert_ne!(hash1.value().unwrap(), hash2.value().unwrap());

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_poseidon_gadget_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();

        let a = FpVar::new_witness(cs.clone(), || Ok(Fr::from(1u64))).unwrap();
        let b = FpVar::new_witness(cs.clone(), || Ok(Fr::from(2u64))).unwrap();

        let _ = poseidon_hash2_gadget(cs.clone(), &a, &b).unwrap();

        // Should have a reasonable number of constraints
        // (exact number depends on implementation)
        println!("Constraint count: {}", cs.num_constraints());
        assert!(cs.num_constraints() > 0);
        assert!(cs.is_satisfied().unwrap());
    }
}
