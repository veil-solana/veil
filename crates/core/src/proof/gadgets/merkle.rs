//! Merkle Path Verification Gadget for R1CS circuits
//!
//! Implements Merkle tree path verification as constraints for use in zkSNARK circuits.

use ark_bn254::Fr;
use ark_r1cs_std::{
    alloc::AllocVar,
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};

use super::poseidon::poseidon_hash2_gadget;
use crate::crypto::merkle::TREE_DEPTH;

/// Merkle path gadget for circuit-based verification
pub struct MerklePathGadget {
    /// Sibling hashes along the path
    pub siblings: Vec<FpVar<Fr>>,
    /// Path indices (false = left, true = right)
    pub indices: Vec<Boolean<Fr>>,
}

impl MerklePathGadget {
    /// Create a new Merkle path gadget from witness values
    pub fn new_witness(
        cs: ConstraintSystemRef<Fr>,
        siblings: &[Fr],
        indices: &[bool],
    ) -> Result<Self, SynthesisError> {
        if siblings.len() != TREE_DEPTH || indices.len() != TREE_DEPTH {
            return Err(SynthesisError::AssignmentMissing);
        }

        let siblings: Result<Vec<FpVar<Fr>>, _> = siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
            .collect();

        let indices: Result<Vec<Boolean<Fr>>, _> = indices
            .iter()
            .map(|&i| Boolean::new_witness(cs.clone(), || Ok(i)))
            .collect();

        Ok(Self {
            siblings: siblings?,
            indices: indices?,
        })
    }

    /// Verify the Merkle path leads to the expected root
    ///
    /// Returns a constraint that enforces the computed root equals the expected root
    pub fn verify(
        &self,
        cs: ConstraintSystemRef<Fr>,
        leaf: &FpVar<Fr>,
        expected_root: &FpVar<Fr>,
    ) -> Result<(), SynthesisError> {
        let computed_root = self.compute_root(cs.clone(), leaf)?;
        computed_root.enforce_equal(expected_root)?;
        Ok(())
    }

    /// Compute the Merkle root from the leaf and path
    pub fn compute_root(
        &self,
        cs: ConstraintSystemRef<Fr>,
        leaf: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let mut current = leaf.clone();

        for (sibling, is_right) in self.siblings.iter().zip(self.indices.iter()) {
            // If is_right, current is on the right: hash(sibling, current)
            // Otherwise, current is on the left: hash(current, sibling)
            let left = is_right.select(sibling, &current)?;
            let right = is_right.select(&current, sibling)?;

            current = poseidon_hash2_gadget(cs.clone(), &left, &right)?;
        }

        Ok(current)
    }
}

/// Verify a Merkle path in a circuit
///
/// This is a convenience function that:
/// 1. Allocates the path as witness variables
/// 2. Computes the root from the leaf
/// 3. Enforces the computed root equals the expected root
pub fn verify_merkle_path_gadget(
    cs: ConstraintSystemRef<Fr>,
    leaf: &FpVar<Fr>,
    siblings: &[Fr],
    indices: &[bool],
    expected_root: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    let path = MerklePathGadget::new_witness(cs.clone(), siblings, indices)?;
    path.verify(cs, leaf, expected_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::rngs::OsRng;

    use crate::crypto::merkle::PoseidonMerkleTree;

    #[test]
    fn test_merkle_gadget_valid_proof() {
        // Build a tree and get a proof
        let mut tree = PoseidonMerkleTree::new();

        for i in 0..4 {
            tree.insert(Fr::from(i as u64)).unwrap();
        }

        let leaf_index = 2;
        let proof = tree.generate_proof(leaf_index).unwrap();
        let leaf = tree.get_leaf(leaf_index).unwrap();
        let root = tree.root();

        // Verify in circuit
        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

        let path = MerklePathGadget::new_witness(
            cs.clone(),
            &proof.siblings,
            &proof.indices,
        ).unwrap();

        path.verify(cs.clone(), &leaf_var, &root_var).unwrap();

        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_merkle_gadget_invalid_leaf() {
        let mut tree = PoseidonMerkleTree::new();

        for i in 0..4 {
            tree.insert(Fr::from(i as u64)).unwrap();
        }

        let proof = tree.generate_proof(2).unwrap();
        let wrong_leaf = Fr::from(999u64);
        let root = tree.root();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(wrong_leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

        let path = MerklePathGadget::new_witness(
            cs.clone(),
            &proof.siblings,
            &proof.indices,
        ).unwrap();

        path.verify(cs.clone(), &leaf_var, &root_var).unwrap();

        // With wrong leaf, constraints should NOT be satisfied
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_merkle_gadget_invalid_root() {
        let mut tree = PoseidonMerkleTree::new();

        for i in 0..4 {
            tree.insert(Fr::from(i as u64)).unwrap();
        }

        let proof = tree.generate_proof(2).unwrap();
        let leaf = tree.get_leaf(2).unwrap();
        let wrong_root = Fr::rand(&mut OsRng);

        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(wrong_root)).unwrap();

        let path = MerklePathGadget::new_witness(
            cs.clone(),
            &proof.siblings,
            &proof.indices,
        ).unwrap();

        path.verify(cs.clone(), &leaf_var, &root_var).unwrap();

        // With wrong root, constraints should NOT be satisfied
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_merkle_gadget_constraint_count() {
        let mut tree = PoseidonMerkleTree::new();
        tree.insert(Fr::from(1u64)).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        let leaf = tree.get_leaf(0).unwrap();
        let root = tree.root();

        let cs = ConstraintSystem::<Fr>::new_ref();

        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(leaf)).unwrap();
        let root_var = FpVar::new_input(cs.clone(), || Ok(root)).unwrap();

        let path = MerklePathGadget::new_witness(
            cs.clone(),
            &proof.siblings,
            &proof.indices,
        ).unwrap();

        path.verify(cs.clone(), &leaf_var, &root_var).unwrap();

        println!("Merkle path verification constraints: {}", cs.num_constraints());
        assert!(cs.num_constraints() > 0);
        assert!(cs.is_satisfied().unwrap());
    }
}
