//! Transfer Circuit for Private Transfers
//!
//! This circuit proves that a private transfer is valid:
//! 1. The sender knows the preimage of a commitment in the Merkle tree
//! 2. The nullifier is correctly derived from the spending key and leaf index
//! 3. The new commitment is correctly formed
//! 4. Amount conservation is maintained (input = output for now)
//!
//! Public Inputs:
//! - merkle_root: The current Merkle tree root
//! - nullifier: The nullifier for the spent note
//! - new_commitment: The commitment to the output note
//!
//! Private Inputs (Witness):
//! - sender_secret: The secret used to derive the spending key
//! - input_amount: The amount in the input note
//! - input_blinding: The blinding factor for the input commitment
//! - leaf_index: The index of the input commitment in the Merkle tree
//! - merkle_path: The sibling hashes in the Merkle path
//! - output_blinding: The blinding factor for the output commitment

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_r1cs_std::{
    alloc::AllocVar,
    eq::EqGadget,
    fields::fp::FpVar,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use super::gadgets::merkle::MerklePathGadget;
use super::gadgets::poseidon::poseidon_hash2_gadget;

/// Transfer circuit for private transfers
#[derive(Clone)]
pub struct TransferCircuit {
    // ===== Public Inputs =====
    /// Current Merkle root
    pub merkle_root: Option<Fr>,
    /// Nullifier for the spent note
    pub nullifier: Option<Fr>,
    /// New commitment for the output note
    pub new_commitment: Option<Fr>,

    // ===== Private Inputs (Witness) =====
    /// Sender's secret (32 bytes as Fr)
    pub sender_secret: Option<Fr>,
    /// Amount in the input note
    pub input_amount: Option<Fr>,
    /// Blinding factor for the input commitment
    pub input_blinding: Option<Fr>,
    /// Asset ID (0 for native SOL)
    pub asset_id: Option<Fr>,
    /// Leaf index in the Merkle tree
    pub leaf_index: Option<u64>,
    /// Merkle path siblings
    pub merkle_path: Option<Vec<Fr>>,
    /// Merkle path indices (left/right)
    pub merkle_indices: Option<Vec<bool>>,
    /// Output blinding factor
    pub output_blinding: Option<Fr>,
}

impl Default for TransferCircuit {
    fn default() -> Self {
        Self {
            merkle_root: None,
            nullifier: None,
            new_commitment: None,
            sender_secret: None,
            input_amount: None,
            input_blinding: None,
            asset_id: None,
            leaf_index: None,
            merkle_path: None,
            merkle_indices: None,
            output_blinding: None,
        }
    }
}

impl TransferCircuit {
    /// Create a new transfer circuit with all values
    pub fn new(
        merkle_root: Fr,
        nullifier: Fr,
        new_commitment: Fr,
        sender_secret: Fr,
        input_amount: Fr,
        input_blinding: Fr,
        asset_id: Fr,
        leaf_index: u64,
        merkle_path: Vec<Fr>,
        merkle_indices: Vec<bool>,
        output_blinding: Fr,
    ) -> Self {
        Self {
            merkle_root: Some(merkle_root),
            nullifier: Some(nullifier),
            new_commitment: Some(new_commitment),
            sender_secret: Some(sender_secret),
            input_amount: Some(input_amount),
            input_blinding: Some(input_blinding),
            asset_id: Some(asset_id),
            leaf_index: Some(leaf_index),
            merkle_path: Some(merkle_path),
            merkle_indices: Some(merkle_indices),
            output_blinding: Some(output_blinding),
        }
    }

    /// Number of public inputs
    pub const NUM_PUBLIC_INPUTS: usize = 3; // merkle_root, nullifier, new_commitment
}

impl ConstraintSynthesizer<Fr> for TransferCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        // ===== Allocate Public Inputs =====
        let merkle_root_var = FpVar::new_input(cs.clone(), || {
            self.merkle_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let nullifier_var = FpVar::new_input(cs.clone(), || {
            self.nullifier.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let new_commitment_var = FpVar::new_input(cs.clone(), || {
            self.new_commitment.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ===== Allocate Private Inputs (Witnesses) =====
        let sender_secret_var = FpVar::new_witness(cs.clone(), || {
            self.sender_secret.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let input_amount_var = FpVar::new_witness(cs.clone(), || {
            self.input_amount.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let input_blinding_var = FpVar::new_witness(cs.clone(), || {
            self.input_blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let asset_id_var = FpVar::new_witness(cs.clone(), || {
            self.asset_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let leaf_index = self.leaf_index.ok_or(SynthesisError::AssignmentMissing)?;
        let leaf_index_var = FpVar::new_witness(cs.clone(), || Ok(Fr::from(leaf_index)))?;

        let output_blinding_var = FpVar::new_witness(cs.clone(), || {
            self.output_blinding.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // ===== Constraint 1: Compute spending key =====
        // spending_key = Poseidon(secret, domain_separator)
        let domain_separator = FpVar::new_constant(
            cs.clone(),
            Fr::from_le_bytes_mod_order(b"NYX_SPENDING_KEY"),
        )?;
        let spending_key_var = poseidon_hash2_gadget(cs.clone(), &sender_secret_var, &domain_separator)?;

        // ===== Constraint 2: Compute input commitment =====
        // commitment = Poseidon(Poseidon(spending_key, amount), Poseidon(blinding, asset_id))
        let h1 = poseidon_hash2_gadget(cs.clone(), &spending_key_var, &input_amount_var)?;
        let h2 = poseidon_hash2_gadget(cs.clone(), &input_blinding_var, &asset_id_var)?;
        let input_commitment_var = poseidon_hash2_gadget(cs.clone(), &h1, &h2)?;

        // ===== Constraint 3: Verify Merkle membership =====
        let merkle_path = self.merkle_path.ok_or(SynthesisError::AssignmentMissing)?;
        let merkle_indices = self.merkle_indices.ok_or(SynthesisError::AssignmentMissing)?;

        let path_gadget = MerklePathGadget::new_witness(cs.clone(), &merkle_path, &merkle_indices)?;
        path_gadget.verify(cs.clone(), &input_commitment_var, &merkle_root_var)?;

        // ===== Constraint 4: Verify nullifier derivation =====
        // nullifier = Poseidon(spending_key, hash(leaf_index || domain))
        let nullifier_domain = FpVar::new_constant(
            cs.clone(),
            Fr::from_le_bytes_mod_order(b"NYX_NULLIFIER"),
        )?;
        let index_with_domain = poseidon_hash2_gadget(cs.clone(), &leaf_index_var, &nullifier_domain)?;
        let computed_nullifier = poseidon_hash2_gadget(cs.clone(), &spending_key_var, &index_with_domain)?;

        // Enforce nullifier matches
        computed_nullifier.enforce_equal(&nullifier_var)?;

        // ===== Constraint 5: Verify new commitment =====
        // For transfers within the pool, the output uses the same spending key
        // This ensures only the original owner can spend the output
        let h1_out = poseidon_hash2_gadget(cs.clone(), &spending_key_var, &input_amount_var)?;
        let h2_out = poseidon_hash2_gadget(cs.clone(), &output_blinding_var, &asset_id_var)?;
        let computed_new_commitment = poseidon_hash2_gadget(cs.clone(), &h1_out, &h2_out)?;

        // Enforce new commitment matches
        computed_new_commitment.enforce_equal(&new_commitment_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::rngs::OsRng;

    use crate::crypto::merkle::PoseidonMerkleTree;
    use crate::crypto::nullifier::{Nullifier, SpendingKey};
    use crate::crypto::poseidon::poseidon_hash2;

    /// Helper to compute note commitment
    fn compute_commitment(spending_key: &Fr, amount: &Fr, blinding: &Fr, asset_id: &Fr) -> Fr {
        let h1 = poseidon_hash2(spending_key, amount);
        let h2 = poseidon_hash2(blinding, asset_id);
        poseidon_hash2(&h1, &h2)
    }

    #[test]
    fn test_transfer_circuit_valid() {
        // Create test values
        let sender_secret = Fr::rand(&mut OsRng);
        let input_amount = Fr::from(1000u64);
        let input_blinding = Fr::rand(&mut OsRng);
        let output_blinding = Fr::rand(&mut OsRng);
        let asset_id = Fr::from(0u64); // Native SOL

        // Compute spending key
        let domain = Fr::from_le_bytes_mod_order(b"NYX_SPENDING_KEY");
        let spending_key = poseidon_hash2(&sender_secret, &domain);

        // Compute input commitment
        let input_commitment = compute_commitment(&spending_key, &input_amount, &input_blinding, &asset_id);

        // Build Merkle tree and insert commitment
        let mut tree = PoseidonMerkleTree::new();
        let leaf_index = tree.insert(input_commitment).unwrap();
        let merkle_root = tree.root();
        let proof = tree.generate_proof(leaf_index).unwrap();

        // Compute nullifier (matching the circuit's derivation)
        let nullifier_domain = Fr::from_le_bytes_mod_order(b"NYX_NULLIFIER");
        let index_fr = Fr::from(leaf_index);
        let index_with_domain = poseidon_hash2(&index_fr, &nullifier_domain);
        let nullifier = poseidon_hash2(&spending_key, &index_with_domain);

        // Compute output commitment
        let new_commitment = compute_commitment(&spending_key, &input_amount, &output_blinding, &asset_id);

        // Create circuit
        let circuit = TransferCircuit::new(
            merkle_root,
            nullifier,
            new_commitment,
            sender_secret,
            input_amount,
            input_blinding,
            asset_id,
            leaf_index,
            proof.siblings,
            proof.indices,
            output_blinding,
        );

        // Generate constraints
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // Check constraints are satisfied
        println!("Transfer circuit constraints: {}", cs.num_constraints());
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_transfer_circuit_invalid_nullifier() {
        let sender_secret = Fr::rand(&mut OsRng);
        let input_amount = Fr::from(1000u64);
        let input_blinding = Fr::rand(&mut OsRng);
        let output_blinding = Fr::rand(&mut OsRng);
        let asset_id = Fr::from(0u64);

        let domain = Fr::from_le_bytes_mod_order(b"NYX_SPENDING_KEY");
        let spending_key = poseidon_hash2(&sender_secret, &domain);

        let input_commitment = compute_commitment(&spending_key, &input_amount, &input_blinding, &asset_id);

        let mut tree = PoseidonMerkleTree::new();
        let leaf_index = tree.insert(input_commitment).unwrap();
        let merkle_root = tree.root();
        let proof = tree.generate_proof(leaf_index).unwrap();

        // Wrong nullifier
        let wrong_nullifier = Fr::rand(&mut OsRng);

        let new_commitment = compute_commitment(&spending_key, &input_amount, &output_blinding, &asset_id);

        let circuit = TransferCircuit::new(
            merkle_root,
            wrong_nullifier,
            new_commitment,
            sender_secret,
            input_amount,
            input_blinding,
            asset_id,
            leaf_index,
            proof.siblings,
            proof.indices,
            output_blinding,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // Should NOT be satisfied with wrong nullifier
        assert!(!cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_transfer_circuit_invalid_merkle_proof() {
        let sender_secret = Fr::rand(&mut OsRng);
        let input_amount = Fr::from(1000u64);
        let input_blinding = Fr::rand(&mut OsRng);
        let output_blinding = Fr::rand(&mut OsRng);
        let asset_id = Fr::from(0u64);

        let domain = Fr::from_le_bytes_mod_order(b"NYX_SPENDING_KEY");
        let spending_key = poseidon_hash2(&sender_secret, &domain);

        let input_commitment = compute_commitment(&spending_key, &input_amount, &input_blinding, &asset_id);

        let mut tree = PoseidonMerkleTree::new();
        let leaf_index = tree.insert(input_commitment).unwrap();
        let merkle_root = tree.root();

        // Get proof but corrupt a sibling
        let mut proof = tree.generate_proof(leaf_index).unwrap();
        proof.siblings[0] = Fr::rand(&mut OsRng);

        let nullifier_domain = Fr::from_le_bytes_mod_order(b"NYX_NULLIFIER");
        let index_fr = Fr::from(leaf_index);
        let index_with_domain = poseidon_hash2(&index_fr, &nullifier_domain);
        let nullifier = poseidon_hash2(&spending_key, &index_with_domain);

        let new_commitment = compute_commitment(&spending_key, &input_amount, &output_blinding, &asset_id);

        let circuit = TransferCircuit::new(
            merkle_root,
            nullifier,
            new_commitment,
            sender_secret,
            input_amount,
            input_blinding,
            asset_id,
            leaf_index,
            proof.siblings,
            proof.indices,
            output_blinding,
        );

        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).unwrap();

        // Should NOT be satisfied with corrupted Merkle proof
        assert!(!cs.is_satisfied().unwrap());
    }
}
