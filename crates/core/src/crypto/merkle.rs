//! Poseidon-based Merkle Tree for zkSNARK-compatible proofs
//!
//! This module implements an incremental Merkle tree using Poseidon hash,
//! which is efficient to verify inside zkSNARK circuits.
//!
//! Tree Structure:
//! - Depth: 20 levels (supports ~1 million leaves)
//! - Uses Poseidon hash for all internal nodes
//! - Compatible with circom and arkworks circuits

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use thiserror::Error;

use super::poseidon::poseidon_hash2;

/// Merkle tree depth (20 levels = 2^20 = ~1 million leaves)
pub const TREE_DEPTH: usize = 20;

/// Maximum number of leaves
pub const MAX_LEAVES: u64 = 1 << TREE_DEPTH;

#[derive(Error, Debug)]
pub enum MerkleError {
    #[error("Tree is full")]
    TreeFull,
    #[error("Invalid leaf index: {0}")]
    InvalidLeafIndex(u64),
    #[error("Invalid proof length")]
    InvalidProofLength,
}

/// Precomputed zero hashes for each level (Poseidon-based)
/// zeros[0] = 0 (empty leaf)
/// zeros[i] = Poseidon(zeros[i-1], zeros[i-1])
fn compute_zero_hashes() -> [Fr; TREE_DEPTH + 1] {
    let mut zeros = [Fr::from(0u64); TREE_DEPTH + 1];

    for i in 1..=TREE_DEPTH {
        zeros[i] = poseidon_hash2(&zeros[i - 1], &zeros[i - 1]);
    }

    zeros
}

/// Get zero hash for a specific level
pub fn get_zero_hash(level: usize) -> Fr {
    // We compute all zeros each time for simplicity
    // In production, these would be cached constants
    compute_zero_hashes()[level]
}

/// A Merkle path (proof) for a leaf
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling hashes from leaf to root
    pub siblings: Vec<Fr>,
    /// Path indices (false = left, true = right)
    pub indices: Vec<bool>,
    /// The leaf index
    pub leaf_index: u64,
}

impl MerklePath {
    /// Verify the path leads to the expected root
    pub fn verify(&self, leaf: &Fr, expected_root: &Fr) -> bool {
        if self.siblings.len() != TREE_DEPTH || self.indices.len() != TREE_DEPTH {
            return false;
        }

        let mut current = *leaf;

        for (sibling, &is_right) in self.siblings.iter().zip(self.indices.iter()) {
            current = if is_right {
                poseidon_hash2(sibling, &current)
            } else {
                poseidon_hash2(&current, sibling)
            };
        }

        current == *expected_root
    }

    /// Convert to bytes for serialization
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8 + TREE_DEPTH * 32 + TREE_DEPTH);

        // Leaf index
        bytes.extend_from_slice(&self.leaf_index.to_le_bytes());

        // Siblings
        for sibling in &self.siblings {
            let repr = sibling.into_bigint().to_bytes_le();
            bytes.extend_from_slice(&repr[..32]);
        }

        // Indices as bits
        let indices_byte: u32 = self
            .indices
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &is_right)| {
                if is_right {
                    acc | (1 << i)
                } else {
                    acc
                }
            });
        bytes.extend_from_slice(&indices_byte.to_le_bytes());

        bytes
    }
}

/// Incremental Merkle Tree using Poseidon hash
///
/// Optimized for O(log n) insertions using the "filled subtrees" technique.
#[derive(Clone, Debug)]
pub struct PoseidonMerkleTree {
    /// Current number of leaves
    pub next_index: u64,
    /// Filled subtrees at each level
    filled_subtrees: Vec<Fr>,
    /// Current root
    current_root: Fr,
    /// All leaves (for proof generation)
    leaves: Vec<Fr>,
    /// Precomputed zero hashes
    zeros: Vec<Fr>,
}

impl Default for PoseidonMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl PoseidonMerkleTree {
    /// Create a new empty tree
    pub fn new() -> Self {
        let zeros: Vec<Fr> = compute_zero_hashes().to_vec();

        // Initialize filled_subtrees with zero hashes
        let filled_subtrees: Vec<Fr> = (0..TREE_DEPTH).map(|i| zeros[i]).collect();

        // Initial root is zero hash at top level
        let current_root = zeros[TREE_DEPTH];

        Self {
            next_index: 0,
            filled_subtrees,
            current_root,
            leaves: Vec::new(),
            zeros,
        }
    }

    /// Insert a new leaf into the tree
    ///
    /// Returns the index of the inserted leaf
    pub fn insert(&mut self, leaf: Fr) -> Result<u64, MerkleError> {
        if self.next_index >= MAX_LEAVES {
            return Err(MerkleError::TreeFull);
        }

        let leaf_index = self.next_index;
        self.leaves.push(leaf);

        let mut current = leaf;
        let mut index = leaf_index;

        for level in 0..TREE_DEPTH {
            let is_left = index % 2 == 0;

            if is_left {
                // Store this as the filled subtree
                self.filled_subtrees[level] = current;
                // Hash with zero on the right
                current = poseidon_hash2(&current, &self.zeros[level]);
            } else {
                // Hash with filled subtree on the left
                current = poseidon_hash2(&self.filled_subtrees[level], &current);
            }

            index /= 2;
        }

        self.current_root = current;
        self.next_index += 1;

        Ok(leaf_index)
    }

    /// Get the current root
    pub fn root(&self) -> Fr {
        self.current_root
    }

    /// Get the root as 32 bytes
    pub fn root_bytes(&self) -> [u8; 32] {
        let bytes = self.current_root.into_bigint().to_bytes_le();
        let mut result = [0u8; 32];
        result.copy_from_slice(&bytes[..32]);
        result
    }

    /// Generate a Merkle proof for a leaf at the given index
    pub fn generate_proof(&self, leaf_index: u64) -> Result<MerklePath, MerkleError> {
        if leaf_index >= self.next_index {
            return Err(MerkleError::InvalidLeafIndex(leaf_index));
        }

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut indices = Vec::with_capacity(TREE_DEPTH);

        // Build the full tree to get siblings
        let mut level_nodes = self.leaves.clone();

        // Pad to next power of 2 with zeros
        while level_nodes.len() < (1 << TREE_DEPTH) {
            level_nodes.push(self.zeros[0]);
        }

        let mut current_index = leaf_index as usize;

        for level in 0..TREE_DEPTH {
            let is_right = current_index % 2 == 1;
            indices.push(is_right);

            let sibling_index = if is_right {
                current_index - 1
            } else {
                current_index + 1
            };

            siblings.push(level_nodes[sibling_index]);

            // Compute next level
            let mut next_level = Vec::with_capacity(level_nodes.len() / 2);
            for i in (0..level_nodes.len()).step_by(2) {
                let hash = poseidon_hash2(&level_nodes[i], &level_nodes[i + 1]);
                next_level.push(hash);
            }
            level_nodes = next_level;

            current_index /= 2;
        }

        Ok(MerklePath {
            siblings,
            indices,
            leaf_index,
        })
    }

    /// Check if a root is known (matches current root)
    pub fn is_known_root(&self, root: &Fr) -> bool {
        *root == self.current_root
    }

    /// Get the leaf at a given index
    pub fn get_leaf(&self, index: u64) -> Option<Fr> {
        self.leaves.get(index as usize).copied()
    }

    /// Get the number of leaves in the tree
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Check if tree is empty
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }
}

/// Verify a Merkle proof
pub fn verify_merkle_proof(
    leaf: &Fr,
    leaf_index: u64,
    siblings: &[Fr],
    root: &Fr,
) -> bool {
    if siblings.len() != TREE_DEPTH {
        return false;
    }

    let mut current = *leaf;
    let mut index = leaf_index;

    for sibling in siblings.iter() {
        let is_right = index % 2 == 1;

        current = if is_right {
            poseidon_hash2(sibling, &current)
        } else {
            poseidon_hash2(&current, sibling)
        };

        index /= 2;
    }

    current == *root
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use rand::rngs::OsRng;

    #[test]
    fn test_empty_tree() {
        let tree = PoseidonMerkleTree::new();
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        // Root should be zero hash at depth 20
        let expected_root = get_zero_hash(TREE_DEPTH);
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn test_insert_single_leaf() {
        let mut tree = PoseidonMerkleTree::new();
        let leaf = Fr::from(12345u64);

        let index = tree.insert(leaf).unwrap();
        assert_eq!(index, 0);
        assert_eq!(tree.len(), 1);

        // Root should change
        assert_ne!(tree.root(), get_zero_hash(TREE_DEPTH));
    }

    #[test]
    fn test_deterministic_root() {
        let leaf = Fr::from(42u64);

        let mut tree1 = PoseidonMerkleTree::new();
        let mut tree2 = PoseidonMerkleTree::new();

        tree1.insert(leaf).unwrap();
        tree2.insert(leaf).unwrap();

        assert_eq!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_different_leaves_different_roots() {
        let mut tree1 = PoseidonMerkleTree::new();
        let mut tree2 = PoseidonMerkleTree::new();

        tree1.insert(Fr::from(1u64)).unwrap();
        tree2.insert(Fr::from(2u64)).unwrap();

        assert_ne!(tree1.root(), tree2.root());
    }

    #[test]
    fn test_proof_generation_and_verification() {
        let mut tree = PoseidonMerkleTree::new();

        // Insert some leaves
        for i in 0..4 {
            tree.insert(Fr::from(i as u64)).unwrap();
        }

        // Generate proof for each leaf
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            let leaf = tree.get_leaf(i).unwrap();

            // Verify the proof
            assert!(proof.verify(&leaf, &tree.root()));
        }
    }

    #[test]
    fn test_proof_fails_with_wrong_leaf() {
        let mut tree = PoseidonMerkleTree::new();
        tree.insert(Fr::from(100u64)).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        let wrong_leaf = Fr::from(999u64);

        assert!(!proof.verify(&wrong_leaf, &tree.root()));
    }

    #[test]
    fn test_proof_fails_with_wrong_root() {
        let mut tree = PoseidonMerkleTree::new();
        tree.insert(Fr::from(100u64)).unwrap();

        let proof = tree.generate_proof(0).unwrap();
        let leaf = tree.get_leaf(0).unwrap();
        let wrong_root = Fr::from(999u64);

        assert!(!proof.verify(&leaf, &wrong_root));
    }

    #[test]
    fn test_many_insertions() {
        let mut tree = PoseidonMerkleTree::new();

        for i in 0..100 {
            let leaf = Fr::from(i as u64);
            tree.insert(leaf).unwrap();
        }

        assert_eq!(tree.len(), 100);

        // Verify proofs for some leaves
        for i in [0, 50, 99] {
            let proof = tree.generate_proof(i).unwrap();
            let leaf = tree.get_leaf(i).unwrap();
            assert!(proof.verify(&leaf, &tree.root()));
        }
    }

    #[test]
    fn test_random_leaves() {
        let mut tree = PoseidonMerkleTree::new();

        let leaves: Vec<Fr> = (0..10).map(|_| Fr::rand(&mut OsRng)).collect();

        for leaf in &leaves {
            tree.insert(*leaf).unwrap();
        }

        // All proofs should verify
        for i in 0..10 {
            let proof = tree.generate_proof(i).unwrap();
            let leaf = tree.get_leaf(i).unwrap();
            assert!(proof.verify(&leaf, &tree.root()));
        }
    }

    #[test]
    fn test_verify_merkle_proof_function() {
        let mut tree = PoseidonMerkleTree::new();

        for i in 0..5 {
            tree.insert(Fr::from(i as u64)).unwrap();
        }

        let proof = tree.generate_proof(2).unwrap();
        let leaf = tree.get_leaf(2).unwrap();

        assert!(verify_merkle_proof(&leaf, 2, &proof.siblings, &tree.root()));
    }
}
