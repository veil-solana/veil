//! Circuit gadgets for zkSNARK proofs
//!
//! This module contains constraint system implementations for:
//! - Poseidon hash function
//! - Merkle tree path verification

pub mod merkle;
pub mod poseidon;

pub use merkle::MerklePathGadget;
pub use poseidon::PoseidonGadget;
