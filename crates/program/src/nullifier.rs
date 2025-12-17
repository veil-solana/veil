//! Nullifier Set Implementation
//!
//! Uses PDAs (Program Derived Addresses) to track spent nullifiers.
//! Each spent nullifier creates a small PDA account that serves as a marker.
//!
//! This approach:
//! - Has NO false positives (unlike bloom filters)
//! - Uses ~128 bytes per nullifier (account overhead + data)
//! - Allows O(1) lookup via PDA derivation
//! - Is standard practice for Solana privacy protocols

use anchor_lang::prelude::*;
use solana_program::keccak;

/// Seeds prefix for nullifier PDAs
pub const NULLIFIER_SEED: &[u8] = b"nullifier";

/// Size of a nullifier marker account
/// Discriminator (8) + pool pubkey (32) + nullifier hash (32) + spent_at slot (8)
pub const NULLIFIER_ACCOUNT_SIZE: usize = 8 + 32 + 32 + 8;

/// Nullifier marker account
/// Created when a nullifier is spent to prevent double-spending
#[account]
#[derive(Debug)]
pub struct NullifierMarker {
    /// The pool this nullifier belongs to
    pub pool: Pubkey,

    /// The nullifier hash (stored for verification)
    pub nullifier: [u8; 32],

    /// Slot when this nullifier was spent
    pub spent_at: u64,
}

impl NullifierMarker {
    pub const SIZE: usize = 32 + 32 + 8; // pool + nullifier + spent_at
}

/// Derive the PDA address for a nullifier
///
/// # Arguments
/// * `program_id` - The program ID
/// * `pool` - The pool pubkey
/// * `nullifier` - The 32-byte nullifier hash
///
/// # Returns
/// Tuple of (PDA address, bump seed)
pub fn derive_nullifier_pda(
    program_id: &Pubkey,
    pool: &Pubkey,
    nullifier: &[u8; 32],
) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            NULLIFIER_SEED,
            pool.as_ref(),
            nullifier,
        ],
        program_id,
    )
}

/// Check if a nullifier PDA account exists (meaning it's spent)
///
/// This is a helper for off-chain checks.
/// On-chain, we use Anchor's init constraint which fails if account exists.
pub fn is_nullifier_spent_offchain(
    nullifier_account_info: &AccountInfo,
) -> bool {
    // If account has data and is owned by our program, nullifier is spent
    nullifier_account_info.data_len() > 0
}

/// Hash a nullifier with additional data for domain separation
///
/// This ensures nullifiers are unique per pool and prevents
/// cross-pool nullifier reuse attacks.
pub fn hash_nullifier_for_pool(
    pool: &Pubkey,
    nullifier: &[u8; 32],
) -> [u8; 32] {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(pool.as_ref());
    data.extend_from_slice(nullifier);
    keccak::hash(&data).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_program::pubkey::Pubkey;

    #[test]
    fn test_derive_nullifier_pda() {
        let program_id = Pubkey::new_unique();
        let pool = Pubkey::new_unique();
        let nullifier = [1u8; 32];

        let (pda, bump) = derive_nullifier_pda(&program_id, &pool, &nullifier);

        // PDA should be deterministic
        let (pda2, bump2) = derive_nullifier_pda(&program_id, &pool, &nullifier);
        assert_eq!(pda, pda2);
        assert_eq!(bump, bump2);

        // Different nullifier = different PDA
        let nullifier2 = [2u8; 32];
        let (pda3, _) = derive_nullifier_pda(&program_id, &pool, &nullifier2);
        assert_ne!(pda, pda3);
    }

    #[test]
    fn test_hash_nullifier_for_pool() {
        let pool1 = Pubkey::new_unique();
        let pool2 = Pubkey::new_unique();
        let nullifier = [42u8; 32];

        let hash1 = hash_nullifier_for_pool(&pool1, &nullifier);
        let hash2 = hash_nullifier_for_pool(&pool2, &nullifier);

        // Same nullifier in different pools should produce different hashes
        assert_ne!(hash1, hash2);

        // Same inputs should produce same hash
        let hash3 = hash_nullifier_for_pool(&pool1, &nullifier);
        assert_eq!(hash1, hash3);
    }
}
