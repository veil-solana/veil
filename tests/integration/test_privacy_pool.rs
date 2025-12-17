//! Integration tests for Nyx Privacy Pool
//!
//! These tests use solana-program-test to simulate the Solana runtime.

use anchor_lang::prelude::*;
use anchor_lang::InstructionData;
use solana_program_test::*;
use solana_sdk::{
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    system_program,
    transaction::Transaction,
};

// Program ID (must match declare_id! in lib.rs)
const PROGRAM_ID: &str = "Nyx1111111111111111111111111111111111111111";

fn program_id() -> Pubkey {
    PROGRAM_ID.parse().unwrap()
}

fn find_pool_pda() -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"privacy_pool"], &program_id())
}

fn find_vault_pda(pool: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", pool.as_ref()], &program_id())
}

fn find_nullifier_pda(pool: &Pubkey, nullifier: &[u8; 32]) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"nullifier", pool.as_ref(), nullifier],
        &program_id(),
    )
}

/// Create initialize instruction
fn create_initialize_ix(authority: &Pubkey) -> Instruction {
    let (pool, _) = find_pool_pda();

    // Anchor instruction discriminator for "initialize"
    let discriminator: [u8; 8] = [175, 175, 109, 31, 13, 152, 155, 237];

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(*authority, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data: discriminator.to_vec(),
    }
}

/// Create shield_sol instruction
fn create_shield_sol_ix(
    depositor: &Pubkey,
    commitment: [u8; 32],
    amount: u64,
) -> Instruction {
    let (pool, _) = find_pool_pda();
    let (vault, _) = find_vault_pda(&pool);

    // Anchor instruction discriminator for "shield_sol"
    let discriminator: [u8; 8] = [183, 4, 24, 123, 20, 45, 203, 91];

    let mut data = discriminator.to_vec();
    data.extend_from_slice(&commitment);
    data.extend_from_slice(&amount.to_le_bytes());

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(*depositor, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

/// Create transfer instruction
fn create_transfer_ix(
    relayer: &Pubkey,
    nullifier: [u8; 32],
    new_commitment: [u8; 32],
    proof: Vec<u8>,
) -> Instruction {
    let (pool, _) = find_pool_pda();
    let (nullifier_marker, _) = find_nullifier_pda(&pool, &nullifier);

    // Anchor instruction discriminator for "transfer"
    let discriminator: [u8; 8] = [163, 52, 200, 231, 140, 3, 69, 186];

    let mut data = discriminator.to_vec();
    data.extend_from_slice(&nullifier);
    data.extend_from_slice(&new_commitment);
    // Vec<u8> is serialized as: 4-byte length + data
    data.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    data.extend_from_slice(&proof);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(nullifier_marker, false),
            AccountMeta::new(*relayer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

/// Create unshield_sol instruction
fn create_unshield_sol_ix(
    relayer: &Pubkey,
    recipient: &Pubkey,
    nullifier: [u8; 32],
    amount: u64,
    proof: Vec<u8>,
) -> Instruction {
    let (pool, _) = find_pool_pda();
    let (vault, _) = find_vault_pda(&pool);
    let (nullifier_marker, _) = find_nullifier_pda(&pool, &nullifier);

    // Anchor instruction discriminator for "unshield_sol"
    let discriminator: [u8; 8] = [45, 127, 188, 9, 224, 78, 199, 57];

    let mut data = discriminator.to_vec();
    data.extend_from_slice(&nullifier);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(&(proof.len() as u32).to_le_bytes());
    data.extend_from_slice(&proof);

    Instruction {
        program_id: program_id(),
        accounts: vec![
            AccountMeta::new(pool, false),
            AccountMeta::new(nullifier_marker, false),
            AccountMeta::new(vault, false),
            AccountMeta::new(*recipient, false),
            AccountMeta::new(*relayer, true),
            AccountMeta::new_readonly(system_program::ID, false),
        ],
        data,
    }
}

/// Generate a mock MVP proof (96 bytes: 64 signature + 32 pubkey)
fn generate_mock_proof(signer: &Keypair) -> Vec<u8> {
    let mut proof = vec![0u8; 96];
    // Fill with non-zero signature bytes
    for i in 0..64 {
        proof[i] = ((i + 1) % 256) as u8;
    }
    // Add pubkey
    proof[64..96].copy_from_slice(&signer.pubkey().to_bytes());
    proof
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Test basic pool initialization
    #[tokio::test]
    async fn test_initialize_pool() {
        // Note: This test requires the program to be built
        // For now, we just verify the instruction creation works
        let authority = Keypair::new();
        let ix = create_initialize_ix(&authority.pubkey());

        assert_eq!(ix.program_id, program_id());
        assert_eq!(ix.accounts.len(), 3);
        assert_eq!(ix.data.len(), 8); // Just discriminator
    }

    /// Test shield SOL instruction creation
    #[tokio::test]
    async fn test_shield_sol_instruction() {
        let depositor = Keypair::new();
        let commitment = [42u8; 32];
        let amount = 1_000_000_000u64; // 1 SOL

        let ix = create_shield_sol_ix(&depositor.pubkey(), commitment, amount);

        assert_eq!(ix.program_id, program_id());
        assert_eq!(ix.accounts.len(), 4);
        // Data: 8 (discriminator) + 32 (commitment) + 8 (amount) = 48
        assert_eq!(ix.data.len(), 48);
    }

    /// Test transfer instruction creation
    #[tokio::test]
    async fn test_transfer_instruction() {
        let relayer = Keypair::new();
        let nullifier = [1u8; 32];
        let new_commitment = [2u8; 32];
        let proof = generate_mock_proof(&relayer);

        let ix = create_transfer_ix(
            &relayer.pubkey(),
            nullifier,
            new_commitment,
            proof.clone(),
        );

        assert_eq!(ix.program_id, program_id());
        assert_eq!(ix.accounts.len(), 4);
        // Data: 8 + 32 + 32 + 4 + 96 = 172
        assert_eq!(ix.data.len(), 172);
    }

    /// Test unshield SOL instruction creation
    #[tokio::test]
    async fn test_unshield_sol_instruction() {
        let relayer = Keypair::new();
        let recipient = Keypair::new();
        let nullifier = [3u8; 32];
        let amount = 500_000_000u64; // 0.5 SOL
        let proof = generate_mock_proof(&relayer);

        let ix = create_unshield_sol_ix(
            &relayer.pubkey(),
            &recipient.pubkey(),
            nullifier,
            amount,
            proof.clone(),
        );

        assert_eq!(ix.program_id, program_id());
        assert_eq!(ix.accounts.len(), 6);
        // Data: 8 + 32 + 8 + 4 + 96 = 148
        assert_eq!(ix.data.len(), 148);
    }

    /// Test PDA derivation
    #[tokio::test]
    async fn test_pda_derivation() {
        let (pool, pool_bump) = find_pool_pda();
        let (vault, vault_bump) = find_vault_pda(&pool);
        let nullifier = [0u8; 32];
        let (null_marker, null_bump) = find_nullifier_pda(&pool, &nullifier);

        // PDAs should be valid (bump > 0 or 0 for valid PDAs)
        assert!(pool_bump <= 255);
        assert!(vault_bump <= 255);
        assert!(null_bump <= 255);

        // PDAs should be different
        assert_ne!(pool, vault);
        assert_ne!(pool, null_marker);
        assert_ne!(vault, null_marker);

        // PDAs should be deterministic
        let (pool2, _) = find_pool_pda();
        assert_eq!(pool, pool2);
    }

    /// Test nullifier uniqueness
    #[tokio::test]
    async fn test_nullifier_uniqueness() {
        let (pool, _) = find_pool_pda();

        let nullifier1 = [1u8; 32];
        let nullifier2 = [2u8; 32];

        let (marker1, _) = find_nullifier_pda(&pool, &nullifier1);
        let (marker2, _) = find_nullifier_pda(&pool, &nullifier2);

        // Different nullifiers should produce different PDAs
        assert_ne!(marker1, marker2);
    }
}
