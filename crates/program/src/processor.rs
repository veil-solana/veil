//! Instruction processors
//!
//! Contains the business logic for each instruction.

use anchor_lang::prelude::*;
use anchor_lang::system_program;
use anchor_spl::token;

use crate::instructions::NyxError;
use crate::merkle::TREE_DEPTH;
use crate::token as pool_token;
use crate::verification::{self, MvpProof};
use crate::{Initialize, Shield, ShieldSol, Transfer, Unshield, UnshieldSol};

/// Maximum leaves in tree (2^20)
const MAX_COMMITMENTS: u64 = 1 << TREE_DEPTH;

/// Process Initialize instruction
pub fn process_initialize(ctx: Context<Initialize>) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    // Initialize with real Merkle tree
    pool.initialize(ctx.accounts.authority.key(), ctx.bumps.pool);

    msg!("Privacy pool initialized");
    msg!("Initial root: {:?}", pool.current_root());
    Ok(())
}

/// Process Shield SOL instruction
pub fn process_shield_sol(ctx: Context<ShieldSol>, commitment: [u8; 32], amount: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    // Validate
    require!(amount > 0, NyxError::InvalidAmount);
    require!(
        pool.commitment_count() < MAX_COMMITMENTS,
        NyxError::PoolFull
    );

    // Transfer SOL from depositor to vault
    let cpi_context = CpiContext::new(
        ctx.accounts.system_program.to_account_info(),
        system_program::Transfer {
            from: ctx.accounts.depositor.to_account_info(),
            to: ctx.accounts.vault.to_account_info(),
        },
    );
    system_program::transfer(cpi_context, amount)?;

    // Add commitment to tree
    let leaf_index = pool.add_commitment(commitment)?;

    msg!("Shielded {} lamports at index {}", amount, leaf_index);
    msg!("New root: {:?}", pool.current_root());

    Ok(())
}

/// Process Shield SPL token instruction
pub fn process_shield(ctx: Context<Shield>, commitment: [u8; 32], amount: u64) -> Result<()> {
    let pool = &mut ctx.accounts.pool;

    // Validate
    require!(amount > 0, NyxError::InvalidAmount);
    require!(
        pool.commitment_count() < MAX_COMMITMENTS,
        NyxError::PoolFull
    );

    // Transfer SPL tokens from depositor to vault
    let cpi_accounts = token::Transfer {
        from: ctx.accounts.depositor_token_account.to_account_info(),
        to: ctx.accounts.vault_token_account.to_account_info(),
        authority: ctx.accounts.depositor.to_account_info(),
    };
    let cpi_context = CpiContext::new(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
    );
    token::transfer(cpi_context, amount)?;

    // Add commitment to tree
    let leaf_index = pool.add_commitment(commitment)?;

    msg!("Shielded {} tokens at index {}", amount, leaf_index);
    msg!("New root: {:?}", pool.current_root());

    Ok(())
}

/// Process Transfer instruction
pub fn process_transfer(
    ctx: Context<Transfer>,
    nullifier: [u8; 32],
    new_commitment: [u8; 32],
    proof: Vec<u8>,
) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let nullifier_marker = &mut ctx.accounts.nullifier_marker;
    let clock = Clock::get()?;

    // Validate proof length (96 bytes for MVP: 64 signature + 32 pubkey)
    require!(proof.len() >= MvpProof::SIZE, NyxError::InvalidProof);

    // Note: Double-spend prevention is handled by Anchor's init constraint

    // Get current root for verification
    let root = pool.current_root();

    // Verify the proof
    let valid = verification::verify_transfer_proof(
        &proof,
        &nullifier,
        &new_commitment,
        &root,
    )?;
    require!(valid, NyxError::InvalidProof);

    // Initialize nullifier marker (marks nullifier as spent)
    nullifier_marker.pool = pool.key();
    nullifier_marker.nullifier = nullifier;
    nullifier_marker.spent_at = clock.slot;

    // Record in pool stats
    pool.record_nullifier_spent();

    // Add new commitment
    let leaf_index = pool.add_commitment(new_commitment)?;

    msg!("Private transfer complete");
    msg!("New commitment at index {}", leaf_index);
    msg!("Nullifier spent at slot {}", clock.slot);

    Ok(())
}

/// Process Unshield SOL instruction
pub fn process_unshield_sol(
    ctx: Context<UnshieldSol>,
    nullifier: [u8; 32],
    amount: u64,
    proof: Vec<u8>,
) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let nullifier_marker = &mut ctx.accounts.nullifier_marker;
    let clock = Clock::get()?;

    // Validate
    require!(amount > 0, NyxError::InvalidAmount);
    require!(proof.len() >= MvpProof::SIZE, NyxError::InvalidProof);

    // Note: Double-spend prevention is handled by Anchor's init constraint

    // Get current root for verification
    let root = pool.current_root();
    let recipient_key = ctx.accounts.recipient.key();

    // Verify the proof
    let valid = verification::verify_unshield_proof(
        &proof,
        &nullifier,
        &recipient_key,
        amount,
        &root,
    )?;
    require!(valid, NyxError::InvalidProof);

    // Initialize nullifier marker (marks nullifier as spent)
    nullifier_marker.pool = pool.key();
    nullifier_marker.nullifier = nullifier;
    nullifier_marker.spent_at = clock.slot;

    // Record in pool stats
    pool.record_nullifier_spent();

    // Transfer SOL from vault to recipient
    let vault = &ctx.accounts.vault;
    let recipient = &ctx.accounts.recipient;

    let vault_lamports = vault.lamports();
    require!(vault_lamports >= amount, pool_token::TokenError::InsufficientFunds);

    **vault.try_borrow_mut_lamports()? -= amount;
    **recipient.try_borrow_mut_lamports()? += amount;

    msg!("Unshielded {} lamports", amount);
    msg!("Nullifier spent at slot {}", clock.slot);

    Ok(())
}

/// Process Unshield SPL token instruction
pub fn process_unshield(
    ctx: Context<Unshield>,
    nullifier: [u8; 32],
    amount: u64,
    proof: Vec<u8>,
) -> Result<()> {
    let pool = &mut ctx.accounts.pool;
    let nullifier_marker = &mut ctx.accounts.nullifier_marker;
    let clock = Clock::get()?;

    // Validate
    require!(amount > 0, NyxError::InvalidAmount);
    require!(proof.len() >= MvpProof::SIZE, NyxError::InvalidProof);

    // Note: Double-spend prevention is handled by Anchor's init constraint

    // Get current root for verification
    let root = pool.current_root();
    // For SPL tokens, use the token account owner as recipient
    let recipient_key = ctx.accounts.recipient_token_account.owner;

    // Verify the proof
    let valid = verification::verify_unshield_proof(
        &proof,
        &nullifier,
        &recipient_key,
        amount,
        &root,
    )?;
    require!(valid, NyxError::InvalidProof);

    // Initialize nullifier marker (marks nullifier as spent)
    nullifier_marker.pool = pool.key();
    nullifier_marker.nullifier = nullifier;
    nullifier_marker.spent_at = clock.slot;

    // Record in pool stats
    pool.record_nullifier_spent();

    // Transfer SPL tokens from vault to recipient
    let pool_key = pool.key();
    let vault_bump = ctx.bumps.vault_authority;
    let signer_seeds: &[&[&[u8]]] = &[&[
        pool_token::VAULT_SEED,
        pool_key.as_ref(),
        &[vault_bump],
    ]];

    let cpi_accounts = token::Transfer {
        from: ctx.accounts.vault_token_account.to_account_info(),
        to: ctx.accounts.recipient_token_account.to_account_info(),
        authority: ctx.accounts.vault_authority.to_account_info(),
    };
    let cpi_context = CpiContext::new_with_signer(
        ctx.accounts.token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );
    token::transfer(cpi_context, amount)?;

    msg!("Unshielded {} tokens", amount);
    msg!("Nullifier spent at slot {}", clock.slot);

    Ok(())
}
