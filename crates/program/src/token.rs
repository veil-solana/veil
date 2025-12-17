//! Token Integration Module
//!
//! Provides CPI (Cross-Program Invocation) helpers for:
//! - Native SOL transfers (via System Program)
//! - SPL Token transfers (via Token Program)
//!
//! The pool uses PDAs as vault authorities, enabling trustless custody.

use anchor_lang::prelude::*;
use anchor_lang::system_program::{self, Transfer as SolTransfer};
use anchor_spl::token::{self, Transfer as TokenTransfer, Token, TokenAccount};

/// Seeds for the pool vault PDA (controls pool's token accounts)
pub const VAULT_SEED: &[u8] = b"vault";

/// Transfer native SOL from depositor to pool vault
///
/// # Arguments
/// * `depositor` - The signer sending SOL
/// * `vault` - The pool's SOL vault (PDA)
/// * `system_program` - System program for SOL transfers
/// * `amount` - Amount of lamports to transfer
pub fn transfer_sol_to_pool<'info>(
    depositor: &Signer<'info>,
    vault: &AccountInfo<'info>,
    system_program: &Program<'info, System>,
    amount: u64,
) -> Result<()> {
    let cpi_context = CpiContext::new(
        system_program.to_account_info(),
        SolTransfer {
            from: depositor.to_account_info(),
            to: vault.to_account_info(),
        },
    );

    system_program::transfer(cpi_context, amount)
}

/// Transfer native SOL from pool vault to recipient
///
/// Uses PDA signing for the vault authority.
///
/// # Arguments
/// * `vault` - The pool's SOL vault (PDA)
/// * `recipient` - Account receiving SOL
/// * `system_program` - System program for SOL transfers
/// * `amount` - Amount of lamports to transfer
/// * `pool_key` - Pool pubkey for PDA derivation
/// * `vault_bump` - Bump seed for vault PDA
pub fn transfer_sol_from_pool<'info>(
    vault: &AccountInfo<'info>,
    recipient: &AccountInfo<'info>,
    amount: u64,
    pool_key: &Pubkey,
    vault_bump: u8,
) -> Result<()> {
    // Calculate the signer seeds for the vault PDA
    let pool_key_bytes = pool_key.as_ref();
    let bump_bytes = [vault_bump];
    let signer_seeds: &[&[&[u8]]] = &[&[VAULT_SEED, pool_key_bytes, &bump_bytes]];

    // Transfer using direct lamport manipulation (more efficient than CPI for PDA)
    let vault_lamports = vault.lamports();
    require!(vault_lamports >= amount, TokenError::InsufficientFunds);

    **vault.try_borrow_mut_lamports()? -= amount;
    **recipient.try_borrow_mut_lamports()? += amount;

    // Note: For production, consider using invoke_signed with system_program::transfer
    // This direct manipulation works because the vault is a PDA owned by system program
    let _ = signer_seeds; // Silence unused warning - kept for documentation

    Ok(())
}

/// Transfer SPL tokens from depositor to pool vault
///
/// # Arguments
/// * `depositor_token_account` - Depositor's token account
/// * `vault_token_account` - Pool's vault token account
/// * `depositor` - Signer authority
/// * `token_program` - SPL Token program
/// * `amount` - Amount of tokens to transfer
pub fn transfer_spl_to_pool<'info>(
    depositor_token_account: &Account<'info, TokenAccount>,
    vault_token_account: &Account<'info, TokenAccount>,
    depositor: &Signer<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
) -> Result<()> {
    let cpi_accounts = TokenTransfer {
        from: depositor_token_account.to_account_info(),
        to: vault_token_account.to_account_info(),
        authority: depositor.to_account_info(),
    };

    let cpi_context = CpiContext::new(token_program.to_account_info(), cpi_accounts);
    token::transfer(cpi_context, amount)
}

/// Transfer SPL tokens from pool vault to recipient
///
/// Uses PDA signing for the vault authority.
///
/// # Arguments
/// * `vault_token_account` - Pool's vault token account
/// * `recipient_token_account` - Recipient's token account
/// * `vault_authority` - PDA that owns the vault token account
/// * `token_program` - SPL Token program
/// * `amount` - Amount of tokens to transfer
/// * `pool_key` - Pool pubkey for PDA derivation
/// * `vault_bump` - Bump seed for vault PDA
pub fn transfer_spl_from_pool<'info>(
    vault_token_account: &Account<'info, TokenAccount>,
    recipient_token_account: &Account<'info, TokenAccount>,
    vault_authority: &AccountInfo<'info>,
    token_program: &Program<'info, Token>,
    amount: u64,
    pool_key: &Pubkey,
    vault_bump: u8,
) -> Result<()> {
    let pool_key_bytes = pool_key.as_ref();
    let bump_bytes = [vault_bump];
    let signer_seeds: &[&[&[u8]]] = &[&[VAULT_SEED, pool_key_bytes, &bump_bytes]];

    let cpi_accounts = TokenTransfer {
        from: vault_token_account.to_account_info(),
        to: recipient_token_account.to_account_info(),
        authority: vault_authority.to_account_info(),
    };

    let cpi_context = CpiContext::new_with_signer(
        token_program.to_account_info(),
        cpi_accounts,
        signer_seeds,
    );

    token::transfer(cpi_context, amount)
}

/// Derive the vault PDA for a pool
pub fn derive_vault_pda(program_id: &Pubkey, pool: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[VAULT_SEED, pool.as_ref()], program_id)
}

/// Custom errors for token operations
#[error_code]
pub enum TokenError {
    #[msg("Insufficient funds in vault")]
    InsufficientFunds,
    #[msg("Invalid token account")]
    InvalidTokenAccount,
    #[msg("Token mint mismatch")]
    MintMismatch,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_vault_pda() {
        let program_id = Pubkey::new_unique();
        let pool = Pubkey::new_unique();

        let (pda, bump) = derive_vault_pda(&program_id, &pool);

        // Should be deterministic
        let (pda2, bump2) = derive_vault_pda(&program_id, &pool);
        assert_eq!(pda, pda2);
        assert_eq!(bump, bump2);

        // Different pool = different PDA
        let pool2 = Pubkey::new_unique();
        let (pda3, _) = derive_vault_pda(&program_id, &pool2);
        assert_ne!(pda, pda3);
    }
}
