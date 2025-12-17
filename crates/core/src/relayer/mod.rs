//! Relayer Infrastructure
//!
//! This module provides client-side support for interacting with relayers.
//! Relayers are trusted third parties that submit private transactions on behalf
//! of users, paying for gas fees and receiving a fee in return.
//!
//! Key components:
//! - `RelayerClient`: Client for communicating with relayers
//! - `RelayRequest`: Transaction request to be submitted by a relayer
//! - `FeeEstimator`: Utility for estimating relayer fees
//!
//! Privacy model:
//! - Relayers can see the nullifier, new commitment, and proof
//! - Relayers CANNOT see the sender, recipient, or amount
//! - The user's IP address may be visible to the relayer (use Tor for anonymity)

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Default relayer fee in basis points (0.3%)
pub const DEFAULT_FEE_BPS: u16 = 30;

/// Maximum acceptable fee in basis points (5%)
pub const MAX_FEE_BPS: u16 = 500;

/// Errors that can occur during relayer operations
#[derive(Error, Debug)]
pub enum RelayerError {
    #[error("No relayers available")]
    NoRelayersAvailable,
    #[error("Relayer fee too high: {0} bps (max: {1} bps)")]
    FeeTooHigh(u16, u16),
    #[error("Network error: {0}")]
    NetworkError(String),
    #[error("Invalid response from relayer: {0}")]
    InvalidResponse(String),
    #[error("Transaction rejected: {0}")]
    TransactionRejected(String),
    #[error("Timeout waiting for confirmation")]
    Timeout,
    #[error("Proof invalid")]
    InvalidProof,
}

/// Status of a relay request
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RelayStatus {
    /// Request is pending submission
    Pending,
    /// Transaction has been submitted
    Submitted { signature: String },
    /// Transaction confirmed on-chain
    Confirmed { signature: String, slot: u64 },
    /// Transaction failed
    Failed { reason: String },
}

/// A request to relay a private transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayRequest {
    /// Type of operation (transfer, unshield)
    pub operation: OperationType,
    /// Nullifier being spent
    pub nullifier: [u8; 32],
    /// New commitment (for transfers) or recipient (for unshields)
    pub output: RelayOutput,
    /// zkSNARK proof (256 bytes for Groth16)
    pub proof: Vec<u8>,
    /// Merkle root the proof was generated against
    pub merkle_root: [u8; 32],
    /// Maximum fee the user is willing to pay (in lamports)
    pub max_fee: u64,
}

/// Type of relay operation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum OperationType {
    /// Private transfer (commitment to commitment)
    Transfer,
    /// Unshield (commitment to public account)
    UnshieldSol,
    /// Unshield SPL tokens
    UnshieldToken { mint: String },
}

/// Output of a relay operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RelayOutput {
    /// New commitment for transfers
    Commitment([u8; 32]),
    /// Recipient and amount for unshields
    Unshield {
        recipient: String, // Base58 Pubkey
        amount: u64,
    },
}

/// Response from a relayer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayResponse {
    /// Unique request ID
    pub request_id: String,
    /// Current status
    pub status: RelayStatus,
    /// Fee charged (in lamports)
    pub fee: u64,
    /// Estimated time to confirmation (seconds)
    pub estimated_confirmation_time: Option<u32>,
}

/// Information about a relayer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayerInfo {
    /// Relayer's public identifier
    pub id: String,
    /// API endpoint URL
    pub endpoint: String,
    /// Fee in basis points
    pub fee_bps: u16,
    /// Minimum transaction amount
    pub min_amount: u64,
    /// Supported operations
    pub supported_operations: Vec<OperationType>,
    /// Current status
    pub is_online: bool,
    /// Average confirmation time (seconds)
    pub avg_confirmation_time: u32,
}

/// Client for interacting with relayers
pub struct RelayerClient {
    /// List of known relayers
    relayers: Vec<RelayerInfo>,
    /// Maximum acceptable fee (basis points)
    max_fee_bps: u16,
    /// Request timeout (seconds)
    timeout_secs: u32,
}

impl Default for RelayerClient {
    fn default() -> Self {
        Self::new()
    }
}

impl RelayerClient {
    /// Create a new relayer client
    pub fn new() -> Self {
        Self {
            relayers: Vec::new(),
            max_fee_bps: MAX_FEE_BPS,
            timeout_secs: 60,
        }
    }

    /// Create client with custom settings
    pub fn with_settings(max_fee_bps: u16, timeout_secs: u32) -> Self {
        Self {
            relayers: Vec::new(),
            max_fee_bps,
            timeout_secs,
        }
    }

    /// Add a relayer to the client
    pub fn add_relayer(&mut self, relayer: RelayerInfo) {
        self.relayers.push(relayer);
    }

    /// Add the default mainnet relayers
    pub fn add_default_relayers(&mut self) {
        // TODO: Add actual relayer endpoints when deployed
        // For now, this is a placeholder for production relayers
        self.relayers.push(RelayerInfo {
            id: "nyx-relayer-1".to_string(),
            endpoint: "https://relayer1.nyx.network".to_string(),
            fee_bps: DEFAULT_FEE_BPS,
            min_amount: 10_000, // 0.00001 SOL
            supported_operations: vec![
                OperationType::Transfer,
                OperationType::UnshieldSol,
            ],
            is_online: false, // Will be updated on health check
            avg_confirmation_time: 5,
        });
    }

    /// Select the best relayer for a given operation
    ///
    /// Selection criteria:
    /// 1. Must support the operation type
    /// 2. Must be online
    /// 3. Fee must be within acceptable range
    /// 4. Prefer lower fees and faster confirmation
    pub fn select_relayer(&self, operation: &OperationType) -> Result<&RelayerInfo, RelayerError> {
        let eligible: Vec<_> = self.relayers.iter()
            .filter(|r| r.is_online)
            .filter(|r| r.supported_operations.contains(operation))
            .filter(|r| r.fee_bps <= self.max_fee_bps)
            .collect();

        if eligible.is_empty() {
            return Err(RelayerError::NoRelayersAvailable);
        }

        // Select by lowest fee, then fastest confirmation
        eligible.into_iter()
            .min_by_key(|r| (r.fee_bps, r.avg_confirmation_time))
            .ok_or(RelayerError::NoRelayersAvailable)
    }

    /// Estimate fee for a relay operation
    ///
    /// Returns (relayer_fee, network_fee) in lamports
    pub fn estimate_fee(&self, operation: &OperationType, amount: u64) -> Result<(u64, u64), RelayerError> {
        let relayer = self.select_relayer(operation)?;

        // Relayer fee = amount * fee_bps / 10000
        let relayer_fee = (amount as u128 * relayer.fee_bps as u128 / 10000) as u64;

        // Estimated network fee (transaction + account creation)
        let network_fee = match operation {
            OperationType::Transfer => 5_000, // ~5000 lamports
            OperationType::UnshieldSol => 5_000,
            OperationType::UnshieldToken { .. } => 10_000, // Includes ATA creation
        };

        Ok((relayer_fee, network_fee))
    }

    /// Submit a relay request (mock implementation)
    ///
    /// In production, this would:
    /// 1. Select a relayer
    /// 2. Send the request to the relayer's API
    /// 3. Wait for submission confirmation
    /// 4. Return the transaction signature
    pub async fn submit(&self, request: RelayRequest) -> Result<RelayResponse, RelayerError> {
        // Validate fee
        let (relayer_fee, _network_fee) = self.estimate_fee(&request.operation, self.get_amount(&request))?;
        if relayer_fee > request.max_fee {
            return Err(RelayerError::FeeTooHigh(
                (relayer_fee * 10000 / self.get_amount(&request)) as u16,
                self.max_fee_bps,
            ));
        }

        // Select relayer
        let _relayer = self.select_relayer(&request.operation)?;

        // In production, this would make an HTTP request to the relayer
        // For now, return a mock response
        Ok(RelayResponse {
            request_id: format!("req_{}", hex::encode(&request.nullifier[..8])),
            status: RelayStatus::Pending,
            fee: relayer_fee,
            estimated_confirmation_time: Some(5),
        })
    }

    /// Get the amount from a relay request
    fn get_amount(&self, request: &RelayRequest) -> u64 {
        match &request.output {
            RelayOutput::Commitment(_) => 1_000_000_000, // Default 1 SOL for transfers
            RelayOutput::Unshield { amount, .. } => *amount,
        }
    }
}

/// Fee estimator utility
pub struct FeeEstimator {
    /// Base fee in basis points
    pub base_fee_bps: u16,
    /// Network congestion multiplier (1.0 = normal)
    pub congestion_multiplier: f64,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self {
            base_fee_bps: DEFAULT_FEE_BPS,
            congestion_multiplier: 1.0,
        }
    }
}

impl FeeEstimator {
    /// Estimate total fee for an operation
    ///
    /// Returns total fee in lamports
    pub fn estimate(&self, amount: u64) -> u64 {
        let base_fee = (amount as u128 * self.base_fee_bps as u128 / 10000) as u64;
        let adjusted_fee = (base_fee as f64 * self.congestion_multiplier) as u64;

        // Minimum fee to cover network costs
        adjusted_fee.max(5000)
    }

    /// Calculate amount received after fees
    pub fn amount_after_fees(&self, amount: u64) -> u64 {
        let fee = self.estimate(amount);
        amount.saturating_sub(fee)
    }

    /// Calculate amount needed to receive a specific amount after fees
    pub fn amount_needed_for(&self, desired_amount: u64) -> u64 {
        // amount * (1 - fee_bps/10000) = desired
        // amount = desired / (1 - fee_bps/10000)
        // amount = desired * 10000 / (10000 - fee_bps)
        let adjusted_bps = (self.base_fee_bps as f64 * self.congestion_multiplier) as u64;
        (desired_amount as u128 * 10000 / (10000 - adjusted_bps as u128)) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fee_estimation() {
        let estimator = FeeEstimator::default();

        // 1 SOL should have ~0.3% fee
        let fee = estimator.estimate(1_000_000_000);
        assert_eq!(fee, 3_000_000); // 0.003 SOL

        // Small amounts should have minimum fee
        let small_fee = estimator.estimate(1000);
        assert_eq!(small_fee, 5000); // Minimum fee
    }

    #[test]
    fn test_amount_after_fees() {
        let estimator = FeeEstimator::default();

        // 1 SOL - 0.3% fee = 0.997 SOL
        let received = estimator.amount_after_fees(1_000_000_000);
        assert_eq!(received, 997_000_000);
    }

    #[test]
    fn test_relayer_selection() {
        let mut client = RelayerClient::new();

        // No relayers = error
        assert!(client.select_relayer(&OperationType::Transfer).is_err());

        // Add an offline relayer
        client.add_relayer(RelayerInfo {
            id: "offline".to_string(),
            endpoint: "https://offline.example.com".to_string(),
            fee_bps: 10,
            min_amount: 1000,
            supported_operations: vec![OperationType::Transfer],
            is_online: false,
            avg_confirmation_time: 5,
        });

        // Still no available relayers
        assert!(client.select_relayer(&OperationType::Transfer).is_err());

        // Add an online relayer
        client.add_relayer(RelayerInfo {
            id: "online".to_string(),
            endpoint: "https://online.example.com".to_string(),
            fee_bps: 30,
            min_amount: 1000,
            supported_operations: vec![OperationType::Transfer],
            is_online: true,
            avg_confirmation_time: 5,
        });

        // Now we can select
        let relayer = client.select_relayer(&OperationType::Transfer).unwrap();
        assert_eq!(relayer.id, "online");
    }
}
