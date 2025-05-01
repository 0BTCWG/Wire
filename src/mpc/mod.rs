// MPC (Multi-Party Computation) module for 0BTC Wire
//
// This module provides the core functionality for MPC operations required by the 0BTC Wire system,
// including distributed key generation, threshold signatures, and secure communication between
// MPC operator nodes.

mod core;
mod communication;
mod bitcoin;
mod ceremonies;
mod cli;
mod attestation;
mod burn;
mod fee;
mod secure_storage;
mod key_rotation;
mod auth;
mod bitcoin_security;

pub use core::{MPCCore, KeyShare, PublicKey};
pub use ceremonies::{DKGCeremony, SigningCeremony};
pub use bitcoin::{DepositMonitor, WithdrawalProcessor};
pub use attestation::{MintAttestation, AttestationManager};
pub use burn::{BurnProof, BurnManager};
pub use fee::{FeeUTXO, FeeManager};
pub use secure_storage::{SecureStorage, KeyShareStorage};
pub use key_rotation::{KeyRotationManager, KeyRotationStatus};
pub use auth::{AuthManager, User, UserRole};
pub use bitcoin_security::{BitcoinSecurityManager, ForkStatus, DoubleSpendStatus};

/// Error types for MPC operations
#[derive(Debug, thiserror::Error)]
pub enum MPCError {
    #[error("Invalid key share: {0}")]
    InvalidKeyShare(String),
    
    #[error("Invalid signature share: {0}")]
    InvalidSignatureShare(String),
    
    #[error("Communication error: {0}")]
    CommunicationError(String),
    
    #[error("Ceremony error: {0}")]
    CeremonyError(String),
    
    #[error("Threshold not met: required {required}, got {received}")]
    ThresholdNotMet { required: usize, received: usize },
    
    #[error("Bitcoin operation error: {0}")]
    BitcoinError(String),
    
    #[error("Authentication error: {0}")]
    AuthError(String),
    
    #[error("Security error: {0}")]
    SecurityError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
}

/// Result type for MPC operations
pub type MPCResult<T> = Result<T, MPCError>;

/// Configuration for MPC operations
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MPCConfig {
    /// Number of parties in the MPC setup
    pub parties: usize,
    
    /// Minimum number of parties required for signing
    pub threshold: usize,
    
    /// Network addresses of all parties
    pub party_addresses: Vec<String>,
    
    /// Index of this party (0-based)
    pub my_index: usize,
    
    /// Path to the key share file
    pub key_share_path: String,
    
    /// Path to the TLS certificate
    pub tls_cert_path: String,
    
    /// Path to the TLS key
    pub tls_key_path: String,
    
    /// Path to the user database
    pub user_db_path: String,
    
    /// Path to the security database
    pub security_db_path: String,
    
    /// Bitcoin nodes
    pub bitcoin_nodes: Vec<String>,
    
    /// Normal confirmation threshold
    pub normal_confirmations: u64,
    
    /// Fork confirmation threshold
    pub fork_confirmations: u64,
}

/// Initialize the MPC system with the given configuration
pub fn init(config: MPCConfig) -> MPCResult<MPCCore> {
    // This is a placeholder implementation
    // The actual implementation would initialize the MPC library and set up communication
    core::MPCCore::new(config)
}

/// Run the MPC operator CLI
pub fn run_cli() -> MPCResult<()> {
    cli::run_cli()
}
