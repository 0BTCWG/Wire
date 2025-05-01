// Mint Attestation Workflow for 0BTC Wire
//
// This module implements the workflow for generating mint attestations
// for wrapped Bitcoin (wBTC) based on verified Bitcoin deposits.

use crate::mpc::{MPCCore, MPCError, MPCResult};
use crate::mpc::ceremonies::{SigningCeremony, Ceremony};
use crate::mpc::bitcoin::BitcoinDeposit;
use ed25519_dalek::{Signature as Ed25519Signature, VerifyingKey, Signature, Verifier};
use serde::{Deserialize, Serialize};
use serde_arrays;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a mint attestation for wrapped Bitcoin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MintAttestation {
    /// Unique ID for this attestation
    pub id: String,
    
    /// Bitcoin transaction ID of the deposit
    pub deposit_txid: String,
    
    /// Output index in the transaction
    pub deposit_vout: u32,
    
    /// Recipient's public key hash (for the 0BTC Wire system)
    pub recipient_pubkey_hash: [u8; 32],
    
    /// Amount in satoshis
    pub amount: u64,
    
    /// Nonce to prevent replay attacks
    pub nonce: u64,
    
    /// Ed25519 signature
    #[serde(with = "serde_arrays")]
    pub signature: [u8; 64],
    
    /// Expiry timestamp (Unix timestamp)
    pub expiry: u64,
    
    /// Creation timestamp (Unix timestamp)
    pub created_at: u64,
}

impl MintAttestation {
    /// Create a new mint attestation
    pub fn new(
        deposit_txid: String,
        deposit_vout: u32,
        recipient_pubkey_hash: [u8; 32],
        amount: u64,
        nonce: u64,
        signature: [u8; 64],
        expiry: u64,
    ) -> Self {
        let id = format!("att-{}", uuid::Uuid::new_v4());
        let created_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        
        Self {
            id,
            deposit_txid,
            deposit_vout,
            recipient_pubkey_hash,
            amount,
            nonce,
            signature,
            expiry,
            created_at,
        }
    }
    
    /// Serialize the attestation to bytes for signing
    pub fn to_signing_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        
        // Domain separator for mint attestations
        bytes.extend_from_slice(b"0BTC_WIRE_MINT_ATTESTATION");
        
        // Deposit transaction ID
        bytes.extend_from_slice(self.deposit_txid.as_bytes());
        
        // Deposit output index
        bytes.extend_from_slice(&self.deposit_vout.to_le_bytes());
        
        // Recipient's public key hash
        bytes.extend_from_slice(&self.recipient_pubkey_hash);
        
        // Amount
        bytes.extend_from_slice(&self.amount.to_le_bytes());
        
        // Nonce
        bytes.extend_from_slice(&self.nonce.to_le_bytes());
        
        // Expiry
        bytes.extend_from_slice(&self.expiry.to_le_bytes());
        
        bytes
    }
    
    /// Verify the attestation signature
    pub fn verify(&self, public_key: &[u8; 32]) -> bool {
        // Import the specific types we need from ed25519-dalek
        use ed25519_dalek::{Signature, VerifyingKey, Verifier};
        
        let signing_bytes = self.to_signing_bytes();
        
        // Try to convert the public key bytes to a VerifyingKey
        let verifying_key = match VerifyingKey::from_bytes(public_key) {
            Ok(pk) => pk,
            Err(_) => return false,
        };
        
        // Try to convert the signature bytes to a Signature
        // We need to handle the Result returned by from_bytes
        let signature = match Signature::try_from(&self.signature[..]) {
            Ok(sig) => sig,
            Err(_) => return false,
        };
        
        // Verify the signature
        verifying_key.verify(&signing_bytes, &signature).is_ok()
    }
}

/// Manager for mint attestations
pub struct AttestationManager {
    /// MPC core for cryptographic operations
    mpc_core: MPCCore,
    
    /// Database path for storing attestations
    db_path: String,
    
    /// Attestations indexed by ID
    attestations: HashMap<String, MintAttestation>,
    
    /// Current nonce for attestations
    current_nonce: u64,
    
    /// Attestation validity period in seconds
    validity_period: u64,
}

impl AttestationManager {
    /// Create a new attestation manager
    pub fn new(mpc_core: MPCCore, db_path: String, validity_period: u64) -> MPCResult<Self> {
        let mut manager = Self {
            mpc_core,
            db_path: db_path.clone(),
            attestations: HashMap::new(),
            current_nonce: 0,
            validity_period,
        };
        
        // Load attestations from database if it exists
        if Path::new(&db_path).exists() {
            manager.load_attestations()?;
        }
        
        Ok(manager)
    }
    
    /// Load attestations from the database
    fn load_attestations(&mut self) -> MPCResult<()> {
        let data = fs::read(&self.db_path)
            .map_err(|e| MPCError::InternalError(format!("Failed to read attestations database: {}", e)))?;
        
        let attestations: Vec<MintAttestation> = serde_json::from_slice(&data)
            .map_err(|e| MPCError::InternalError(format!("Failed to parse attestations database: {}", e)))?;
        
        // Find the highest nonce
        let mut max_nonce = 0;
        
        for attestation in attestations {
            if attestation.nonce > max_nonce {
                max_nonce = attestation.nonce;
            }
            
            self.attestations.insert(attestation.id.clone(), attestation);
        }
        
        self.current_nonce = max_nonce + 1;
        
        Ok(())
    }
    
    /// Save attestations to the database
    fn save_attestations(&self) -> MPCResult<()> {
        let attestations: Vec<MintAttestation> = self.attestations.values().cloned().collect();
        
        let data = serde_json::to_vec(&attestations)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize attestations: {}", e)))?;
        
        fs::write(&self.db_path, data)
            .map_err(|e| MPCError::InternalError(format!("Failed to write attestations database: {}", e)))?;
        
        Ok(())
    }
    
    /// Generate an attestation for a Bitcoin deposit
    pub fn generate_attestation(&mut self, deposit: &BitcoinDeposit) -> MPCResult<MintAttestation> {
        // Create a recipient public key hash array
        let mut recipient_pubkey_hash = [0u8; 32];
        if deposit.recipient_pubkey_hash.len() != 32 {
            return Err(MPCError::InternalError(format!(
                "Invalid recipient public key hash length: {} (expected 32)",
                deposit.recipient_pubkey_hash.len()
            )));
        }
        recipient_pubkey_hash.copy_from_slice(&deposit.recipient_pubkey_hash);
        
        // Calculate expiry timestamp
        let expiry = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs() + self.validity_period;
        
        // Create attestation without signature
        let attestation = MintAttestation::new(
            deposit.txid.clone(),
            deposit.vout,
            recipient_pubkey_hash,
            deposit.amount,
            self.current_nonce,
            [0u8; 64], // Placeholder signature
            expiry,
        );
        
        // Get signing bytes
        let signing_bytes = attestation.to_signing_bytes();
        
        // Create signing ceremony
        let mut ceremony = SigningCeremony::new(
            self.mpc_core.clone(),
            signing_bytes,
            self.mpc_core.get_config().parties,
            self.mpc_core.get_config().threshold,
        );
        
        // Start ceremony
        Ceremony::start(&mut ceremony)?;
        
        // Generate signature share
        let _signature_share = ceremony.generate_signature_share()?;
        
        // In a real implementation, this would wait for signature shares from other parties
        
        // Combine signature shares
        let signature = ceremony.combine_signature_shares()?;
        
        // Create attestation with signature
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(signature.to_bytes().as_slice());
        
        let attestation = MintAttestation::new(
            deposit.txid.clone(),
            deposit.vout,
            recipient_pubkey_hash,
            deposit.amount,
            self.current_nonce,
            signature_bytes,
            expiry,
        );
        
        // Increment nonce
        self.current_nonce += 1;
        
        // Store attestation
        self.attestations.insert(attestation.id.clone(), attestation.clone());
        
        // Save attestations to database
        self.save_attestations()?;
        
        Ok(attestation)
    }
    
    /// Get an attestation by ID
    pub fn get_attestation(&self, id: &str) -> Option<&MintAttestation> {
        self.attestations.get(id)
    }
    
    /// Get all attestations
    pub fn get_all_attestations(&self) -> Vec<&MintAttestation> {
        self.attestations.values().collect()
    }
    
    /// Get attestations for a specific deposit
    pub fn get_attestations_for_deposit(&self, txid: &str, vout: u32) -> Vec<&MintAttestation> {
        self.attestations.values()
            .filter(|a| a.deposit_txid == txid && a.deposit_vout == vout)
            .collect()
    }
    
    /// Check if an attestation is expired
    pub fn is_expired(&self, attestation: &MintAttestation) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        
        attestation.expiry < now
    }
    
    /// Remove expired attestations
    pub fn remove_expired_attestations(&mut self) -> MPCResult<Vec<String>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| std::time::Duration::from_secs(0))
            .as_secs();
        
        let expired_ids: Vec<String> = self.attestations.values()
            .filter(|a| a.expiry < now)
            .map(|a| a.id.clone())
            .collect();
        
        for id in &expired_ids {
            self.attestations.remove(id);
        }
        
        if !expired_ids.is_empty() {
            self.save_attestations()?;
        }
        
        Ok(expired_ids)
    }
}
