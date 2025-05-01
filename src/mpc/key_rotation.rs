// Key Rotation for MPC
//
// This module provides functionality for rotating MPC key shares securely.

use crate::mpc::{MPCCore, MPCError, MPCResult};
use crate::mpc::core::KeyShare;
use crate::mpc::ceremonies::{DKGCeremony, CeremonyStatus, Ceremony};
use crate::mpc::secure_storage::KeyShareStorage;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use sha2::Digest;

/// Key rotation status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyRotationStatus {
    /// Key rotation is pending
    Pending,
    
    /// Key rotation is in progress
    InProgress,
    
    /// Key rotation is completed
    Completed,
    
    /// Key rotation has failed
    Failed,
}

/// Key rotation record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyRotationRecord {
    /// Unique ID for this key rotation
    pub id: String,
    
    /// DKG ceremony ID
    pub ceremony_id: String,
    
    /// Timestamp when the key rotation was initiated
    pub initiated_at: u64,
    
    /// Timestamp when the key rotation was completed (if completed)
    pub completed_at: Option<u64>,
    
    /// Status of the key rotation
    pub status: KeyRotationStatus,
    
    /// Reason for the key rotation
    pub reason: String,
    
    /// Old key share hash (for verification)
    pub old_key_share_hash: String,
    
    /// New key share hash (for verification)
    pub new_key_share_hash: Option<String>,
}

/// Key rotation manager
pub struct KeyRotationManager {
    /// MPC core
    mpc_core: MPCCore,
    
    /// Path to the key rotation database
    db_path: String,
    
    /// Key share storage
    key_share_storage: KeyShareStorage,
    
    /// Current key rotation record
    current_rotation: Option<KeyRotationRecord>,
}

impl KeyRotationManager {
    /// Create a new key rotation manager
    pub fn new(
        mpc_core: MPCCore,
        db_path: String,
        key_share_storage: KeyShareStorage,
    ) -> MPCResult<Self> {
        let mut manager = Self {
            mpc_core,
            db_path: db_path.clone(),
            key_share_storage,
            current_rotation: None,
        };
        
        // Load current rotation if it exists
        if Path::new(&db_path).exists() {
            let data = fs::read(&db_path)
                .map_err(|e| MPCError::InternalError(format!("Failed to read key rotation database: {}", e)))?;
            
            let rotation: KeyRotationRecord = serde_json::from_slice(&data)
                .map_err(|e| MPCError::InternalError(format!("Failed to parse key rotation database: {}", e)))?;
            
            manager.current_rotation = Some(rotation);
        }
        
        Ok(manager)
    }
    
    /// Save the current key rotation record
    fn save_current_rotation(&self) -> MPCResult<()> {
        if let Some(rotation) = &self.current_rotation {
            let data = serde_json::to_vec(rotation)
                .map_err(|e| MPCError::InternalError(format!("Failed to serialize key rotation record: {}", e)))?;
            
            // Create parent directories if they don't exist
            if let Some(parent) = Path::new(&self.db_path).parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MPCError::InternalError(format!("Failed to create directories: {}", e)))?;
            }
            
            fs::write(&self.db_path, data)
                .map_err(|e| MPCError::InternalError(format!("Failed to write key rotation record: {}", e)))?;
        }
        
        Ok(())
    }
    
    /// Calculate a hash of a key share for verification
    fn hash_key_share(key_share: &KeyShare) -> MPCResult<String> {
        let data = serde_json::to_vec(key_share)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize key share: {}", e)))?;
        
        let mut hasher = sha2::Sha256::new();
        hasher.update(&data);
        let hash = hasher.finalize();
        
        Ok(hex::encode(hash))
    }
    
    /// Initiate a key rotation
    pub fn initiate_rotation(
        &mut self,
        reason: &str,
        old_key_share: &KeyShare,
        password: &str,
    ) -> MPCResult<DKGCeremony> {
        // Check if a rotation is already in progress
        if let Some(rotation) = &self.current_rotation {
            if rotation.status == KeyRotationStatus::Pending || rotation.status == KeyRotationStatus::InProgress {
                return Err(MPCError::InternalError("Key rotation already in progress".to_string()));
            }
        }
        
        // Generate a unique ID for the rotation
        let rotation_id = format!("rotation-{}", uuid::Uuid::new_v4());
        let ceremony_id = format!("dkg-{}", rotation_id);
        
        // Calculate the hash of the old key share
        let old_key_share_hash = Self::hash_key_share(old_key_share)?;
        
        // Create a key rotation record
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        let rotation = KeyRotationRecord {
            id: rotation_id,
            ceremony_id: ceremony_id.clone(),
            initiated_at: timestamp,
            completed_at: None,
            status: KeyRotationStatus::Pending,
            reason: reason.to_string(),
            old_key_share_hash,
            new_key_share_hash: None,
        };
        
        self.current_rotation = Some(rotation);
        self.save_current_rotation()?;
        
        // Create a backup of the old key share
        self.key_share_storage.create_backup()?;
        
        // Create a new DKG ceremony
        let config = self.mpc_core.get_config();
        let ceremony = DKGCeremony::new(
            self.mpc_core.clone(),
            config.parties,
            config.threshold
        );
        
        Ok(ceremony)
    }
    
    /// Start the key rotation
    pub fn start_rotation(&mut self, ceremony: &mut DKGCeremony) -> MPCResult<()> {
        // Check if a rotation is pending
        let rotation = match &mut self.current_rotation {
            Some(rotation) if rotation.status == KeyRotationStatus::Pending => rotation,
            _ => return Err(MPCError::InternalError("No pending key rotation".to_string())),
        };
        
        // Start the DKG ceremony
        Ceremony::start(ceremony)?;
        
        // Update the rotation status
        rotation.status = KeyRotationStatus::InProgress;
        self.save_current_rotation()?;
        
        Ok(())
    }
    
    /// Complete the key rotation
    pub fn complete_rotation(
        &mut self,
        ceremony: &DKGCeremony,
        password: &str,
    ) -> MPCResult<()> {
        // Check if a rotation is in progress
        let rotation = match &mut self.current_rotation {
            Some(rotation) if rotation.status == KeyRotationStatus::InProgress => rotation,
            _ => return Err(MPCError::InternalError("No key rotation in progress".to_string())),
        };
        
        // Check if the ceremony is completed
        if ceremony.status() != CeremonyStatus::Completed {
            return Err(MPCError::CeremonyError("DKG ceremony not completed".to_string()));
        }
        
        // Get the new key share
        let new_key_share = ceremony.get_key_share()?;
        
        // Calculate the hash of the new key share
        let new_key_share_hash = Self::hash_key_share(&new_key_share)?;
        
        // Save the new key share
        self.key_share_storage.save_key_share(&new_key_share, password)?;
        
        // Update the rotation record
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        rotation.completed_at = Some(timestamp);
        rotation.status = KeyRotationStatus::Completed;
        rotation.new_key_share_hash = Some(new_key_share_hash);
        
        self.save_current_rotation()?;
        
        Ok(())
    }
    
    /// Fail the key rotation
    pub fn fail_rotation(&mut self, reason: &str) -> MPCResult<()> {
        // Check if a rotation is in progress
        let rotation = match &mut self.current_rotation {
            Some(rotation) if rotation.status == KeyRotationStatus::Pending || rotation.status == KeyRotationStatus::InProgress => rotation,
            _ => return Err(MPCError::InternalError("No key rotation in progress".to_string())),
        };
        
        // Update the rotation status
        rotation.status = KeyRotationStatus::Failed;
        rotation.reason = format!("{} - Failed: {}", rotation.reason, reason);
        
        self.save_current_rotation()?;
        
        Ok(())
    }
    
    /// Get the current key rotation record
    pub fn get_current_rotation(&self) -> Option<&KeyRotationRecord> {
        self.current_rotation.as_ref()
    }
    
    /// Check if a key rotation is in progress
    pub fn is_rotation_in_progress(&self) -> bool {
        match &self.current_rotation {
            Some(rotation) => rotation.status == KeyRotationStatus::Pending || rotation.status == KeyRotationStatus::InProgress,
            None => false,
        }
    }
}
