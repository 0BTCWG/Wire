// Secure Storage for MPC Key Shares
//
// This module provides encrypted storage for MPC key shares and other sensitive data.

use crate::mpc::{MPCError, MPCResult};
use crate::mpc::core::KeyShare;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;
use pbkdf2::pbkdf2;
use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};

/// Encrypted data container
#[derive(Serialize, Deserialize)]
pub struct EncryptedData {
    /// Encrypted data bytes
    pub encrypted_data: Vec<u8>,
    
    /// Nonce used for encryption
    pub nonce: [u8; 12],
    
    /// Salt used for key derivation
    pub salt: [u8; 16],
    
    /// Number of PBKDF2 iterations
    pub iterations: u32,
}

/// Secure storage for sensitive data
pub struct SecureStorage {
    /// Path to the storage file
    storage_path: String,
}

impl SecureStorage {
    /// Create a new secure storage
    pub fn new(storage_path: String) -> Self {
        Self { storage_path }
    }
    
    /// Save data with encryption
    pub fn save_encrypted<T: Serialize>(&self, data: &T, password: &str) -> MPCResult<()> {
        // Generate random salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        
        // Derive encryption key from password
        let iterations = 100_000; // High iteration count for security
        let mut key_bytes = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            &salt,
            iterations,
            &mut key_bytes,
        ).map_err(|_| MPCError::InternalError("Failed to derive key".to_string()))?;
        
        let key = Key::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        
        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        // Serialize data
        let serialized = serde_json::to_vec(data)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize data: {}", e)))?;
        
        // Encrypt data
        let encrypted = cipher.encrypt(nonce, serialized.as_ref())
            .map_err(|e| MPCError::InternalError(format!("Failed to encrypt data: {}", e)))?;
        
        let encrypted_data = EncryptedData {
            encrypted_data: encrypted,
            nonce: nonce_bytes,
            salt,
            iterations,
        };
        
        // Save encrypted data
        let encrypted_bytes = serde_json::to_vec(&encrypted_data)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize encrypted data: {}", e)))?;
        
        // Create parent directories if they don't exist
        if let Some(parent) = Path::new(&self.storage_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| MPCError::InternalError(format!("Failed to create directories: {}", e)))?;
        }
        
        fs::write(&self.storage_path, encrypted_bytes)
            .map_err(|e| MPCError::InternalError(format!("Failed to write encrypted data: {}", e)))?;
        
        Ok(())
    }
    
    /// Load data with decryption
    pub fn load_encrypted<T: for<'de> Deserialize<'de>>(&self, password: &str) -> MPCResult<T> {
        // Read encrypted data
        let encrypted_bytes = fs::read(&self.storage_path)
            .map_err(|e| MPCError::InternalError(format!("Failed to read encrypted data: {}", e)))?;
        
        let encrypted_data: EncryptedData = serde_json::from_slice(&encrypted_bytes)
            .map_err(|e| MPCError::InternalError(format!("Failed to parse encrypted data: {}", e)))?;
        
        // Derive decryption key from password
        let mut key_bytes = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            &encrypted_data.salt,
            encrypted_data.iterations,
            &mut key_bytes,
        ).map_err(|_| MPCError::InternalError("Failed to derive key".to_string()))?;
        
        let key = Key::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        
        // Decrypt data
        let nonce = Nonce::from_slice(&encrypted_data.nonce);
        let decrypted = cipher.decrypt(nonce, encrypted_data.encrypted_data.as_ref())
            .map_err(|_| MPCError::InternalError("Failed to decrypt data (incorrect password?)".to_string()))?;
        
        // Deserialize data
        let data: T = serde_json::from_slice(&decrypted)
            .map_err(|e| MPCError::InternalError(format!("Failed to deserialize data: {}", e)))?;
        
        Ok(data)
    }
    
    /// Check if the storage file exists
    pub fn exists(&self) -> bool {
        Path::new(&self.storage_path).exists()
    }
    
    /// Create a backup of the storage file
    pub fn create_backup(&self) -> MPCResult<String> {
        if !self.exists() {
            return Err(MPCError::InternalError("Storage file does not exist".to_string()));
        }
        
        let backup_path = format!("{}.backup", self.storage_path);
        fs::copy(&self.storage_path, &backup_path)
            .map_err(|e| MPCError::InternalError(format!("Failed to create backup: {}", e)))?;
        
        Ok(backup_path)
    }
}

/// Secure storage for key shares
pub struct KeyShareStorage {
    /// Secure storage
    storage: SecureStorage,
}

impl KeyShareStorage {
    /// Create a new key share storage
    pub fn new(storage_path: String) -> Self {
        Self {
            storage: SecureStorage::new(storage_path),
        }
    }
    
    /// Save a key share with encryption
    pub fn save_key_share(&self, key_share: &KeyShare, password: &str) -> MPCResult<()> {
        self.storage.save_encrypted(key_share, password)
    }
    
    /// Load a key share with decryption
    pub fn load_key_share(&self, password: &str) -> MPCResult<KeyShare> {
        self.storage.load_encrypted(password)
    }
    
    /// Check if a key share exists
    pub fn exists(&self) -> bool {
        self.storage.exists()
    }
    
    /// Create a backup of the key share
    pub fn create_backup(&self) -> MPCResult<String> {
        self.storage.create_backup()
    }
}
