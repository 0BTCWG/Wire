// Authentication for MPC Operators
//
// This module provides multi-factor authentication for MPC operators.

use crate::mpc::{MPCError, MPCResult};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use pbkdf2::pbkdf2;
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use totp_rs::{TOTP, Algorithm};
use qrcode::QrCode;
use qrcode::render::unicode::Dense1x2;

/// User role
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UserRole {
    /// Administrator (can manage users)
    Admin,
    
    /// Operator (can perform MPC operations)
    Operator,
    
    /// Observer (can view status but not perform operations)
    Observer,
}

/// User record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    /// Username
    pub username: String,
    
    /// Password hash
    pub password_hash: String,
    
    /// Salt for password hashing
    pub salt: [u8; 16],
    
    /// TOTP secret
    pub totp_secret: String,
    
    /// User role
    pub role: UserRole,
    
    /// Last login timestamp
    pub last_login: Option<u64>,
    
    /// Failed login attempts
    pub failed_attempts: u32,
    
    /// Locked until timestamp
    pub locked_until: Option<u64>,
    
    /// Created at timestamp
    pub created_at: u64,
    
    /// Updated at timestamp
    pub updated_at: u64,
}

/// Authentication manager
pub struct AuthManager {
    /// Path to the user database
    db_path: String,
    
    /// Users indexed by username
    users: std::collections::HashMap<String, User>,
    
    /// Maximum failed login attempts before locking
    max_failed_attempts: u32,
    
    /// Lock duration in seconds
    lock_duration: u64,
}

impl AuthManager {
    /// Create a new authentication manager
    pub fn new(db_path: String, max_failed_attempts: u32, lock_duration: u64) -> MPCResult<Self> {
        let mut manager = Self {
            db_path,
            users: std::collections::HashMap::new(),
            max_failed_attempts,
            lock_duration,
        };
        
        // Load users if the database exists
        if Path::new(&manager.db_path).exists() {
            manager.load_users()?;
        }
        
        Ok(manager)
    }
    
    /// Load users from the database
    fn load_users(&mut self) -> MPCResult<()> {
        let data = fs::read(&self.db_path)
            .map_err(|e| MPCError::InternalError(format!("Failed to read user database: {}", e)))?;
        
        let users: Vec<User> = serde_json::from_slice(&data)
            .map_err(|e| MPCError::InternalError(format!("Failed to parse user database: {}", e)))?;
        
        for user in users {
            self.users.insert(user.username.clone(), user);
        }
        
        Ok(())
    }
    
    /// Save users to the database
    fn save_users(&self) -> MPCResult<()> {
        let users: Vec<User> = self.users.values().cloned().collect();
        
        let data = serde_json::to_vec(&users)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize user database: {}", e)))?;
        
        // Create parent directories if they don't exist
        if let Some(parent) = Path::new(&self.db_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| MPCError::InternalError(format!("Failed to create directories: {}", e)))?;
        }
        
        fs::write(&self.db_path, data)
            .map_err(|e| MPCError::InternalError(format!("Failed to write user database: {}", e)))?;
        
        Ok(())
    }
    
    /// Hash a password
    fn hash_password(password: &str, salt: &[u8; 16]) -> MPCResult<String> {
        let mut hash = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(
            password.as_bytes(),
            salt,
            100_000, // High iteration count for security
            &mut hash,
        ).map_err(|_| MPCError::InternalError("Failed to hash password".to_string()))?;
        
        Ok(hex::encode(hash))
    }
    
    /// Generate a TOTP secret
    fn generate_totp_secret() -> String {
        let mut secret = [0u8; 20];
        OsRng.fill_bytes(&mut secret);
        base32::encode(base32::Alphabet::RFC4648 { padding: false }, &secret)
    }
    
    /// Create a new user
    pub fn create_user(
        &mut self,
        username: &str,
        password: &str,
        role: UserRole,
    ) -> MPCResult<(String, String)> {
        // Check if the user already exists
        if self.users.contains_key(username) {
            return Err(MPCError::InternalError(format!("User {} already exists", username)));
        }
        
        // Generate salt
        let mut salt = [0u8; 16];
        OsRng.fill_bytes(&mut salt);
        
        // Hash password
        let password_hash = Self::hash_password(password, &salt)?;
        
        // Generate TOTP secret
        let totp_secret = Self::generate_totp_secret();
        
        // Create user
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        let user = User {
            username: username.to_string(),
            password_hash,
            salt,
            totp_secret: totp_secret.clone(),
            role,
            last_login: None,
            failed_attempts: 0,
            locked_until: None,
            created_at: timestamp,
            updated_at: timestamp,
        };
        
        // Add user
        self.users.insert(username.to_string(), user);
        self.save_users()?;
        
        // Generate TOTP URI for QR code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_secret.as_bytes(),
            Some("0BTC Wire MPC".to_string()),
            username.to_string(),
        ).map_err(|e| MPCError::InternalError(format!("Failed to create TOTP: {}", e)))?;
        
        let totp_uri = totp.get_url();
        
        Ok((totp_secret, totp_uri))
    }
    
    /// Generate a QR code for TOTP setup
    pub fn generate_totp_qr_code(&self, totp_uri: &str) -> MPCResult<String> {
        let code = QrCode::new(totp_uri)
            .map_err(|e| MPCError::InternalError(format!("Failed to create QR code: {}", e)))?;
        
        let qr_code = code.render::<Dense1x2>()
            .dark_color('█')
            .light_color('░')
            .build();
        
        Ok(qr_code)
    }
    
    /// Authenticate a user with password and TOTP
    pub fn authenticate(
        &mut self,
        username: &str,
        password: &str,
        totp_code: &str,
    ) -> MPCResult<bool> {
        // Get the user
        let user = match self.users.get_mut(username) {
            Some(user) => user,
            None => return Ok(false),
        };
        
        // Check if the user is locked
        if let Some(locked_until) = user.locked_until {
            let current_time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| MPCError::InternalError(format!("Failed to get current time: {}", e)))?
                .as_secs();
            
            if current_time < locked_until {
                return Ok(false);
            }
            
            // Reset lock if expired
            user.locked_until = None;
        }
        
        // Verify password
        let password_hash = Self::hash_password(password, &user.salt)?;
        
        if password_hash != user.password_hash {
            // Increment failed attempts
            user.failed_attempts += 1;
            
            // Lock the user if too many failed attempts
            if user.failed_attempts >= self.max_failed_attempts {
                let current_time = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| MPCError::InternalError(format!("Failed to get current time: {}", e)))?
                    .as_secs();
                
                user.locked_until = Some(current_time + self.lock_duration);
            }
            
            self.save_users()?;
            
            return Ok(false);
        }
        
        // Verify TOTP code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            user.totp_secret.as_bytes(),
            None,
            username.to_string(),
        ).map_err(|e| MPCError::InternalError(format!("Failed to create TOTP: {}", e)))?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get current time: {}", e)))?
            .as_secs();
        
        let is_valid = totp.check(totp_code, current_time);
        
        if !is_valid {
            // Increment failed attempts
            user.failed_attempts += 1;
            
            // Lock the user if too many failed attempts
            if user.failed_attempts >= self.max_failed_attempts {
                user.locked_until = Some(current_time + self.lock_duration);
            }
            
            self.save_users()?;
            
            return Ok(false);
        }
        
        // Authentication successful
        user.last_login = Some(current_time);
        user.failed_attempts = 0;
        user.updated_at = current_time;
        
        self.save_users()?;
        
        Ok(true)
    }
    
    /// Change a user's password
    pub fn change_password(
        &mut self,
        username: &str,
        old_password: &str,
        new_password: &str,
    ) -> MPCResult<bool> {
        // Get the user
        let user = match self.users.get_mut(username) {
            Some(user) => user,
            None => return Ok(false),
        };
        
        // Verify old password
        let old_password_hash = Self::hash_password(old_password, &user.salt)?;
        
        if old_password_hash != user.password_hash {
            return Ok(false);
        }
        
        // Generate new salt
        let mut new_salt = [0u8; 16];
        OsRng.fill_bytes(&mut new_salt);
        
        // Hash new password
        let new_password_hash = Self::hash_password(new_password, &new_salt)?;
        
        // Update user
        user.password_hash = new_password_hash;
        user.salt = new_salt;
        user.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        self.save_users()?;
        
        Ok(true)
    }
    
    /// Reset a user's TOTP
    pub fn reset_totp(&mut self, username: &str) -> MPCResult<(String, String)> {
        // Get the user
        let user = match self.users.get_mut(username) {
            Some(user) => user,
            None => return Err(MPCError::InternalError(format!("User {} not found", username))),
        };
        
        // Generate new TOTP secret
        let totp_secret = Self::generate_totp_secret();
        
        // Update user
        user.totp_secret = totp_secret.clone();
        user.updated_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        self.save_users()?;
        
        // Generate TOTP URI for QR code
        let totp = TOTP::new(
            Algorithm::SHA1,
            6,
            1,
            30,
            totp_secret.as_bytes(),
            Some("0BTC Wire MPC".to_string()),
            username.to_string(),
        ).map_err(|e| MPCError::InternalError(format!("Failed to create TOTP: {}", e)))?;
        
        let totp_uri = totp.get_url();
        
        Ok((totp_secret, totp_uri))
    }
    
    /// Get a user
    pub fn get_user(&self, username: &str) -> MPCResult<&User> {
        match self.users.get(username) {
            Some(user) => Ok(user),
            None => Err(MPCError::InternalError(format!("User {} not found", username))),
        }
    }
    
    /// Delete a user
    pub fn delete_user(&mut self, username: &str) -> MPCResult<bool> {
        let removed = self.users.remove(username).is_some();
        
        if removed {
            self.save_users()?;
        }
        
        Ok(removed)
    }
    
    /// List all users
    pub fn list_users(&self) -> Vec<&User> {
        self.users.values().collect()
    }
    
    /// Check if a user has a specific role
    pub fn has_role(&self, username: &str, role: UserRole) -> bool {
        match self.users.get(username) {
            Some(user) => user.role == role,
            None => false,
        }
    }
    
    /// Check if a user is an admin
    pub fn is_admin(&self, username: &str) -> bool {
        self.has_role(username, UserRole::Admin)
    }
    
    /// Check if a user is an operator
    pub fn is_operator(&self, username: &str) -> bool {
        self.has_role(username, UserRole::Operator) || self.has_role(username, UserRole::Admin)
    }
}
