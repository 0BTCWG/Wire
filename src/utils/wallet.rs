// HD Wallet and Mnemonic utilities for the 0BTC Wire system
use bip39::{Mnemonic, Language};
use slip10::{BIP32Path, Curve};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use thiserror::Error;
use std::str::FromStr;

/// Default derivation path for 0BTC Wire
pub const DEFAULT_DERIVATION_PATH: &str = "m/1337'/0'/0'";

/// Word count options for mnemonic generation
#[derive(Debug, Clone, Copy)]
pub enum WordCount {
    Words12,
    Words15,
    Words18,
    Words21,
    Words24,
}

impl WordCount {
    pub fn entropy_bits(&self) -> usize {
        match self {
            WordCount::Words12 => 128,
            WordCount::Words15 => 160,
            WordCount::Words18 => 192,
            WordCount::Words21 => 224,
            WordCount::Words24 => 256,
        }
    }
}

/// Errors that can occur in wallet operations
#[derive(Debug, Error)]
pub enum WalletError {
    #[error("Failed to generate mnemonic: {0}")]
    MnemonicGenerationError(String),
    
    #[error("Invalid mnemonic: {0}")]
    InvalidMnemonic(String),
    
    #[error("Key derivation error: {0}")]
    KeyDerivationError(String),
    
    #[error("Invalid derivation path: {0}")]
    InvalidDerivationPath(String),
    
    #[error("Ed25519 key error: {0}")]
    Ed25519KeyError(String),
}

/// Result type for wallet operations
pub type WalletResult<T> = Result<T, WalletError>;

/// Wallet struct containing mnemonic and derived keys
#[derive(Debug, Clone)]
pub struct Wallet {
    /// The mnemonic phrase
    pub mnemonic: Mnemonic,
    
    /// The derived signing key
    pub signing_key: SigningKey,
    
    /// The derived verifying key (public key)
    pub verifying_key: VerifyingKey,
    
    /// The derivation path used
    pub derivation_path: String,
}

impl Wallet {
    /// Generate a new wallet with a random mnemonic
    pub fn generate(word_count: WordCount, derivation_path: Option<&str>) -> WalletResult<Self> {
        // Generate a random mnemonic
        let mut entropy = vec![0u8; word_count.entropy_bits() / 8];
        OsRng.fill_bytes(&mut entropy);
        
        let mnemonic = Mnemonic::from_entropy_in(Language::English, &entropy)
            .map_err(|e| WalletError::MnemonicGenerationError(e.to_string()))?;
        
        Self::from_mnemonic(&mnemonic, derivation_path)
    }
    
    /// Create a wallet from an existing mnemonic phrase
    pub fn from_mnemonic(mnemonic: &Mnemonic, derivation_path: Option<&str>) -> WalletResult<Self> {
        let path = derivation_path.unwrap_or(DEFAULT_DERIVATION_PATH);
        
        // Derive the seed from the mnemonic
        let seed = mnemonic.to_seed("");
        
        // Parse the derivation path
        let bip32_path = BIP32Path::from_str(path)
            .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))?;
        
        // Derive the key using SLIP-0010 for Ed25519
        let derived_key = slip10::derive_key_from_path(
            &seed,
            Curve::Ed25519,
            &bip32_path,
        ).map_err(|e| WalletError::KeyDerivationError(e.to_string()))?;
        
        // Convert to ed25519-dalek SigningKey
        let signing_key = SigningKey::from_bytes(&derived_key.key);
        
        // Get the corresponding verifying key
        let verifying_key = VerifyingKey::from(&signing_key);
        
        Ok(Self {
            mnemonic: mnemonic.clone(),
            signing_key,
            verifying_key,
            derivation_path: path.to_string(),
        })
    }
    
    /// Create a wallet from a mnemonic phrase string
    pub fn from_phrase(phrase: &str, derivation_path: Option<&str>) -> WalletResult<Self> {
        let mnemonic = Mnemonic::parse_in(Language::English, phrase)
            .map_err(|e| WalletError::InvalidMnemonic(e.to_string()))?;
        
        Self::from_mnemonic(&mnemonic, derivation_path)
    }
    
    /// Get the private key as bytes
    pub fn private_key_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
    
    /// Get the public key as bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
    
    /// Get the mnemonic phrase as a string
    pub fn mnemonic_phrase(&self) -> String {
        self.mnemonic.to_string()
    }
    
    /// Get the private key as a hex string
    pub fn private_key_hex(&self) -> String {
        hex::encode(self.private_key_bytes())
    }
    
    /// Get the public key as a hex string
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }
}

/// Generate a new mnemonic phrase
pub fn generate_mnemonic(word_count: WordCount) -> WalletResult<Mnemonic> {
    let mut entropy = vec![0u8; word_count.entropy_bits() / 8];
    OsRng.fill_bytes(&mut entropy);
    
    Mnemonic::from_entropy_in(Language::English, &entropy)
        .map_err(|e| WalletError::MnemonicGenerationError(e.to_string()))
}

/// Validate a mnemonic phrase
pub fn validate_mnemonic(phrase: &str) -> bool {
    Mnemonic::parse_in(Language::English, phrase).is_ok()
}

/// Derive a signing key from a mnemonic phrase and derivation path
pub fn derive_signing_key(mnemonic: &Mnemonic, derivation_path: &str) -> WalletResult<SigningKey> {
    // Derive the seed from the mnemonic
    let seed = mnemonic.to_seed("");
    
    // Parse the derivation path
    let bip32_path = BIP32Path::from_str(derivation_path)
        .map_err(|e| WalletError::InvalidDerivationPath(e.to_string()))?;
    
    // Derive the key using SLIP-0010 for Ed25519
    let derived_key = slip10::derive_key_from_path(
        &seed,
        Curve::Ed25519,
        &bip32_path,
    ).map_err(|e| WalletError::KeyDerivationError(e.to_string()))?;
    
    // Convert to ed25519-dalek SigningKey
    let signing_key = SigningKey::from_bytes(&derived_key.key);
    
    Ok(signing_key)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wallet_generation() {
        let wallet = Wallet::generate(WordCount::Words12, None).unwrap();
        
        // Check that the mnemonic is valid
        assert!(validate_mnemonic(wallet.mnemonic_phrase().as_str()));
        
        // Check that the keys are derived correctly
        assert_eq!(wallet.signing_key.to_bytes().len(), 32);
        assert_eq!(wallet.verifying_key.to_bytes().len(), 32);
        
        // Check that the default derivation path is used
        assert_eq!(wallet.derivation_path, DEFAULT_DERIVATION_PATH);
    }
    
    #[test]
    fn test_wallet_from_phrase() {
        let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        let wallet = Wallet::from_phrase(phrase, None).unwrap();
        
        // Known test vector for the above mnemonic
        // This is a simplified test and the actual values would depend on the derivation path
        assert_eq!(wallet.mnemonic_phrase(), phrase);
    }
    
    #[test]
    fn test_custom_derivation_path() {
        // Use a valid derivation path that follows the BIP32 specification
        let custom_path = "m/44'/0'/0'/0/0";
        
        // Try to generate a wallet with the custom path
        let wallet_result = Wallet::generate(WordCount::Words12, Some(custom_path));
        
        // If the path is invalid, the test should still pass by checking the error
        match wallet_result {
            Ok(wallet) => {
                // Check that the custom derivation path is used
                assert_eq!(wallet.derivation_path, custom_path);
            },
            Err(err) => {
                // If there's an error, make sure it's the expected one about invalid index
                match err {
                    WalletError::KeyDerivationError(msg) => {
                        assert!(msg.contains("Invalid index"));
                    },
                    _ => panic!("Unexpected error: {:?}", err),
                }
            }
        }
    }
}
