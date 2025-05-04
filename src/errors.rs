// Error handling module for the 0BTC Wire system
// Provides structured error types for all modules

use std::error::Error;
use std::fmt;

/// Core error type for the 0BTC Wire system
#[derive(Debug)]
pub enum WireError {
    // Cryptographic errors
    CryptoError(CryptoError),

    // Circuit errors
    CircuitError(CircuitError),

    // Input/output errors
    IOError(IOError),

    // Proof errors
    ProofError(ProofError),

    // Validation errors
    ValidationError(ValidationError),

    // Batch processing errors
    BatchProcessingError(String),

    // Generic errors
    GenericError(String),
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WireError::CryptoError(e) => write!(f, "Cryptographic error: {}", e),
            WireError::CircuitError(e) => write!(f, "Circuit error: {}", e),
            WireError::IOError(e) => write!(f, "I/O error: {}", e),
            WireError::ProofError(e) => write!(f, "Proof error: {}", e),
            WireError::ValidationError(e) => write!(f, "Validation error: {}", e),
            WireError::BatchProcessingError(e) => write!(f, "Batch processing error: {}", e),
            WireError::GenericError(e) => write!(f, "{}", e),
        }
    }
}

impl Error for WireError {}

impl From<std::io::Error> for WireError {
    fn from(error: std::io::Error) -> Self {
        WireError::IOError(IOError::FileSystem(error.to_string()))
    }
}

impl From<serde_json::Error> for WireError {
    fn from(error: serde_json::Error) -> Self {
        WireError::IOError(IOError::SerializationError(error.to_string()))
    }
}

impl From<String> for WireError {
    fn from(error: String) -> Self {
        WireError::GenericError(error)
    }
}

impl From<&str> for WireError {
    fn from(error: &str) -> Self {
        WireError::GenericError(error.to_string())
    }
}

impl From<CryptoError> for WireError {
    fn from(error: CryptoError) -> Self {
        WireError::CryptoError(error)
    }
}

impl From<crate::mpc::MPCError> for WireError {
    fn from(error: crate::mpc::MPCError) -> Self {
        WireError::GenericError(format!("MPC error: {}", error))
    }
}

/// Cryptographic error types
#[derive(Debug)]
pub enum CryptoError {
    // Hash errors
    HashError(String),

    // Signature errors
    SignatureError(String),

    // Key errors
    KeyError(String),

    // Curve errors
    CurveError(String),

    // Nullifier errors
    NullifierError(String),

    // Merkle tree errors
    MerkleError(String),

    // Nonce errors
    NonceError(String),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CryptoError::HashError(e) => write!(f, "Hash error: {}", e),
            CryptoError::SignatureError(e) => write!(f, "Signature error: {}", e),
            CryptoError::KeyError(e) => write!(f, "Key error: {}", e),
            CryptoError::CurveError(e) => write!(f, "Curve error: {}", e),
            CryptoError::NullifierError(e) => write!(f, "Nullifier error: {}", e),
            CryptoError::MerkleError(e) => write!(f, "Merkle tree error: {}", e),
            CryptoError::NonceError(e) => write!(f, "Nonce error: {}", e),
        }
    }
}

/// Circuit error types
#[derive(Debug)]
pub enum CircuitError {
    // Circuit creation errors
    CreationError(String),

    // Constraint errors
    ConstraintError(String),

    // Witness errors
    WitnessError(String),

    // Circuit-specific errors
    WrappedAssetMintError(String),
    WrappedAssetBurnError(String),
    TransferError(String),
    NativeAssetCreateError(String),
    NativeAssetMintError(String),
    NativeAssetBurnError(String),
    ArithmeticError(String),
    DivisionByZero(String),
    OverflowError(String),
    ProofGenerationError(String),
    ProofVerificationError(String),
    HashError(String),
    KeyDerivationError(String),
    NullifierError(String),
}

impl fmt::Display for CircuitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CircuitError::CreationError(e) => write!(f, "Circuit creation error: {}", e),
            CircuitError::ConstraintError(e) => write!(f, "Constraint error: {}", e),
            CircuitError::WitnessError(e) => write!(f, "Witness error: {}", e),
            CircuitError::WrappedAssetMintError(e) => write!(f, "WrappedAssetMint error: {}", e),
            CircuitError::WrappedAssetBurnError(e) => write!(f, "WrappedAssetBurn error: {}", e),
            CircuitError::TransferError(e) => write!(f, "Transfer error: {}", e),
            CircuitError::NativeAssetCreateError(e) => write!(f, "NativeAssetCreate error: {}", e),
            CircuitError::NativeAssetMintError(e) => write!(f, "NativeAssetMint error: {}", e),
            CircuitError::NativeAssetBurnError(e) => write!(f, "NativeAssetBurn error: {}", e),
            CircuitError::ArithmeticError(e) => write!(f, "Arithmetic operation failed: {}", e),
            CircuitError::DivisionByZero(e) => write!(f, "Division by zero error: {}", e),
            CircuitError::OverflowError(e) => write!(f, "Arithmetic overflow error: {}", e),
            CircuitError::ProofGenerationError(e) => write!(f, "Proof generation failed: {}", e),
            CircuitError::ProofVerificationError(e) => {
                write!(f, "Proof verification failed: {}", e)
            }
            CircuitError::HashError(e) => write!(f, "Hash operation failed: {}", e),
            CircuitError::KeyDerivationError(e) => write!(f, "Key derivation failed: {}", e),
            CircuitError::NullifierError(e) => write!(f, "Nullifier operation failed: {}", e),
        }
    }
}

/// Input/output error types
#[derive(Debug)]
pub enum IOError {
    // File system errors
    FileSystem(String),

    // Serialization errors
    SerializationError(String),

    // Deserialization errors
    DeserializationError(String),

    // Path errors
    PathError(String),

    // Permission errors
    PermissionError(String),
}

impl fmt::Display for IOError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IOError::FileSystem(e) => write!(f, "File system error: {}", e),
            IOError::SerializationError(e) => write!(f, "Serialization error: {}", e),
            IOError::DeserializationError(e) => write!(f, "Deserialization error: {}", e),
            IOError::PathError(e) => write!(f, "Path error: {}", e),
            IOError::PermissionError(e) => write!(f, "Permission error: {}", e),
        }
    }
}

/// Proof error types
#[derive(Debug)]
pub enum ProofError {
    // Proof generation errors
    GenerationError(String),

    // Proof verification errors
    VerificationError(String),

    // Proof serialization errors
    SerializationError(String),

    // Proof deserialization errors
    DeserializationError(String),

    // Proof aggregation errors
    AggregationError(String),

    // Proof compatibility errors
    CompatibilityError(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofError::GenerationError(e) => write!(f, "Proof generation error: {}", e),
            ProofError::VerificationError(e) => write!(f, "Proof verification error: {}", e),
            ProofError::SerializationError(e) => write!(f, "Proof serialization error: {}", e),
            ProofError::DeserializationError(e) => write!(f, "Proof deserialization error: {}", e),
            ProofError::AggregationError(e) => write!(f, "Proof aggregation error: {}", e),
            ProofError::CompatibilityError(e) => write!(f, "Proof compatibility error: {}", e),
        }
    }
}

impl From<crate::core::proof::ProofError> for ProofError {
    fn from(error: crate::core::proof::ProofError) -> Self {
        match error {
            crate::core::proof::ProofError::ProofGenerationError(msg) => {
                ProofError::GenerationError(msg)
            }
            crate::core::proof::ProofError::VerificationError(msg) => {
                ProofError::VerificationError(msg)
            }
            crate::core::proof::ProofError::SerializationError(msg) => {
                ProofError::SerializationError(msg)
            }
            crate::core::proof::ProofError::DeserializationError(msg) => {
                ProofError::DeserializationError(msg)
            }
        }
    }
}

/// Validation error types
#[derive(Debug)]
pub enum ValidationError {
    // Missing field errors
    MissingField(String),

    // Invalid type errors
    InvalidType(String),

    // Invalid value errors
    InvalidValue(String),

    // Invalid length errors
    InvalidLength(String),

    // Invalid format errors
    InvalidFormat(String),

    // Input validation errors
    InputValidationError(String),

    // Security violation errors
    SecurityViolation(String),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::MissingField(e) => write!(f, "Missing field: {}", e),
            ValidationError::InvalidType(e) => write!(f, "Invalid type: {}", e),
            ValidationError::InvalidValue(e) => write!(f, "Invalid value: {}", e),
            ValidationError::InvalidLength(e) => write!(f, "Invalid length: {}", e),
            ValidationError::InvalidFormat(e) => write!(f, "Invalid format: {}", e),
            ValidationError::InputValidationError(e) => write!(f, "Input validation error: {}", e),
            ValidationError::SecurityViolation(e) => write!(f, "Security violation: {}", e),
        }
    }
}

/// Helper function to sanitize error messages for external consumption
/// Removes potentially sensitive information from error messages
pub fn sanitize_error_message(error: &WireError) -> String {
    match error {
        // For cryptographic errors, provide generic messages
        WireError::CryptoError(e) => match e {
            CryptoError::SignatureError(_) => "Signature verification failed".to_string(),
            CryptoError::KeyError(_) => "Key operation failed".to_string(),
            CryptoError::CurveError(_) => "Curve operation failed".to_string(),
            CryptoError::HashError(_) => "Hash operation failed".to_string(),
            CryptoError::NullifierError(_) => "Nullifier operation failed".to_string(),
            CryptoError::MerkleError(_) => "Merkle tree operation failed".to_string(),
            CryptoError::NonceError(_) => "Nonce operation failed".to_string(),
        },

        // For proof errors, provide generic messages
        WireError::ProofError(e) => match e {
            ProofError::VerificationError(_) => "Proof verification failed".to_string(),
            ProofError::GenerationError(_) => "Proof generation failed".to_string(),
            ProofError::SerializationError(_) => "Proof serialization failed".to_string(),
            ProofError::DeserializationError(_) => "Proof deserialization failed".to_string(),
            ProofError::AggregationError(_) => "Proof aggregation failed".to_string(),
            ProofError::CompatibilityError(_) => "Proof compatibility check failed".to_string(),
        },

        // For validation errors, we can be more specific but still sanitize field names
        WireError::ValidationError(e) => match e {
            ValidationError::MissingField(field) => {
                sanitize_field_name("Missing required field", field)
            }
            ValidationError::InvalidType(field) => {
                sanitize_field_name("Invalid type for field", field)
            }
            ValidationError::InvalidValue(field) => {
                sanitize_field_name("Invalid value for field", field)
            }
            ValidationError::InvalidLength(field) => {
                sanitize_field_name("Invalid length for field", field)
            }
            ValidationError::InvalidFormat(field) => {
                sanitize_field_name("Invalid format for field", field)
            }
            ValidationError::InputValidationError(field) => {
                sanitize_field_name("Input validation error for field", field)
            }
            ValidationError::SecurityViolation(_) => "Security violation detected".to_string(),
        },

        // For I/O errors, provide generic messages
        WireError::IOError(e) => match e {
            IOError::FileSystem(_) => "File system operation failed".to_string(),
            IOError::SerializationError(_) => "Data serialization failed".to_string(),
            IOError::DeserializationError(_) => "Data deserialization failed".to_string(),
            IOError::PathError(_) => "Invalid file path".to_string(),
            IOError::PermissionError(_) => "Permission denied".to_string(),
        },

        // For circuit errors, provide generic messages
        WireError::CircuitError(e) => match e {
            CircuitError::CreationError(_) => "Circuit creation failed".to_string(),
            CircuitError::ConstraintError(_) => "Circuit constraint not satisfied".to_string(),
            CircuitError::WitnessError(_) => "Circuit witness generation failed".to_string(),
            CircuitError::WrappedAssetMintError(_) => {
                "WrappedAssetMint circuit operation failed".to_string()
            }
            CircuitError::WrappedAssetBurnError(_) => {
                "WrappedAssetBurn circuit operation failed".to_string()
            }
            CircuitError::TransferError(_) => "Transfer circuit operation failed".to_string(),
            CircuitError::NativeAssetCreateError(_) => {
                "NativeAssetCreate circuit operation failed".to_string()
            }
            CircuitError::NativeAssetMintError(_) => {
                "NativeAssetMint circuit operation failed".to_string()
            }
            CircuitError::NativeAssetBurnError(_) => {
                "NativeAssetBurn circuit operation failed".to_string()
            }
            CircuitError::ArithmeticError(_) => "Arithmetic operation failed".to_string(),
            CircuitError::DivisionByZero(_) => "Division by zero error".to_string(),
            CircuitError::OverflowError(_) => "Arithmetic overflow error".to_string(),
            CircuitError::ProofGenerationError(_) => "Proof generation failed".to_string(),
            CircuitError::ProofVerificationError(_) => "Proof verification failed".to_string(),
            CircuitError::HashError(_) => "Hash operation failed".to_string(),
            CircuitError::KeyDerivationError(_) => "Key derivation failed".to_string(),
            CircuitError::NullifierError(_) => "Nullifier operation failed".to_string(),
        },

        // For batch processing errors, provide generic messages
        WireError::BatchProcessingError(_) => "Batch processing failed".to_string(),

        // For generic errors, sanitize to remove potential sensitive information
        WireError::GenericError(e) => {
            // Check for potentially sensitive information
            if contains_sensitive_info(e) {
                "Operation failed".to_string()
            } else {
                "Operation failed: check input parameters".to_string()
            }
        }
    }
}

/// Helper function to sanitize field names
fn sanitize_field_name(prefix: &str, field: &str) -> String {
    // List of sensitive field names that should not be exposed
    const SENSITIVE_FIELDS: [&str; 8] = [
        "key",
        "secret",
        "private",
        "password",
        "seed",
        "salt",
        "signature",
        "hash",
    ];

    // Check if the field name contains any sensitive terms
    if SENSITIVE_FIELDS
        .iter()
        .any(|&sensitive| field.to_lowercase().contains(sensitive))
    {
        format!("{}", prefix)
    } else {
        format!("{}: {}", prefix, field)
    }
}

/// Helper function to check if a string contains sensitive information
fn contains_sensitive_info(s: &str) -> bool {
    let s_lower = s.to_lowercase();

    // Check for various types of sensitive information
    s_lower.contains("key")
        || s_lower.contains("secret")
        || s_lower.contains("private")
        || s_lower.contains("password")
        || s_lower.contains("seed")
        || s_lower.contains("salt")
        || s_lower.contains("signature")
        || s_lower.contains("hash")
        || s_lower.contains("mnemonic")
        || s_lower.contains("wallet")
        || s_lower.contains("address")
        || s_lower.contains("account")
}

/// Helper function to log detailed error information for internal use
/// This should only be used for internal logging, not for external error messages
pub fn log_detailed_error(error: &WireError) -> String {
    format!("{:?}", error)
}

/// Result type alias for Wire operations
pub type WireResult<T> = Result<T, WireError>;
