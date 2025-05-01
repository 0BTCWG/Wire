// Input validation for the 0BTC Wire CLI
use std::fs;
use std::path::{Path, PathBuf};
use std::io;
use log::{warn};
use serde_json::Value;

/// Validation result type
pub type ValidationResult<T> = Result<T, ValidationError>;

/// Validation error type
#[derive(Debug)]
pub enum ValidationError {
    /// File system error
    FileSystem(String),
    /// Invalid path error
    InvalidPath(String),
    /// JSON parsing error
    JsonParse(String),
    /// Missing field error
    MissingField(String),
    /// Invalid field type error
    InvalidFieldType(String),
    /// Invalid value error
    InvalidValue(String),
    /// Security error
    Security(String),
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ValidationError::FileSystem(msg) => write!(f, "File system error: {}", msg),
            ValidationError::InvalidPath(msg) => write!(f, "Invalid path: {}", msg),
            ValidationError::JsonParse(msg) => write!(f, "JSON parse error: {}", msg),
            ValidationError::MissingField(msg) => write!(f, "Missing field: {}", msg),
            ValidationError::InvalidFieldType(msg) => write!(f, "Invalid field type: {}", msg),
            ValidationError::InvalidValue(msg) => write!(f, "Invalid value: {}", msg),
            ValidationError::Security(msg) => write!(f, "Security error: {}", msg),
        }
    }
}

impl From<io::Error> for ValidationError {
    fn from(error: io::Error) -> Self {
        ValidationError::FileSystem(error.to_string())
    }
}

impl From<serde_json::Error> for ValidationError {
    fn from(error: serde_json::Error) -> Self {
        ValidationError::JsonParse(error.to_string())
    }
}

/// Validate a file path
///
/// This function checks that a file path:
/// 1. Is a valid path (no invalid characters)
/// 2. Exists (if check_exists is true)
/// 3. Is a file (if check_exists is true)
/// 4. Is readable (if check_exists is true)
pub fn validate_file_path(path_str: &str, check_exists: bool) -> ValidationResult<PathBuf> {
    // Sanitize the path
    let path_str = sanitize_path(path_str)?;
    
    // Create a path object
    let path = Path::new(&path_str);
    
    // Check if the path is absolute
    if !path.is_absolute() {
        return Err(ValidationError::InvalidPath(
            "Path must be absolute".to_string(),
        ));
    }
    
    // Check if the path exists and is a file
    if check_exists {
        if !path.exists() {
            return Err(ValidationError::InvalidPath(
                format!("File does not exist: {}", path_str),
            ));
        }
        
        if !path.is_file() {
            return Err(ValidationError::InvalidPath(
                format!("Path is not a file: {}", path_str),
            ));
        }
        
        // Check if the file is readable
        match fs::metadata(path) {
            Ok(metadata) => {
                // On Unix systems, we can check permissions
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = metadata.permissions();
                    let mode = permissions.mode();
                    if mode & 0o400 == 0 {
                        return Err(ValidationError::InvalidPath(
                            format!("File is not readable: {}", path_str),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(ValidationError::FileSystem(
                    format!("Failed to get file metadata: {}", e),
                ));
            }
        }
    }
    
    Ok(path.to_path_buf())
}

/// Validate a directory path
///
/// This function checks that a directory path:
/// 1. Is a valid path (no invalid characters)
/// 2. Exists (if check_exists is true)
/// 3. Is a directory (if check_exists is true)
/// 4. Is readable (if check_exists is true)
pub fn validate_directory_path(path_str: &str, check_exists: bool) -> ValidationResult<PathBuf> {
    // Sanitize the path
    let path_str = sanitize_path(path_str)?;
    
    // Create a path object
    let path = Path::new(&path_str);
    
    // Check if the path is absolute
    if !path.is_absolute() {
        return Err(ValidationError::InvalidPath(
            "Path must be absolute".to_string(),
        ));
    }
    
    // Check if the path exists and is a directory
    if check_exists {
        if !path.exists() {
            return Err(ValidationError::InvalidPath(
                format!("Directory does not exist: {}", path_str),
            ));
        }
        
        if !path.is_dir() {
            return Err(ValidationError::InvalidPath(
                format!("Path is not a directory: {}", path_str),
            ));
        }
        
        // Check if the directory is readable
        match fs::metadata(path) {
            Ok(metadata) => {
                // On Unix systems, we can check permissions
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = metadata.permissions();
                    let mode = permissions.mode();
                    if mode & 0o500 == 0 {
                        return Err(ValidationError::InvalidPath(
                            format!("Directory is not readable: {}", path_str),
                        ));
                    }
                }
            }
            Err(e) => {
                return Err(ValidationError::FileSystem(
                    format!("Failed to get directory metadata: {}", e),
                ));
            }
        }
    }
    
    Ok(path.to_path_buf())
}

/// Validate an output file path
///
/// This function checks that an output file path:
/// 1. Is a valid path (no invalid characters)
/// 2. Parent directory exists
/// 3. Parent directory is writable
pub fn validate_output_file_path(path_str: &str) -> ValidationResult<PathBuf> {
    // Sanitize the path
    let path_str = sanitize_path(path_str)?;
    
    // Create a path object
    let path = Path::new(&path_str);
    
    // Check if the path is absolute
    if !path.is_absolute() {
        return Err(ValidationError::InvalidPath(
            "Path must be absolute".to_string(),
        ));
    }
    
    // Check if the parent directory exists
    let parent = path.parent().ok_or_else(|| {
        ValidationError::InvalidPath("Cannot get parent directory".to_string())
    })?;
    
    if !parent.exists() {
        return Err(ValidationError::InvalidPath(
            format!("Parent directory does not exist: {}", parent.display()),
        ));
    }
    
    if !parent.is_dir() {
        return Err(ValidationError::InvalidPath(
            format!("Parent path is not a directory: {}", parent.display()),
        ));
    }
    
    // Check if the parent directory is writable
    match fs::metadata(parent) {
        Ok(metadata) => {
            // On Unix systems, we can check permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let permissions = metadata.permissions();
                let mode = permissions.mode();
                if mode & 0o200 == 0 {
                    return Err(ValidationError::InvalidPath(
                        format!("Parent directory is not writable: {}", parent.display()),
                    ));
                }
            }
        }
        Err(e) => {
            return Err(ValidationError::FileSystem(
                format!("Failed to get parent directory metadata: {}", e),
            ));
        }
    }
    
    Ok(path.to_path_buf())
}

/// Sanitize a path string
///
/// This function removes any potentially dangerous characters from a path string.
fn sanitize_path(path_str: &str) -> ValidationResult<String> {
    // Check for null bytes
    if path_str.contains('\0') {
        return Err(ValidationError::Security(
            "Path contains null bytes".to_string(),
        ));
    }
    
    // Check for relative path traversal
    if path_str.contains("..") {
        warn!("Path contains relative traversal sequence: {}", path_str);
    }
    
    // Check for other suspicious patterns
    if path_str.contains("//") || path_str.contains("\\/") || path_str.contains("/\\") {
        warn!("Path contains suspicious patterns: {}", path_str);
    }
    
    // Normalize the path
    let path = Path::new(path_str);
    match path.canonicalize() {
        Ok(canonical_path) => Ok(canonical_path.to_string_lossy().to_string()),
        Err(_) => Ok(path_str.to_string()), // If canonicalization fails, return the original path
    }
}

/// Validate a circuit type
///
/// This function checks that a circuit type is valid.
pub fn validate_circuit_type(circuit_type: &str) -> ValidationResult<String> {
    // List of valid circuit types
    const VALID_CIRCUIT_TYPES: [&str; 6] = [
        "wrapped_asset_mint",
        "wrapped_asset_burn",
        "transfer",
        "native_asset_create",
        "native_asset_mint",
        "native_asset_burn",
    ];
    
    // Check if the circuit type is valid
    if !VALID_CIRCUIT_TYPES.contains(&circuit_type) {
        return Err(ValidationError::InvalidValue(
            format!(
                "Invalid circuit type: {}. Valid types are: {}",
                circuit_type,
                VALID_CIRCUIT_TYPES.join(", ")
            ),
        ));
    }
    
    Ok(circuit_type.to_string())
}

/// Validate a JSON file
///
/// This function checks that a file contains valid JSON.
pub fn validate_json_file(path: &Path) -> ValidationResult<Value> {
    // Read the file
    let file_content = fs::read_to_string(path)?;
    
    // Parse the JSON
    let json: Value = serde_json::from_str(&file_content)?;
    
    Ok(json)
}

/// Validate a batch size
///
/// This function checks that a batch size is valid.
pub fn validate_batch_size(batch_size: usize) -> ValidationResult<usize> {
    // Check if the batch size is valid
    if batch_size == 0 {
        return Err(ValidationError::InvalidValue(
            "Batch size must be greater than 0".to_string(),
        ));
    }
    
    if batch_size > 32 {
        warn!("Large batch size may cause memory issues: {}", batch_size);
    }
    
    Ok(batch_size)
}

/// Validate a proof file
///
/// This function checks that a file contains a valid proof.
pub fn validate_proof_file(path: &Path) -> ValidationResult<Value> {
    // Validate that the file contains valid JSON
    let json = validate_json_file(path)?;
    
    // Check that the JSON has the required fields
    if !json.is_object() {
        return Err(ValidationError::InvalidFieldType(
            "Proof must be a JSON object".to_string(),
        ));
    }
    
    // Check for required fields
    let required_fields = ["proof", "public_inputs"];
    for field in required_fields.iter() {
        if !json.get(field).is_some() {
            return Err(ValidationError::MissingField(
                format!("Proof is missing required field: {}", field),
            ));
        }
    }
    
    // Check that the proof field is an object
    if !json["proof"].is_object() {
        return Err(ValidationError::InvalidFieldType(
            "Proof field must be an object".to_string(),
        ));
    }
    
    // Check that the public_inputs field is an array
    if !json["public_inputs"].is_array() {
        return Err(ValidationError::InvalidFieldType(
            "public_inputs field must be an array".to_string(),
        ));
    }
    
    Ok(json)
}

/// Validate a directory of proof files
///
/// This function checks that a directory contains valid proof files.
pub fn validate_proof_directory(path: &Path) -> ValidationResult<Vec<PathBuf>> {
    // Check if the path is a directory
    if !path.is_dir() {
        return Err(ValidationError::InvalidPath(
            format!("Path is not a directory: {}", path.display()),
        ));
    }
    
    // Get all files in the directory
    let entries = fs::read_dir(path)?;
    
    // Filter for JSON files and validate each one
    let mut proof_files = Vec::new();
    for entry in entries {
        let entry = entry?;
        let file_path = entry.path();
        
        // Skip directories
        if file_path.is_dir() {
            continue;
        }
        
        // Check if the file has a .json extension
        if let Some(extension) = file_path.extension() {
            if extension == "json" {
                // Validate the proof file
                match validate_proof_file(&file_path) {
                    Ok(_) => {
                        proof_files.push(file_path);
                    }
                    Err(e) => {
                        warn!(
                            "Skipping invalid proof file {}: {}",
                            file_path.display(),
                            e
                        );
                    }
                }
            }
        }
    }
    
    // Check if we found any proof files
    if proof_files.is_empty() {
        return Err(ValidationError::InvalidValue(
            format!("No valid proof files found in directory: {}", path.display()),
        ));
    }
    
    Ok(proof_files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    
    #[test]
    fn test_validate_circuit_type() {
        // Valid circuit types
        assert!(validate_circuit_type("wrapped_asset_mint").is_ok());
        assert!(validate_circuit_type("wrapped_asset_burn").is_ok());
        assert!(validate_circuit_type("transfer").is_ok());
        assert!(validate_circuit_type("native_asset_create").is_ok());
        assert!(validate_circuit_type("native_asset_mint").is_ok());
        assert!(validate_circuit_type("native_asset_burn").is_ok());
        
        // Invalid circuit types
        assert!(validate_circuit_type("invalid").is_err());
        assert!(validate_circuit_type("").is_err());
    }
    
    #[test]
    fn test_validate_batch_size() {
        // Valid batch sizes
        assert!(validate_batch_size(1).is_ok());
        assert!(validate_batch_size(8).is_ok());
        assert!(validate_batch_size(32).is_ok());
        
        // Invalid batch sizes
        assert!(validate_batch_size(0).is_err());
    }
    
    #[test]
    fn test_sanitize_path() {
        // Valid paths
        assert!(sanitize_path("/tmp/test").is_ok());
        assert!(sanitize_path("/home/user/test").is_ok());
        
        // Invalid paths
        assert!(sanitize_path("/tmp/test\0").is_err());
    }
    
    #[test]
    fn test_validate_json_file() {
        // Create a temporary directory
        let dir = tempdir().unwrap();
        
        // Create a valid JSON file
        let valid_json_path = dir.path().join("valid.json");
        let mut valid_json_file = File::create(&valid_json_path).unwrap();
        writeln!(valid_json_file, r#"{{"key": "value"}}"#).unwrap();
        
        // Create an invalid JSON file
        let invalid_json_path = dir.path().join("invalid.json");
        let mut invalid_json_file = File::create(&invalid_json_path).unwrap();
        writeln!(invalid_json_file, r#"{{"key": "value""#).unwrap();
        
        // Test validation
        assert!(validate_json_file(&valid_json_path).is_ok());
        assert!(validate_json_file(&invalid_json_path).is_err());
    }
}
