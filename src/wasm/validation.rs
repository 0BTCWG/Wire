// Validation module for the WASM interface
// Provides security-focused input validation for all WASM functions

use crate::errors::{ValidationError as WireValidationError, WireError};
#[cfg(feature = "wasm")]
use js_sys::{Array, Object, Uint8Array};
use log::warn;
use serde_json::Value;
use std::collections::HashSet;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;

/// Maximum allowed input string length (1MB)
const MAX_STRING_LENGTH: usize = 1024 * 1024;

/// Maximum allowed array length
const MAX_ARRAY_LENGTH: usize = 1024;

/// Maximum allowed batch size
const MAX_BATCH_SIZE: usize = 16;

/// Error type for validation failures
#[derive(Debug)]
pub enum ValidationError {
    MissingField(String),
    InvalidType(String),
    InvalidValue(String),
    InvalidLength(String),
    InvalidFormat(String),
    SecurityViolation(String),
    InputValidationError(String),
}

impl ValidationError {
    #[cfg(feature = "wasm")]
    pub fn to_js_error(&self) -> JsValue {
        let error_msg = match self {
            ValidationError::MissingField(field) => format!("Missing required field: {}", field),
            ValidationError::InvalidType(field) => format!("Invalid type for field: {}", field),
            ValidationError::InvalidValue(field) => format!("Invalid value for field: {}", field),
            ValidationError::InvalidLength(field) => format!("Invalid length for field: {}", field),
            ValidationError::InvalidFormat(field) => format!("Invalid format for field: {}", field),
            ValidationError::SecurityViolation(msg) => format!("Security violation: {}", msg),
            ValidationError::InputValidationError(msg) => {
                format!("Input validation error: {}", msg)
            }
        };
        JsValue::from_str(&error_msg)
    }
}

impl From<ValidationError> for WireError {
    fn from(error: ValidationError) -> Self {
        match error {
            ValidationError::MissingField(field) => {
                WireError::ValidationError(WireValidationError::MissingField(field))
            }
            ValidationError::InvalidType(field) => {
                WireError::ValidationError(WireValidationError::InvalidType(field))
            }
            ValidationError::InvalidValue(field) => {
                WireError::ValidationError(WireValidationError::InvalidValue(field))
            }
            ValidationError::InvalidLength(field) => {
                WireError::ValidationError(WireValidationError::InvalidLength(field))
            }
            ValidationError::InvalidFormat(field) => {
                WireError::ValidationError(WireValidationError::InvalidFormat(field))
            }
            ValidationError::SecurityViolation(msg) => {
                WireError::ValidationError(WireValidationError::SecurityViolation(msg))
            }
            ValidationError::InputValidationError(msg) => {
                WireError::ValidationError(WireValidationError::InputValidationError(msg))
            }
        }
    }
}

/// Validate a string length
pub fn validate_string_length(
    value: &str,
    field_name: &str,
    min_length: usize,
    max_length: Option<usize>,
) -> Result<(), ValidationError> {
    let max = max_length.unwrap_or(MAX_STRING_LENGTH);

    if value.len() < min_length {
        return Err(ValidationError::InvalidLength(format!(
            "{} must be at least {} characters",
            field_name, min_length
        )));
    }

    if value.len() > max {
        return Err(ValidationError::InvalidLength(format!(
            "{} must be at most {} characters",
            field_name, max
        )));
    }

    // Check for control characters
    if value
        .chars()
        .any(|c| c.is_control() && c != '\n' && c != '\r' && c != '\t')
    {
        return Err(ValidationError::SecurityViolation(format!(
            "{} contains invalid control characters",
            field_name
        )));
    }

    Ok(())
}

/// Validate a hex string (with or without 0x prefix)
pub fn validate_hex_string(
    value: &str,
    field_name: &str,
    expected_length: Option<usize>,
) -> Result<Vec<u8>, ValidationError> {
    // Validate string length
    validate_string_length(
        value,
        field_name,
        2,
        Some(2 + (expected_length.unwrap_or(MAX_STRING_LENGTH / 2) * 2)),
    )?;

    // Remove 0x prefix if present
    let hex_str = value.trim_start_matches("0x");

    // Check if the string is valid hex
    if !hex_str.chars().all(|c| c.is_digit(16)) {
        return Err(ValidationError::InvalidFormat(format!(
            "{} must be a valid hex string",
            field_name
        )));
    }

    // Check if the length is even (required for hex decoding)
    if hex_str.len() % 2 != 0 {
        return Err(ValidationError::InvalidFormat(format!(
            "{} must have an even number of hex characters",
            field_name
        )));
    }

    // Check length if specified
    if let Some(expected) = expected_length {
        if hex_str.len() != expected * 2 {
            return Err(ValidationError::InvalidLength(format!(
                "{} must be {} bytes ({} hex characters)",
                field_name,
                expected,
                expected * 2
            )));
        }
    }

    // Decode the hex string
    hex::decode(hex_str).map_err(|_| {
        ValidationError::InvalidFormat(format!("{} could not be decoded as hex", field_name))
    })
}

/// Validate a public key (32 bytes)
pub fn validate_public_key(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(32))
}

/// Validate a private key (32 bytes)
pub fn validate_private_key(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(32))
}

/// Validate a signature (64 bytes)
pub fn validate_signature(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(64))
}

/// Validate a hash (32 bytes)
pub fn validate_hash(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(32))
}

/// Validate a salt (32 bytes)
pub fn validate_salt(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(32))
}

/// Validate an asset ID (32 bytes)
pub fn validate_asset_id(value: &str, field_name: &str) -> Result<Vec<u8>, ValidationError> {
    validate_hex_string(value, field_name, Some(32))
}

/// Validate a circuit type
pub fn validate_circuit_type(circuit_type: &str) -> Result<String, ValidationError> {
    // Validate string length
    validate_string_length(circuit_type, "circuit_type", 1, Some(50))?;

    let valid_circuit_types = [
        "wrapped_asset_mint",
        "wrapped_asset_burn",
        "transfer",
        "native_asset_create",
        "native_asset_mint",
        "native_asset_burn",
        "add_liquidity",
        "remove_liquidity",
        "swap",
    ];

    if valid_circuit_types.contains(&circuit_type) {
        Ok(circuit_type.to_string())
    } else {
        Err(ValidationError::InvalidValue(format!(
            "Invalid circuit type: {}. Valid types are: {}",
            circuit_type,
            valid_circuit_types.join(", ")
        )))
    }
}

/// Validate a batch size
pub fn validate_batch_size(batch_size: usize) -> Result<usize, ValidationError> {
    if batch_size == 0 {
        return Err(ValidationError::InvalidValue(
            "Batch size must be greater than 0".to_string(),
        ));
    }

    if batch_size > MAX_BATCH_SIZE {
        return Err(ValidationError::InvalidValue(format!(
            "Batch size must be at most {}",
            MAX_BATCH_SIZE
        )));
    }

    Ok(batch_size)
}

/// Validate an array length
pub fn validate_array_length<T>(
    array: &[T],
    field_name: &str,
    min_length: usize,
    max_length: Option<usize>,
) -> Result<(), ValidationError> {
    let max = max_length.unwrap_or(MAX_ARRAY_LENGTH);

    if array.len() < min_length {
        return Err(ValidationError::InvalidLength(format!(
            "{} must have at least {} elements",
            field_name, min_length
        )));
    }

    if array.len() > max {
        return Err(ValidationError::InvalidLength(format!(
            "{} must have at most {} elements",
            field_name, max
        )));
    }

    Ok(())
}

/// Validate a u64 value
pub fn validate_u64(value: &Value, field_name: &str) -> Result<u64, ValidationError> {
    match value {
        Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                Ok(num)
            } else {
                Err(ValidationError::InvalidValue(format!(
                    "{} must be a non-negative integer",
                    field_name
                )))
            }
        }
        Value::String(s) => {
            // Validate string length
            validate_string_length(s, field_name, 1, Some(64))?;

            // Try to parse the string as a u64
            if s.starts_with("0x") {
                // Parse as hex
                let hex_str = s.trim_start_matches("0x");
                u64::from_str_radix(hex_str, 16).map_err(|_| {
                    ValidationError::InvalidValue(format!(
                        "{} must be a valid hex number",
                        field_name
                    ))
                })
            } else {
                // Parse as decimal
                s.parse::<u64>().map_err(|_| {
                    ValidationError::InvalidValue(format!("{} must be a valid number", field_name))
                })
            }
        }
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be a number or string",
            field_name
        ))),
    }
}

/// Validate a u64 value with range check
pub fn validate_u64_range(
    value: &Value,
    field_name: &str,
    min: Option<u64>,
    max: Option<u64>,
) -> Result<u64, ValidationError> {
    let num = validate_u64(value, field_name)?;

    if let Some(min_val) = min {
        if num < min_val {
            return Err(ValidationError::InvalidValue(format!(
                "{} must be at least {}",
                field_name, min_val
            )));
        }
    }

    if let Some(max_val) = max {
        if num > max_val {
            return Err(ValidationError::InvalidValue(format!(
                "{} must be at most {}",
                field_name, max_val
            )));
        }
    }

    Ok(num)
}

/// Validate a boolean value
pub fn validate_bool(value: &Value, field_name: &str) -> Result<bool, ValidationError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) => {
            // Validate string length
            validate_string_length(s, field_name, 1, Some(5))?;

            match s.to_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(ValidationError::InvalidValue(format!(
                    "{} must be a boolean value",
                    field_name
                ))),
            }
        }
        Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                match num {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(ValidationError::InvalidValue(format!(
                        "{} must be 0 or 1 if provided as a number",
                        field_name
                    ))),
                }
            } else {
                Err(ValidationError::InvalidValue(format!(
                    "{} must be 0 or 1 if provided as a number",
                    field_name
                )))
            }
        }
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be a boolean, number (0/1), or string (true/false)",
            field_name
        ))),
    }
}

/// Validate a JSON object has required fields
pub fn validate_required_fields(
    obj: &Value,
    required_fields: &[&str],
    context: &str,
) -> Result<(), ValidationError> {
    if !obj.is_object() {
        return Err(ValidationError::InvalidType(format!(
            "{} must be a JSON object",
            context
        )));
    }

    let obj = obj.as_object().unwrap();

    for &field in required_fields {
        if !obj.contains_key(field) {
            return Err(ValidationError::MissingField(format!(
                "{} is missing required field: {}",
                context, field
            )));
        }
    }

    Ok(())
}

/// Validate a field is of a specific JSON type
pub fn validate_field_type(
    obj: &Value,
    field: &str,
    expected_type: &str,
    context: &str,
) -> Result<(), ValidationError> {
    if !obj.is_object() {
        return Err(ValidationError::InvalidType(format!(
            "{} must be a JSON object",
            context
        )));
    }

    let obj = obj.as_object().unwrap();

    if !obj.contains_key(field) {
        return Err(ValidationError::MissingField(format!(
            "{} is missing field: {}",
            context, field
        )));
    }

    let value = &obj[field];

    let type_valid = match expected_type {
        "string" => value.is_string(),
        "number" => value.is_number(),
        "boolean" => value.is_boolean(),
        "array" => value.is_array(),
        "object" => value.is_object(),
        "null" => value.is_null(),
        _ => false,
    };

    if !type_valid {
        return Err(ValidationError::InvalidType(format!(
            "{}: field {} must be of type {}",
            context, field, expected_type
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_validate_hex_string() {
        // Valid hex strings
        assert!(validate_hex_string("0x1234", "test", None).is_ok());
        assert!(validate_hex_string("1234", "test", None).is_ok());
        assert!(validate_hex_string("0xabcdef", "test", None).is_ok());
        assert!(validate_hex_string("ABCDEF", "test", None).is_ok());

        // Invalid hex strings
        assert!(validate_hex_string("0x123", "test", None).is_err()); // Odd length
        assert!(validate_hex_string("123g", "test", None).is_err()); // Invalid character
        assert!(validate_hex_string("", "test", None).is_err()); // Empty string

        // Length validation
        assert!(validate_hex_string("1234", "test", Some(2)).is_ok());
        assert!(validate_hex_string("123456", "test", Some(2)).is_err());
    }

    #[test]
    fn test_validate_circuit_type() {
        // Valid circuit types
        assert!(validate_circuit_type("wrapped_asset_mint").is_ok());
        assert!(validate_circuit_type("wrapped_asset_burn").is_ok());
        assert!(validate_circuit_type("transfer").is_ok());
        assert!(validate_circuit_type("native_asset_create").is_ok());
        assert!(validate_circuit_type("native_asset_mint").is_ok());
        assert!(validate_circuit_type("native_asset_burn").is_ok());
        assert!(validate_circuit_type("add_liquidity").is_ok());
        assert!(validate_circuit_type("remove_liquidity").is_ok());
        assert!(validate_circuit_type("swap").is_ok());

        // Invalid circuit types
        assert!(validate_circuit_type("invalid").is_err());
        assert!(validate_circuit_type("").is_err());
    }

    #[test]
    fn test_validate_batch_size() {
        // Valid batch sizes
        assert!(validate_batch_size(1).is_ok());
        assert!(validate_batch_size(16).is_ok());

        // Invalid batch sizes
        assert!(validate_batch_size(0).is_err());
        assert!(validate_batch_size(17).is_err());
    }

    #[test]
    fn test_validate_u64() {
        // Valid u64 values
        assert_eq!(validate_u64(&json!(123), "test").unwrap(), 123);
        assert_eq!(validate_u64(&json!("123"), "test").unwrap(), 123);
        assert_eq!(validate_u64(&json!("0x7b"), "test").unwrap(), 123);

        // Invalid u64 values
        assert!(validate_u64(&json!(-1), "test").is_err());
        assert!(validate_u64(&json!("invalid"), "test").is_err());
        assert!(validate_u64(&json!(true), "test").is_err());
    }

    #[test]
    fn test_validate_bool() {
        // Valid boolean values
        assert_eq!(validate_bool(&json!(true), "test").unwrap(), true);
        assert_eq!(validate_bool(&json!(false), "test").unwrap(), false);
        assert_eq!(validate_bool(&json!("true"), "test").unwrap(), true);
        assert_eq!(validate_bool(&json!("false"), "test").unwrap(), false);
        assert_eq!(validate_bool(&json!(1), "test").unwrap(), true);
        assert_eq!(validate_bool(&json!(0), "test").unwrap(), false);

        // Invalid boolean values
        assert!(validate_bool(&json!("invalid"), "test").is_err());
        assert!(validate_bool(&json!(2), "test").is_err());
        assert!(validate_bool(&json!(null), "test").is_err());
    }
}
