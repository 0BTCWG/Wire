// Validation module for the WASM interface
// Provides security-focused input validation for all WASM functions

#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
use js_sys::{Array, Object, Uint8Array};
use serde_json::Value;
use std::collections::HashSet;
use log::warn;

/// Error type for validation failures
#[derive(Debug)]
pub enum ValidationError {
    MissingField(String),
    InvalidType(String),
    InvalidValue(String),
    InvalidLength(String),
    InvalidFormat(String),
    SecurityViolation(String),
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
        };
        JsValue::from_str(&error_msg)
    }
}

/// Validate a hex string (with or without 0x prefix)
pub fn validate_hex_string(value: &str, field_name: &str, expected_length: Option<usize>) -> Result<Vec<u8>, ValidationError> {
    // Remove 0x prefix if present
    let hex_str = value.trim_start_matches("0x");
    
    // Check if the string is valid hex
    if !hex_str.chars().all(|c| c.is_digit(16)) {
        return Err(ValidationError::InvalidFormat(format!(
            "{} must be a valid hex string", field_name
        )));
    }
    
    // Check length if specified
    if let Some(expected) = expected_length {
        if hex_str.len() != expected * 2 {
            return Err(ValidationError::InvalidLength(format!(
                "{} must be {} bytes ({} hex characters)", field_name, expected, expected * 2
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
    let valid_circuit_types = [
        "wrapped_asset_mint",
        "wrapped_asset_burn",
        "transfer",
        "native_asset_create",
        "native_asset_mint",
        "native_asset_burn",
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
            "Batch size must be greater than 0".to_string()
        ));
    }
    
    if batch_size > 16 {
        warn!("Large batch size ({}), this may cause performance issues", batch_size);
    }
    
    Ok(batch_size)
}

/// Validate a u64 value
pub fn validate_u64(value: &Value, field_name: &str) -> Result<u64, ValidationError> {
    match value {
        Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                Ok(num)
            } else {
                Err(ValidationError::InvalidValue(format!(
                    "{} must be a non-negative integer", field_name
                )))
            }
        },
        Value::String(s) => {
            // Try to parse the string as a u64
            if s.starts_with("0x") {
                // Parse as hex
                let hex_str = s.trim_start_matches("0x");
                u64::from_str_radix(hex_str, 16).map_err(|_| {
                    ValidationError::InvalidValue(format!(
                        "{} must be a valid hex number", field_name
                    ))
                })
            } else {
                // Parse as decimal
                s.parse::<u64>().map_err(|_| {
                    ValidationError::InvalidValue(format!(
                        "{} must be a valid number", field_name
                    ))
                })
            }
        },
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be a number or string", field_name
        ))),
    }
}

/// Validate a boolean value
pub fn validate_bool(value: &Value, field_name: &str) -> Result<bool, ValidationError> {
    match value {
        Value::Bool(b) => Ok(*b),
        Value::String(s) => {
            match s.to_lowercase().as_str() {
                "true" => Ok(true),
                "false" => Ok(false),
                _ => Err(ValidationError::InvalidValue(format!(
                    "{} must be a boolean value", field_name
                ))),
            }
        },
        Value::Number(n) => {
            if let Some(num) = n.as_u64() {
                match num {
                    0 => Ok(false),
                    1 => Ok(true),
                    _ => Err(ValidationError::InvalidValue(format!(
                        "{} must be 0 or 1 if provided as a number", field_name
                    ))),
                }
            } else {
                Err(ValidationError::InvalidValue(format!(
                    "{} must be 0 or 1 if provided as a number", field_name
                )))
            }
        },
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be a boolean, number (0/1), or string (true/false)", field_name
        ))),
    }
}

/// Validate a string value
pub fn validate_string(value: &Value, field_name: &str) -> Result<String, ValidationError> {
    match value {
        Value::String(s) => Ok(s.clone()),
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be a string", field_name
        ))),
    }
}

/// Validate an array value
pub fn validate_array<'a>(value: &'a Value, field_name: &str) -> Result<&'a Vec<Value>, ValidationError> {
    match value {
        Value::Array(a) => Ok(a),
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be an array", field_name
        ))),
    }
}

/// Validate an object value
pub fn validate_object<'a>(value: &'a Value, field_name: &str) -> Result<&'a serde_json::Map<String, Value>, ValidationError> {
    match value {
        Value::Object(o) => Ok(o),
        _ => Err(ValidationError::InvalidType(format!(
            "{} must be an object", field_name
        ))),
    }
}

/// Validate a proof structure
pub fn validate_proof_structure(proof: &Value) -> Result<(), ValidationError> {
    // Check that the proof is an object
    let proof_obj = validate_object(proof, "proof")?;
    
    // Check for required fields
    if !proof_obj.contains_key("proof") {
        return Err(ValidationError::MissingField("proof".to_string()));
    }
    
    if !proof_obj.contains_key("public_inputs") {
        return Err(ValidationError::MissingField("public_inputs".to_string()));
    }
    
    // Validate the proof field
    let proof_field = &proof_obj["proof"];
    validate_object(proof_field, "proof.proof")?;
    
    // Validate the public_inputs field
    let public_inputs = &proof_obj["public_inputs"];
    validate_array(public_inputs, "proof.public_inputs")?;
    
    Ok(())
}

#[cfg(feature = "wasm")]
/// Validate a JS array of proofs
pub fn validate_proofs_array(proofs_array: &JsValue) -> Result<Vec<Value>, ValidationError> {
    // Convert JS array to Rust array
    if !js_sys::Array::is_array(proofs_array) {
        return Err(ValidationError::InvalidType(
            "proofs must be an array".to_string()
        ));
    }
    
    let array = Array::from(proofs_array);
    let length = array.length() as usize;
    
    if length == 0 {
        return Err(ValidationError::InvalidValue(
            "proofs array must not be empty".to_string()
        ));
    }
    
    let mut proofs = Vec::with_capacity(length);
    
    for i in 0..length {
        let proof_js = array.get(i);
        let proof: Value = serde_wasm_bindgen::from_value(proof_js).map_err(|_| {
            ValidationError::InvalidValue(format!(
                "proof at index {} is not a valid JSON object", i
            ))
        })?;
        
        // Validate the proof structure
        validate_proof_structure(&proof)?;
        
        proofs.push(proof);
    }
    
    Ok(proofs)
}

#[cfg(feature = "wasm")]
/// Validate options for proof aggregation
pub fn validate_aggregation_options(options_js: &JsValue) -> Result<(usize, bool), ValidationError> {
    // Default values
    let mut batch_size = 4;
    let mut verbose = false;
    
    // If options are provided, validate them
    if !options_js.is_undefined() && !options_js.is_null() {
        let options: Value = serde_wasm_bindgen::from_value(options_js.clone()).map_err(|_| {
            ValidationError::InvalidValue("options is not a valid JSON object".to_string())
        })?;
        
        let options_obj = validate_object(&options, "options")?;
        
        // Validate batch_size if provided
        if let Some(bs) = options_obj.get("batch_size") {
            batch_size = validate_u64(bs, "options.batch_size")? as usize;
            validate_batch_size(batch_size)?;
        }
        
        // Validate verbose if provided
        if let Some(v) = options_obj.get("verbose") {
            verbose = validate_bool(v, "options.verbose")?;
        }
    }
    
    Ok((batch_size, verbose))
}

/// Extract and validate a required field from a JSON object
pub fn extract_required_field<T>(
    params: &Value,
    field_name: &str,
    validator: impl FnOnce(&Value, &str) -> Result<T, ValidationError>
) -> Result<T, ValidationError> {
    let params_obj = validate_object(params, "params")?;
    
    match params_obj.get(field_name) {
        Some(value) => validator(value, field_name),
        None => Err(ValidationError::MissingField(field_name.to_string())),
    }
}

/// Extract and validate an optional field from a JSON object
pub fn extract_optional_field<T>(
    params: &Value,
    field_name: &str,
    validator: impl FnOnce(&Value, &str) -> Result<T, ValidationError>
) -> Result<Option<T>, ValidationError> {
    let params_obj = validate_object(params, "params")?;
    
    match params_obj.get(field_name) {
        Some(value) => {
            if value.is_null() {
                Ok(None)
            } else {
                Ok(Some(validator(value, field_name)?))
            }
        },
        None => Ok(None),
    }
}

/// Validate parameters for wrapped asset mint
pub fn validate_wrapped_asset_mint_params(params: &Value) -> Result<(), ValidationError> {
    // Required fields
    extract_required_field(params, "recipientPkHash", |v, f| {
        let hex = validate_string(v, f)?;
        validate_hash(&hex, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "amount", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "depositNonce", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "custodianPkX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "custodianPkY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureS", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "salt", |v, f| {
        let hex = validate_string(v, f)?;
        validate_salt(&hex, f)?;
        Ok(())
    })?;
    
    Ok(())
}

/// Validate parameters for wrapped asset burn
pub fn validate_wrapped_asset_burn_params(params: &Value) -> Result<(), ValidationError> {
    // Required fields
    extract_required_field(params, "inputUtxoOwnerPubkeyHash", |v, f| {
        let hex = validate_string(v, f)?;
        validate_hash(&hex, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "inputUtxoAssetId", |v, f| {
        let hex = validate_string(v, f)?;
        validate_asset_id(&hex, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "inputUtxoAmount", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "inputUtxoSalt", |v, f| {
        let hex = validate_string(v, f)?;
        validate_salt(&hex, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "senderSk", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "senderPkX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "senderPkY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureS", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "destinationBtcAddress", |v, f| {
        let hex = validate_string(v, f)?;
        validate_hex_string(&hex, f, None)?;
        Ok(())
    })?;
    
    // Optional fields
    extract_optional_field(params, "feeBtc", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "feeExpiry", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "feeSignatureRX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "feeSignatureRY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "feeSignatureS", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "custodianPkX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_optional_field(params, "custodianPkY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    Ok(())
}

/// Validate parameters for transfer
pub fn validate_transfer_params(params: &Value) -> Result<(), ValidationError> {
    // Validate input UTXOs
    extract_required_field(params, "inputUtxos", |v, f| {
        let utxos = validate_array(v, f)?;
        
        if utxos.is_empty() {
            return Err(ValidationError::InvalidValue(
                "inputUtxos must not be empty".to_string()
            ));
        }
        
        for (i, utxo) in utxos.iter().enumerate() {
            let utxo_obj = validate_object(utxo, &format!("{}[{}]", f, i))?;
            
            // Validate required UTXO fields
            if !utxo_obj.contains_key("ownerPubkeyHash") {
                return Err(ValidationError::MissingField(
                    format!("{}[{}].ownerPubkeyHash", f, i)
                ));
            }
            
            if !utxo_obj.contains_key("assetId") {
                return Err(ValidationError::MissingField(
                    format!("{}[{}].assetId", f, i)
                ));
            }
            
            if !utxo_obj.contains_key("amount") {
                return Err(ValidationError::MissingField(
                    format!("{}[{}].amount", f, i)
                ));
            }
            
            if !utxo_obj.contains_key("salt") {
                return Err(ValidationError::MissingField(
                    format!("{}[{}].salt", f, i)
                ));
            }
            
            // Validate UTXO field types and values
            let owner_pk_hash = &utxo_obj["ownerPubkeyHash"];
            let owner_pk_hash_str = validate_string(owner_pk_hash, &format!("{}[{}].ownerPubkeyHash", f, i))?;
            validate_hash(&owner_pk_hash_str, &format!("{}[{}].ownerPubkeyHash", f, i))?;
            
            let asset_id = &utxo_obj["assetId"];
            let asset_id_str = validate_string(asset_id, &format!("{}[{}].assetId", f, i))?;
            validate_asset_id(&asset_id_str, &format!("{}[{}].assetId", f, i))?;
            
            let amount = &utxo_obj["amount"];
            validate_u64(amount, &format!("{}[{}].amount", f, i))?;
            
            let salt = &utxo_obj["salt"];
            let salt_str = validate_string(salt, &format!("{}[{}].salt", f, i))?;
            validate_salt(&salt_str, &format!("{}[{}].salt", f, i))?;
        }
        
        Ok(())
    })?;
    
    // Validate recipient public key hashes
    extract_required_field(params, "recipientPkHashes", |v, f| {
        let pk_hashes = validate_array(v, f)?;
        
        if pk_hashes.is_empty() {
            return Err(ValidationError::InvalidValue(
                "recipientPkHashes must not be empty".to_string()
            ));
        }
        
        for (i, pk_hash) in pk_hashes.iter().enumerate() {
            let pk_hash_str = validate_string(pk_hash, &format!("{}[{}]", f, i))?;
            validate_hash(&pk_hash_str, &format!("{}[{}]", f, i))?;
        }
        
        Ok(())
    })?;
    
    // Validate output amounts
    extract_required_field(params, "outputAmounts", |v, f| {
        let amounts = validate_array(v, f)?;
        
        if amounts.is_empty() {
            return Err(ValidationError::InvalidValue(
                "outputAmounts must not be empty".to_string()
            ));
        }
        
        for (i, amount) in amounts.iter().enumerate() {
            validate_u64(amount, &format!("{}[{}]", f, i))?;
        }
        
        Ok(())
    })?;
    
    // Validate that recipientPkHashes and outputAmounts have the same length
    let recipient_pk_hashes = validate_array(&params["recipientPkHashes"], "recipientPkHashes")?;
    let output_amounts = validate_array(&params["outputAmounts"], "outputAmounts")?;
    
    if recipient_pk_hashes.len() != output_amounts.len() {
        return Err(ValidationError::InvalidValue(
            "recipientPkHashes and outputAmounts must have the same length".to_string()
        ));
    }
    
    // Validate sender keys and signature
    extract_required_field(params, "senderSk", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "senderPkX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "senderPkY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRX", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureRY", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "signatureS", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    // Validate fee input UTXO
    extract_required_field(params, "feeInputUtxo", |v, f| {
        let fee_utxo = validate_object(v, f)?;
        
        // Validate required fee UTXO fields
        if !fee_utxo.contains_key("ownerPubkeyHash") {
            return Err(ValidationError::MissingField(
                format!("{}.ownerPubkeyHash", f)
            ));
        }
        
        if !fee_utxo.contains_key("assetId") {
            return Err(ValidationError::MissingField(
                format!("{}.assetId", f)
            ));
        }
        
        if !fee_utxo.contains_key("amount") {
            return Err(ValidationError::MissingField(
                format!("{}.amount", f)
            ));
        }
        
        if !fee_utxo.contains_key("salt") {
            return Err(ValidationError::MissingField(
                format!("{}.salt", f)
            ));
        }
        
        // Validate fee UTXO field types and values
        let owner_pk_hash = &fee_utxo["ownerPubkeyHash"];
        let owner_pk_hash_str = validate_string(owner_pk_hash, &format!("{}.ownerPubkeyHash", f))?;
        validate_hash(&owner_pk_hash_str, &format!("{}.ownerPubkeyHash", f))?;
        
        let asset_id = &fee_utxo["assetId"];
        let asset_id_str = validate_string(asset_id, &format!("{}.assetId", f))?;
        validate_asset_id(&asset_id_str, &format!("{}.assetId", f))?;
        
        let amount = &fee_utxo["amount"];
        validate_u64(amount, &format!("{}.amount", f))?;
        
        let salt = &fee_utxo["salt"];
        let salt_str = validate_string(salt, &format!("{}.salt", f))?;
        validate_salt(&salt_str, &format!("{}.salt", f))?;
        
        Ok(())
    })?;
    
    // Validate fee amount and reservoir address
    extract_required_field(params, "feeAmount", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "feeReservoirAddressHash", |v, f| {
        let hex = validate_string(v, f)?;
        validate_hash(&hex, f)?;
        Ok(())
    })?;
    
    extract_required_field(params, "nonce", |v, f| {
        validate_u64(v, f)?;
        Ok(())
    })?;
    
    Ok(())
}
