// Conversion utilities for CLI commands

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;

use wire_lib::errors::{ValidationError, WireResult, WireError};

/// Convert a hex string to a byte array
pub fn hex_to_bytes(hex_str: &str) -> WireResult<Vec<u8>> {
    let hex_str = hex_str.trim_start_matches("0x");
    
    // Ensure even length
    let hex_str = if hex_str.len() % 2 == 1 {
        format!("0{}", hex_str)
    } else {
        hex_str.to_string()
    };
    
    (0..hex_str.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex_str[i..i + 2], 16)
                .map_err(|_| WireError::GenericError("Invalid hex string".to_string()))
        })
        .collect()
}

/// Convert a byte array to a hex string
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    format!("0x{}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>())
}

/// Convert a hex string to a GoldilocksField value
pub fn hex_to_field(hex_str: &str) -> WireResult<GoldilocksField> {
    let hex_str = hex_str.trim_start_matches("0x");
    let num = u64::from_str_radix(hex_str, 16)
        .map_err(|_| WireError::GenericError("Invalid hex string".to_string()))?;
    Ok(GoldilocksField::from_canonical_u64(num))
}

/// Convert a string to a GoldilocksField value
pub fn string_to_field(s: &str) -> WireResult<GoldilocksField> {
    if s.starts_with("0x") {
        hex_to_field(s)
    } else {
        let num = s.parse::<u64>()
            .map_err(|_| WireError::GenericError("Invalid number".to_string()))?;
        Ok(GoldilocksField::from_canonical_u64(num))
    }
}

/// Convert a decimal string to a GoldilocksField value
pub fn decimal_to_field(s: &str) -> WireResult<GoldilocksField> {
    let num = s.parse::<u64>()
        .map_err(|_| WireError::GenericError("Invalid number".to_string()))?;
    Ok(GoldilocksField::from_canonical_u64(num))
}

/// Convert a string to a vector of GoldilocksField values
pub fn string_to_fields(s: &str) -> WireResult<Vec<GoldilocksField>> {
    let mut result = Vec::new();
    
    if s.starts_with("0x") {
        let bytes = hex_to_bytes(s)?;
        for chunk in bytes.chunks(8) {
            let mut padded = [0u8; 8];
            for (i, &byte) in chunk.iter().enumerate() {
                padded[i] = byte;
            }
            let num = u64::from_le_bytes(padded);
            result.push(GoldilocksField::from_canonical_u64(num));
        }
    } else {
        // Assume comma-separated list of values
        for part in s.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            
            if part.starts_with("0x") {
                let field_val = u64::from_str_radix(part.trim_start_matches("0x"), 16)
                    .map_err(|_| WireError::GenericError("Invalid hex string".to_string()))?;
                result.push(GoldilocksField::from_canonical_u64(field_val));
            } else {
                let num = part.parse::<u64>()
                    .map_err(|_| WireError::GenericError("Invalid number".to_string()))?;
                result.push(GoldilocksField::from_canonical_u64(num));
            }
        }
    }
    
    Ok(result)
}
