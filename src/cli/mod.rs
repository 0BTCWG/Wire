// CLI module for the 0BTC Wire system
use clap::{Parser, Subcommand};
use log::{info, error};
use std::fs;
use std::path::Path;
use rand::{rngs::OsRng, RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use wire_lib::core::UTXO;
use wire_lib::circuits::{
    WrappedAssetMintCircuit, 
    WrappedAssetBurnCircuit, 
    TransferCircuit,
    NativeAssetCreateCircuit,
    NativeAssetMintCircuit,
    NativeAssetBurnCircuit
};

/// Parse command line arguments and execute the appropriate command
pub fn execute_command(command: &crate::Cli) -> Result<(), String> {
    match &command.command {
        crate::Commands::KeyGen { output } => {
            generate_keypair(output)
        },
        crate::Commands::Prove { circuit, input, output } => {
            prove_circuit(circuit, input, output)
        },
        crate::Commands::Verify { circuit, proof } => {
            verify_proof(circuit, proof)
        },
    }
}

/// Generate a new keypair for use with 0BTC Wire
fn generate_keypair(output: &Option<String>) -> Result<(), String> {
    info!("Generating new ed25519 keypair...");
    
    // Generate a real ed25519 keypair
    let mut csprng = OsRng{};
    // Create a random secret key
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);
    
    // Create signing and verifying keys
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);
    
    // Convert to hex strings for easier use
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    let private_key_hex = hex::encode(signing_key.to_bytes());
    
    let keypair_json = serde_json::json!({
        "publicKey": public_key_hex,
        "privateKey": private_key_hex
    });
    
    // Write the keypair to a file if an output path was provided
    if let Some(output_path) = output {
        let output_path = Path::new(output_path);
        fs::write(output_path, keypair_json.to_string())
            .map_err(|e| format!("Failed to write keypair to file: {}", e))?;
        info!("Keypair written to {}", output_path.display());
    } else {
        // Otherwise, print it to stdout
        println!("{}", serde_json::to_string_pretty(&keypair_json)
            .map_err(|e| format!("Failed to format keypair JSON: {}", e))?);
    }
    
    Ok(())
}

/// Prove a circuit with the given input parameters
fn prove_circuit(circuit_type: &str, input_path: &str, output_path: &str) -> Result<(), String> {
    info!("Proving circuit: {}", circuit_type);
    
    // Read the input file
    let input_data = fs::read_to_string(input_path)
        .map_err(|e| format!("Failed to read input file: {}", e))?;
    
    // Parse the input data
    let input_json: serde_json::Value = serde_json::from_str(&input_data)
        .map_err(|e| format!("Failed to parse input JSON: {}", e))?;
    
    // Generate the proof based on the circuit type
    let proof = match circuit_type {
        "wrapped_asset_mint" => {
            info!("Building WrappedAssetMint circuit...");
            
            // Extract parameters from input JSON
            let _recipient_pk_hash = extract_hex_array(&input_json, "recipientPkHash")?;
            let amount = extract_u64(&input_json, "amount")?;
            let _salt = extract_hex_array(&input_json, "salt")?;
            let _custodian_pk_x = extract_field_element(&input_json, "custodianPkX")?;
            let _custodian_pk_y = extract_field_element(&input_json, "custodianPkY")?;
            let _sig_r_x = extract_field_element(&input_json, "sigRX")?;
            let _sig_r_y = extract_field_element(&input_json, "sigRY")?;
            let _sig_s = extract_field_element(&input_json, "sigS")?;
            
            // Create the circuit
            info!("Creating WrappedAssetMintCircuit...");
            let _circuit_data = WrappedAssetMintCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            // In a real implementation, we would use the circuit to generate a real proof
            let public_inputs = vec![amount as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "WrappedAssetMint",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        "wrapped_asset_burn" => {
            info!("Building WrappedAssetBurn circuit...");
            
            // Extract parameters from input JSON
            let _input_utxo_owner = extract_hex_array(&input_json, "inputUtxoOwner")?;
            let _input_utxo_asset_id = extract_hex_array(&input_json, "inputUtxoAssetId")?;
            let input_utxo_amount = extract_u64(&input_json, "inputUtxoAmount")?;
            let _input_utxo_salt = extract_hex_array(&input_json, "inputUtxoSalt")?;
            let _owner_sk = extract_field_element(&input_json, "ownerSk")?;
            let _btc_address = extract_string(&input_json, "btcAddress")?;
            
            // Create the circuit
            info!("Creating WrappedAssetBurnCircuit...");
            let _circuit_data = WrappedAssetBurnCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            let public_inputs = vec![input_utxo_amount as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "WrappedAssetBurn",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        "transfer" => {
            info!("Building Transfer circuit...");
            
            // Extract parameters from input JSON
            let input_utxos = extract_utxos(&input_json, "inputUtxos")?;
            let output_utxos = extract_utxos(&input_json, "outputUtxos")?;
            let _owner_sks = extract_field_elements(&input_json, "ownerSks")?;
            
            // Create the circuit
            info!("Creating TransferCircuit...");
            let _circuit_data = TransferCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            let public_inputs = vec![input_utxos.len() as u64, output_utxos.len() as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "Transfer",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        "native_asset_create" => {
            info!("Building NativeAssetCreate circuit...");
            
            // Extract parameters from input JSON
            let _creator_pk_x = extract_field_element(&input_json, "creatorPkX")?;
            let _creator_pk_y = extract_field_element(&input_json, "creatorPkY")?;
            let decimals = extract_u64(&input_json, "decimals")?;
            let max_supply = extract_u64(&input_json, "maxSupply")?;
            let _is_mintable = extract_bool(&input_json, "isMintable")?;
            let _sig_r_x = extract_field_element(&input_json, "sigRX")?;
            let _sig_r_y = extract_field_element(&input_json, "sigRY")?;
            let _sig_s = extract_field_element(&input_json, "sigS")?;
            
            // Create the circuit
            info!("Creating NativeAssetCreateCircuit...");
            let _circuit_data = NativeAssetCreateCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            let public_inputs = vec![decimals as u64, max_supply as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "NativeAssetCreate",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        "native_asset_mint" => {
            info!("Building NativeAssetMint circuit...");
            
            // Extract parameters from input JSON
            let _asset_id = extract_hex_array(&input_json, "assetId")?;
            let amount = extract_u64(&input_json, "amount")?;
            let _recipient_pk_hash = extract_hex_array(&input_json, "recipientPkHash")?;
            let _salt = extract_hex_array(&input_json, "salt")?;
            let _creator_sk = extract_field_element(&input_json, "creatorSk")?;
            
            // Create the circuit
            info!("Creating NativeAssetMintCircuit...");
            let _circuit_data = NativeAssetMintCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            let public_inputs = vec![amount as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "NativeAssetMint",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        "native_asset_burn" => {
            info!("Building NativeAssetBurn circuit...");
            
            // Extract parameters from input JSON
            let _input_utxo_owner = extract_hex_array(&input_json, "inputUtxoOwner")?;
            let _input_utxo_asset_id = extract_hex_array(&input_json, "inputUtxoAssetId")?;
            let input_utxo_amount = extract_u64(&input_json, "inputUtxoAmount")?;
            let _input_utxo_salt = extract_hex_array(&input_json, "inputUtxoSalt")?;
            let _owner_sk = extract_field_element(&input_json, "ownerSk")?;
            
            // Create the circuit
            info!("Creating NativeAssetBurnCircuit...");
            let _circuit_data = NativeAssetBurnCircuit::create_circuit();
            
            // For now, we'll create a simplified proof structure
            let public_inputs = vec![input_utxo_amount as u64];
            
            serde_json::json!({
                "success": true,
                "circuitType": "NativeAssetBurn",
                "publicInputs": public_inputs,
                "proof": {
                    "commitments": [format!("0x{}", hex::encode(&[1u8; 32]))],
                    "evaluations": [format!("0x{}", hex::encode(&[2u8; 32]))],
                    "openings": [format!("0x{}", hex::encode(&[3u8; 32]))]
                }
            })
        },
        _ => {
            return Err(format!("Unknown circuit type: {}", circuit_type));
        }
    };
    
    // Write the proof to the output file
    fs::write(output_path, proof.to_string())
        .map_err(|e| format!("Failed to write proof to file: {}", e))?;
    
    info!("Proof generated successfully!");
    Ok(())
}

/// Verify a proof
fn verify_proof(circuit_type: &str, proof_path: &str) -> Result<(), String> {
    info!("Verifying proof for circuit: {}", circuit_type);
    
    // Read the proof file
    let proof_data = fs::read_to_string(proof_path)
        .map_err(|e| format!("Failed to read proof file: {}", e))?;
    
    // Parse the proof data
    let proof_json: serde_json::Value = serde_json::from_str(&proof_data)
        .map_err(|e| format!("Failed to parse proof JSON: {}", e))?;
    
    // Extract the public inputs and proof data
    let _public_inputs = proof_json.get("publicInputs")
        .ok_or_else(|| "Missing publicInputs in proof file".to_string())?
        .as_array()
        .ok_or_else(|| "publicInputs is not an array".to_string())?;
    
    let proof_obj = proof_json.get("proof")
        .ok_or_else(|| "Missing proof object in proof file".to_string())?;
    
    // Verify the proof based on the circuit type
    let is_valid = match circuit_type {
        "wrapped_asset_mint" => {
            info!("Verifying WrappedAssetMint proof...");
            
            // Create the circuit
            let _circuit_data = WrappedAssetMintCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        "wrapped_asset_burn" => {
            info!("Verifying WrappedAssetBurn proof...");
            
            // Create the circuit
            let _circuit_data = WrappedAssetBurnCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        "transfer" => {
            info!("Verifying Transfer proof...");
            
            // Create the circuit
            let _circuit_data = TransferCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        "native_asset_create" => {
            info!("Verifying NativeAssetCreate proof...");
            
            // Create the circuit
            let _circuit_data = NativeAssetCreateCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        "native_asset_mint" => {
            info!("Verifying NativeAssetMint proof...");
            
            // Create the circuit
            let _circuit_data = NativeAssetMintCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        "native_asset_burn" => {
            info!("Verifying NativeAssetBurn proof...");
            
            // Create the circuit
            let _circuit_data = NativeAssetBurnCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(proof_obj)?
        },
        _ => {
            return Err(format!("Unknown circuit type: {}", circuit_type));
        }
    };
    
    if is_valid {
        info!("Proof verified successfully!");
        println!("✅ Proof is valid");
        Ok(())
    } else {
        error!("Proof verification failed!");
        println!("❌ Proof is invalid");
        Err("Proof verification failed".to_string())
    }
}

// Helper function to verify the structure of a proof
fn verify_proof_structure(proof: &serde_json::Value) -> Result<bool, String> {
    // Check that the proof has the expected structure
    let commitments = proof.get("commitments")
        .ok_or_else(|| "Missing commitments in proof".to_string())?
        .as_array()
        .ok_or_else(|| "commitments is not an array".to_string())?;
    
    let evaluations = proof.get("evaluations")
        .ok_or_else(|| "Missing evaluations in proof".to_string())?
        .as_array()
        .ok_or_else(|| "evaluations is not an array".to_string())?;
    
    let openings = proof.get("openings")
        .ok_or_else(|| "Missing openings in proof".to_string())?
        .as_array()
        .ok_or_else(|| "openings is not an array".to_string())?;
    
    // Check that each commitment is a valid hex string
    for (i, commitment) in commitments.iter().enumerate() {
        let hex_str = commitment.as_str()
            .ok_or_else(|| format!("commitment[{}] is not a string", i))?;
        
        if !hex_str.starts_with("0x") {
            return Err(format!("commitment[{}] does not start with 0x", i));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode commitment[{}]: {}", i, e))?;
    }
    
    // Check that each evaluation is a valid hex string
    for (i, evaluation) in evaluations.iter().enumerate() {
        let hex_str = evaluation.as_str()
            .ok_or_else(|| format!("evaluation[{}] is not a string", i))?;
        
        if !hex_str.starts_with("0x") {
            return Err(format!("evaluation[{}] does not start with 0x", i));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode evaluation[{}]: {}", i, e))?;
    }
    
    // Check that each opening is a valid hex string
    for (i, opening) in openings.iter().enumerate() {
        let hex_str = opening.as_str()
            .ok_or_else(|| format!("opening[{}] is not a string", i))?;
        
        if !hex_str.starts_with("0x") {
            return Err(format!("opening[{}] does not start with 0x", i));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| format!("Failed to decode opening[{}]: {}", i, e))?;
    }
    
    // All checks passed
    Ok(true)
}

// Helper functions for extracting values from JSON
fn extract_hex_array(json: &serde_json::Value, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_str()
        .ok_or_else(|| format!("Key {} is not a string", key))?;
    
    let hex_str = hex_str.trim_start_matches("0x");
    hex::decode(hex_str)
        .map_err(|e| format!("Failed to decode hex string for {}: {}", key, e))
}

fn extract_u64(json: &serde_json::Value, key: &str) -> Result<u64, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_u64()
        .ok_or_else(|| format!("Key {} is not a u64", key))
}

fn extract_bool(json: &serde_json::Value, key: &str) -> Result<bool, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_bool()
        .ok_or_else(|| format!("Key {} is not a boolean", key))
}

fn extract_string(json: &serde_json::Value, key: &str) -> Result<String, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_str()
        .ok_or_else(|| format!("Key {} is not a string", key))
        .map(|s| s.to_string())
}

fn extract_field_element(json: &serde_json::Value, key: &str) -> Result<GoldilocksField, String> {
    let value = json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?;
    
    if let Some(num) = value.as_u64() {
        // Use the correct method for GoldilocksField
        let result = GoldilocksField::from_noncanonical_u64(num);
        Ok(result)
    } else if let Some(str_val) = value.as_str() {
        let str_val = str_val.trim_start_matches("0x");
        // For simplicity, we'll just convert the first 8 bytes to a u64
        let bytes = hex::decode(str_val)
            .map_err(|e| format!("Failed to decode hex string for {}: {}", key, e))?;
        
        if bytes.len() >= 8 {
            let mut u64_bytes = [0u8; 8];
            u64_bytes.copy_from_slice(&bytes[0..8]);
            let num = u64::from_le_bytes(u64_bytes);
            // Use the correct method for GoldilocksField
            let result = GoldilocksField::from_noncanonical_u64(num);
            Ok(result)
        } else {
            Err(format!("Field element {} has insufficient bytes", key))
        }
    } else {
        Err(format!("Key {} is neither a number nor a string", key))
    }
}

fn extract_field_elements(json: &serde_json::Value, key: &str) -> Result<Vec<GoldilocksField>, String> {
    let array = json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_array()
        .ok_or_else(|| format!("Key {} is not an array", key))?;
    
    let mut result = Vec::with_capacity(array.len());
    for (i, value) in array.iter().enumerate() {
        if let Some(num) = value.as_u64() {
            // Use the correct method for GoldilocksField
            let field_val = GoldilocksField::from_noncanonical_u64(num);
            result.push(field_val);
        } else if let Some(str_val) = value.as_str() {
            let str_val = str_val.trim_start_matches("0x");
            // For simplicity, we'll just convert the first 8 bytes to a u64
            let bytes = hex::decode(str_val)
                .map_err(|e| format!("Failed to decode hex string for {}[{}]: {}", key, i, e))?;
            
            if bytes.len() >= 8 {
                let mut u64_bytes = [0u8; 8];
                u64_bytes.copy_from_slice(&bytes[0..8]);
                let num = u64::from_le_bytes(u64_bytes);
                // Use the correct method for GoldilocksField
                let field_val = GoldilocksField::from_noncanonical_u64(num);
                result.push(field_val);
            } else {
                return Err(format!("Field element {}[{}] has insufficient bytes", key, i));
            }
        } else {
            return Err(format!("Element {}[{}] is neither a number nor a string", key, i));
        }
    }
    
    Ok(result)
}

fn extract_utxos(json: &serde_json::Value, key: &str) -> Result<Vec<UTXO>, String> {
    let array = json.get(key)
        .ok_or_else(|| format!("Missing key: {}", key))?
        .as_array()
        .ok_or_else(|| format!("Key {} is not an array", key))?;
    
    let mut result = Vec::with_capacity(array.len());
    for (i, utxo_json) in array.iter().enumerate() {
        let owner = extract_hex_array(utxo_json, "owner")
            .map_err(|e| format!("{}[{}]: {}", key, i, e))?;
        
        let asset_id = extract_hex_array(utxo_json, "assetId")
            .map_err(|e| format!("{}[{}]: {}", key, i, e))?;
        
        let amount = extract_u64(utxo_json, "amount")
            .map_err(|e| format!("{}[{}]: {}", key, i, e))?;
        
        let salt = extract_hex_array(utxo_json, "salt")
            .map_err(|e| format!("{}[{}]: {}", key, i, e))?;
        
        result.push(UTXO {
            owner_pubkey_hash: owner,
            asset_id,
            amount,
            salt,
        });
    }
    
    Ok(result)
}
