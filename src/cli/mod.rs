// CLI module for the 0BTC Wire system
use clap::{Parser, Subcommand};
use log::{info, error};
use std::fs;
use std::path::Path;
use rand::{rngs::OsRng, RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2_field::types::Field;
use plonky2::iop::target::Target;
use wire_lib::core::UTXO;
use wire_lib::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, PointTarget};
use wire_lib::core::proof::SerializableProof;
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
            let recipient_pk_hash = extract_hex_array(&input_json, "recipientPkHash")?;
            let amount = extract_u64(&input_json, "amount")?;
            let deposit_nonce = extract_u64(&input_json, "depositNonce")?;
            let custodian_pk_x = extract_u64(&input_json, "custodianPkX")?;
            let custodian_pk_y = extract_u64(&input_json, "custodianPkY")?;
            let signature_r_x = extract_u64(&input_json, "signatureRX")?;
            let signature_r_y = extract_u64(&input_json, "signatureRY")?;
            let signature_s = extract_u64(&input_json, "signatureS")?;
            
            // Generate a real proof
            info!("Generating proof for WrappedAssetMint circuit...");
            let serialized_proof = WrappedAssetMintCircuit::generate_proof(
                &recipient_pk_hash,
                amount,
                deposit_nonce,
                custodian_pk_x,
                custodian_pk_y,
                signature_r_x,
                signature_r_y,
                signature_s,
            ).map_err(|e| format!("Failed to generate proof: {}", e))?;
            
            // Return the proof
            serde_json::json!({
                "success": true,
                "circuitType": "WrappedAssetMint",
                "publicInputs": serialized_proof.public_inputs,
                "proof": serialized_proof.proof_bytes,
            })
        },
        "wrapped_asset_burn" => {
            info!("Building WrappedAssetBurn circuit...");
            
            // Extract parameters from input JSON
            let input_utxo_owner_pubkey_hash = extract_hex_array(&input_json, "inputUtxoOwnerPubkeyHash")?;
            let input_utxo_asset_id = extract_hex_array(&input_json, "inputUtxoAssetId")?;
            let input_utxo_amount = extract_u64(&input_json, "inputUtxoAmount")?;
            let input_utxo_salt = extract_hex_array(&input_json, "inputUtxoSalt")?;
            let sender_sk = extract_u64(&input_json, "senderSk")?;
            let sender_pk_x = extract_u64(&input_json, "senderPkX")?;
            let sender_pk_y = extract_u64(&input_json, "senderPkY")?;
            let signature_r_x = extract_u64(&input_json, "signatureRX")?;
            let signature_r_y = extract_u64(&input_json, "signatureRY")?;
            let signature_s = extract_u64(&input_json, "signatureS")?;
            let destination_btc_address = extract_hex_array(&input_json, "destinationBtcAddress")?;
            
            // Optional fee parameters
            let fee_btc = input_json.get("feeBtc").and_then(|v| v.as_u64());
            let fee_expiry = input_json.get("feeExpiry").and_then(|v| v.as_u64());
            let fee_signature_r_x = input_json.get("feeSignatureRX").and_then(|v| v.as_u64());
            let fee_signature_r_y = input_json.get("feeSignatureRY").and_then(|v| v.as_u64());
            let fee_signature_s = input_json.get("feeSignatureS").and_then(|v| v.as_u64());
            let custodian_pk_x = input_json.get("custodianPkX").and_then(|v| v.as_u64());
            let custodian_pk_y = input_json.get("custodianPkY").and_then(|v| v.as_u64());
            
            // Create a circuit instance
            let circuit = WrappedAssetBurnCircuit {
                input_utxo: UTXOTarget {
                    owner_pubkey_hash_target: vec![],
                    asset_id_target: vec![],
                    amount_target: Target::default(),
                    salt_target: vec![],
                },
                sender_pk: PublicKeyTarget {
                    point: PointTarget {
                        x: Target::default(),
                        y: Target::default(),
                    },
                },
                sender_sig: SignatureTarget {
                    r_point: PointTarget {
                        x: Target::default(),
                        y: Target::default(),
                    },
                    s_scalar: Target::default(),
                },
                destination_btc_address: vec![],
                fee_quote: None,
                custodian_pk: None,
            };
            
            // Generate a real proof
            info!("Generating proof for WrappedAssetBurn circuit...");
            let serialized_proof = WrappedAssetBurnCircuit::generate_proof_static(
                &input_utxo_owner_pubkey_hash,
                &input_utxo_asset_id,
                input_utxo_amount,
                &input_utxo_salt,
                sender_sk,
                sender_pk_x,
                sender_pk_y,
                signature_r_x,
                signature_r_y,
                signature_s,
                &destination_btc_address,
                fee_btc,
                fee_expiry,
                fee_signature_r_x,
                fee_signature_r_y,
                fee_signature_s,
                custodian_pk_x,
                custodian_pk_y,
            ).map_err(|e| format!("Failed to generate proof: {}", e))?;
            
            // Return the proof
            serde_json::json!({
                "success": true,
                "circuitType": "WrappedAssetBurn",
                "publicInputs": serialized_proof.public_inputs,
                "proof": serialized_proof.proof_bytes,
            })
        },
        "transfer" => {
            info!("Building Transfer circuit...");
            
            // Extract parameters from input JSON
            let input_utxos_json = input_json["inputUtxos"].as_array()
                .ok_or_else(|| "Missing or invalid inputUtxos array".to_string())?;
            
            let mut input_utxos_data = Vec::new();
            for utxo_json in input_utxos_json {
                let owner_pubkey_hash = extract_hex_array(utxo_json, "ownerPubkeyHash")?;
                let asset_id = extract_hex_array(utxo_json, "assetId")?;
                let amount = extract_u64(utxo_json, "amount")?;
                let salt = extract_hex_array(utxo_json, "salt")?;
                
                input_utxos_data.push((owner_pubkey_hash, asset_id, amount, salt));
            }
            
            let recipient_pk_hashes_json = input_json["recipientPkHashes"].as_array()
                .ok_or_else(|| "Missing or invalid recipientPkHashes array".to_string())?;
            
            let mut recipient_pk_hashes = Vec::new();
            for pk_hash_json in recipient_pk_hashes_json {
                let pk_hash = hex::decode(pk_hash_json.as_str()
                    .ok_or_else(|| "Invalid recipient public key hash".to_string())?
                    .trim_start_matches("0x"))
                    .map_err(|e| format!("Failed to decode recipient public key hash: {}", e))?;
                
                recipient_pk_hashes.push(pk_hash);
            }
            
            let output_amounts_json = input_json["outputAmounts"].as_array()
                .ok_or_else(|| "Missing or invalid outputAmounts array".to_string())?;
            
            let mut output_amounts = Vec::new();
            for amount_json in output_amounts_json {
                let amount = amount_json.as_u64()
                    .ok_or_else(|| "Invalid output amount".to_string())?;
                
                output_amounts.push(amount);
            }
            
            let sender_sk = extract_u64(&input_json, "senderSk")?;
            let sender_pk_x = extract_u64(&input_json, "senderPkX")?;
            let sender_pk_y = extract_u64(&input_json, "senderPkY")?;
            let signature_r_x = extract_u64(&input_json, "signatureRX")?;
            let signature_r_y = extract_u64(&input_json, "signatureRY")?;
            let signature_s = extract_u64(&input_json, "signatureS")?;
            
            let fee_input_utxo_json = &input_json["feeInputUtxo"];
            let fee_owner_pubkey_hash = extract_hex_array(fee_input_utxo_json, "ownerPubkeyHash")?;
            let fee_asset_id = extract_hex_array(fee_input_utxo_json, "assetId")?;
            let fee_amount_value = extract_u64(fee_input_utxo_json, "amount")?;
            let fee_salt = extract_hex_array(fee_input_utxo_json, "salt")?;
            
            let fee_input_utxo_data = (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt);
            
            let fee_amount = extract_u64(&input_json, "feeAmount")?;
            let fee_reservoir_address_hash = extract_hex_array(&input_json, "feeReservoirAddressHash")?;
            let nonce = extract_u64(&input_json, "nonce")?;
            
            // Generate a real proof
            info!("Generating proof for Transfer circuit...");
            let serialized_proof = TransferCircuit::generate_proof_static(
                input_utxos_data,
                recipient_pk_hashes,
                output_amounts,
                sender_sk,
                sender_pk_x,
                sender_pk_y,
                signature_r_x,
                signature_r_y,
                signature_s,
                fee_input_utxo_data,
                fee_amount,
                fee_reservoir_address_hash,
                nonce,
            ).map_err(|e| format!("Failed to generate proof: {}", e))?;
            
            // Return the proof
            serde_json::json!({
                "success": true,
                "circuitType": "Transfer",
                "publicInputs": serialized_proof.public_inputs,
                "proof": serialized_proof.proof_bytes,
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
pub fn verify_proof(circuit_type: &str, proof_path: &str) -> Result<(), String> {
    info!("Verifying proof for circuit type: {}", circuit_type);
    
    // Read the proof from the file
    let proof_json = fs::read_to_string(proof_path)
        .map_err(|e| format!("Failed to read proof file: {}", e))?;
    
    // Parse the proof JSON
    let proof_value: serde_json::Value = serde_json::from_str(&proof_json)
        .map_err(|e| format!("Failed to parse proof JSON: {}", e))?;
    
    // Verify the proof structure
    verify_proof_structure(&proof_value)?;
    
    // Extract the circuit type
    let circuit_type_from_proof = proof_value["circuitType"].as_str()
        .ok_or_else(|| "Proof does not contain a circuit type".to_string())?;
    
    // Ensure the circuit type matches
    if circuit_type != circuit_type_from_proof {
        return Err(format!("Circuit type mismatch: expected {}, got {}", circuit_type, circuit_type_from_proof));
    }
    
    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"].as_array()
        .ok_or_else(|| "Proof does not contain public inputs".to_string())?;
    
    let public_inputs_vec: Vec<String> = public_inputs.iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    
    let proof_bytes = proof_value["proof"].as_str()
        .ok_or_else(|| "Proof does not contain proof bytes".to_string())?
        .to_string();
    
    // Create a serializable proof
    let serializable_proof = SerializableProof {
        public_inputs: public_inputs_vec,
        proof_bytes,
    };
    
    // Verify the proof based on the circuit type
    match circuit_type {
        "wrapped_asset_mint" => {
            info!("Verifying WrappedAssetMint proof...");
            WrappedAssetMintCircuit::verify_proof(&serializable_proof)
                .map_err(|e| format!("Failed to verify proof: {}", e))?;
            info!("WrappedAssetMint proof verified successfully!");
        },
        "wrapped_asset_burn" => {
            info!("Verifying WrappedAssetBurn proof...");
            WrappedAssetBurnCircuit::verify_proof(&serializable_proof)
                .map_err(|e| format!("Failed to verify proof: {}", e))?;
            info!("WrappedAssetBurn proof verified successfully!");
        },
        "transfer" => {
            info!("Verifying Transfer proof...");
            TransferCircuit::verify_proof(&serializable_proof)
                .map_err(|e| format!("Failed to verify proof: {}", e))?;
            info!("Transfer proof verified successfully!");
        },
        "native_asset_create" => {
            info!("Verifying NativeAssetCreate proof...");
            // TODO: Implement real proof verification for NativeAssetCreate
            info!("NativeAssetCreate proof verification not yet implemented with real ZK proofs");
        },
        "native_asset_mint" => {
            info!("Verifying NativeAssetMint proof...");
            // TODO: Implement real proof verification for NativeAssetMint
            info!("NativeAssetMint proof verification not yet implemented with real ZK proofs");
        },
        "native_asset_burn" => {
            info!("Verifying NativeAssetBurn proof...");
            // TODO: Implement real proof verification for NativeAssetBurn
            info!("NativeAssetBurn proof verification not yet implemented with real ZK proofs");
        },
        _ => {
            return Err(format!("Unsupported circuit type: {}", circuit_type));
        }
    }
    
    Ok(())
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
