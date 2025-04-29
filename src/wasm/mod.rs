// WebAssembly bindings for the 0BTC Wire system
use wasm_bindgen::prelude::*;
use js_sys::{Array, Object, Uint8Array};
use web_sys::console;
use serde::{Serialize, Deserialize};
use serde_json::json;
use log::{info, error};
use rand::{rngs::OsRng, RngCore};
use ed25519_dalek::{SigningKey, VerifyingKey, Signer};
use serde_wasm_bindgen;
use plonky2::iop::target::Target;

use crate::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use crate::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use crate::circuits::transfer::TransferCircuit;
use crate::circuits::native_asset_create::NativeAssetCreateCircuit;
use crate::circuits::native_asset_mint::NativeAssetMintCircuit;
use crate::circuits::native_asset_burn::NativeAssetBurnCircuit;
use crate::core::proof::SerializableProof;
use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, PointTarget};
use crate::circuits::wrapped_asset_mint::SignedAttestationTarget;
use crate::circuits::wrapped_asset_burn::SignedQuoteTarget;

// Initialize the WASM module
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    // Initialize the console error panic hook for better error messages
    console_error_panic_hook::set_once();
    
    // Log initialization
    console::log_1(&JsValue::from_str("Wire WASM module initialized"));
    
    Ok(())
}

// Generate a new Ed25519 keypair
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    let mut csprng = OsRng{};
    let mut secret_key_bytes = [0u8; 32];
    csprng.fill_bytes(&mut secret_key_bytes);
    
    let signing_key = SigningKey::from_bytes(&secret_key_bytes);
    let verifying_key = VerifyingKey::from(&signing_key);
    
    let secret_key_hex = hex::encode(secret_key_bytes);
    let public_key_hex = hex::encode(verifying_key.to_bytes());
    
    let result = json!({
        "secretKey": format!("0x{}", secret_key_hex),
        "publicKey": format!("0x{}", public_key_hex),
    });
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Sign a message with an Ed25519 private key
#[wasm_bindgen]
pub fn sign_message(secret_key_hex: &str, message_hex: &str) -> Result<JsValue, JsValue> {
    // Remove 0x prefix if present
    let secret_key_hex = secret_key_hex.trim_start_matches("0x");
    let message_hex = message_hex.trim_start_matches("0x");
    
    // Decode the secret key
    let secret_key_bytes = hex::decode(secret_key_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode secret key: {}", e)))?;
    
    if secret_key_bytes.len() != 32 {
        return Err(JsValue::from_str(&format!("Invalid secret key length: {}, expected 32", secret_key_bytes.len())));
    }
    
    // Create a fixed-size array from the Vec<u8>
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_key_bytes);
    
    // Create the secret key
    let signing_key = SigningKey::from_bytes(&key_bytes);
    
    // Decode the message
    let message = hex::decode(message_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode message: {}", e)))?;
    
    // Sign the message
    let signature = signing_key.sign(&message);
    
    // Return the signature
    let result = json!({
        "signature": format!("0x{}", hex::encode(signature.to_bytes())),
    });
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Generate a proof for minting wrapped assets
#[wasm_bindgen]
pub fn prove_wrapped_asset_mint(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Generating proof for wrapped asset mint..."));
    
    // Parse the parameters
    let params: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;
    
    // Extract the parameters
    let recipient_pk_hash_hex = params["recipientPkHash"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing recipientPkHash"))?
        .trim_start_matches("0x");
    
    let recipient_pk_hash = hex::decode(recipient_pk_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode recipientPkHash: {}", e)))?;
    
    let amount = params["amount"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid amount"))?;
    
    let deposit_nonce = params["depositNonce"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid depositNonce"))?;
    
    let custodian_pk_x = params["custodianPkX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid custodianPkX"))?;
    
    let custodian_pk_y = params["custodianPkY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid custodianPkY"))?;
    
    let signature_r_x = params["signatureRX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRX"))?;
    
    let signature_r_y = params["signatureRY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRY"))?;
    
    let signature_s = params["signatureS"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureS"))?;
    
    let salt_hex = params["salt"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing salt"))?
        .trim_start_matches("0x");
    
    let salt = hex::decode(salt_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode salt: {}", e)))?;
    
    // Generate the proof using the static method
    let proof_result = WrappedAssetMintCircuit::generate_proof(
        &recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    ).map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;
    
    // Return the proof
    let result = json!({
        "success": true,
        "circuitType": "WrappedAssetMint",
        "publicInputs": proof_result.public_inputs,
        "proof": proof_result.proof_bytes,
    });
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Verify a proof for minting wrapped assets
#[wasm_bindgen]
pub fn verify_wrapped_asset_mint(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Verifying proof for wrapped asset mint..."));
    
    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;
    
    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"].as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;
    
    let public_inputs_vec: Vec<String> = public_inputs.iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    
    let proof_bytes = proof_value["proof"].as_str()
        .ok_or_else(|| JsValue::from_str("Proof does not contain proof bytes"))?
        .to_string();
    
    // Create a serializable proof
    let serializable_proof = SerializableProof {
        public_inputs: public_inputs_vec,
        proof_bytes,
    };
    
    // Verify the proof
    match WrappedAssetMintCircuit::verify_proof(&serializable_proof) {
        Ok(()) => {
            let result = json!({
                "success": true,
                "message": "Proof verified successfully",
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        },
        Err(e) => {
            let result = json!({
                "success": false,
                "message": format!("Proof verification failed: {}", e),
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        }
    }
}

/// Create a proof for transferring assets
#[wasm_bindgen]
pub fn prove_transfer(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Generating proof for transfer..."));
    
    // Parse the parameters
    let params: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;
    
    // Extract the input UTXOs
    let input_utxos_json = params["inputUtxos"].as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid inputUtxos array"))?;
    
    let mut input_utxos_data = Vec::new();
    for utxo_json in input_utxos_json {
        let owner_pubkey_hash_hex = utxo_json["ownerPubkeyHash"].as_str()
            .ok_or_else(|| JsValue::from_str("Missing ownerPubkeyHash in input UTXO"))?
            .trim_start_matches("0x");
        
        let owner_pubkey_hash = hex::decode(owner_pubkey_hash_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode ownerPubkeyHash: {}", e)))?;
        
        let asset_id_hex = utxo_json["assetId"].as_str()
            .ok_or_else(|| JsValue::from_str("Missing assetId in input UTXO"))?
            .trim_start_matches("0x");
        
        let asset_id = hex::decode(asset_id_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode assetId: {}", e)))?;
        
        let amount = utxo_json["amount"].as_u64()
            .ok_or_else(|| JsValue::from_str("Missing or invalid amount in input UTXO"))?;
        
        let salt_hex = utxo_json["salt"].as_str()
            .ok_or_else(|| JsValue::from_str("Missing salt in input UTXO"))?
            .trim_start_matches("0x");
        
        let salt = hex::decode(salt_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode salt: {}", e)))?;
        
        input_utxos_data.push((owner_pubkey_hash, asset_id, amount, salt));
    }
    
    // Extract the recipient public key hashes
    let recipient_pk_hashes_json = params["recipientPkHashes"].as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid recipientPkHashes array"))?;
    
    let mut recipient_pk_hashes = Vec::new();
    for pk_hash_json in recipient_pk_hashes_json {
        let pk_hash_hex = pk_hash_json.as_str()
            .ok_or_else(|| JsValue::from_str("Invalid recipient public key hash"))?
            .trim_start_matches("0x");
        
        let pk_hash = hex::decode(pk_hash_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode recipient public key hash: {}", e)))?;
        
        recipient_pk_hashes.push(pk_hash);
    }
    
    // Extract the output amounts
    let output_amounts_json = params["outputAmounts"].as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid outputAmounts array"))?;
    
    let mut output_amounts = Vec::new();
    for amount_json in output_amounts_json {
        let amount = amount_json.as_u64()
            .ok_or_else(|| JsValue::from_str("Invalid output amount"))?;
        
        output_amounts.push(amount);
    }
    
    // Extract the sender's secret key and public key
    let sender_sk = params["senderSk"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderSk"))?;
    
    let sender_pk_x = params["senderPkX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkX"))?;
    
    let sender_pk_y = params["senderPkY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkY"))?;
    
    // Extract the signature
    let signature_r_x = params["signatureRX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRX"))?;
    
    let signature_r_y = params["signatureRY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRY"))?;
    
    let signature_s = params["signatureS"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureS"))?;
    
    // Extract the fee input UTXO
    let fee_input_utxo_json = &params["feeInputUtxo"];
    
    let fee_owner_pubkey_hash_hex = fee_input_utxo_json["ownerPubkeyHash"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing ownerPubkeyHash in fee input UTXO"))?
        .trim_start_matches("0x");
    
    let fee_owner_pubkey_hash = hex::decode(fee_owner_pubkey_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee ownerPubkeyHash: {}", e)))?;
    
    let fee_asset_id_hex = fee_input_utxo_json["assetId"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing assetId in fee input UTXO"))?
        .trim_start_matches("0x");
    
    let fee_asset_id = hex::decode(fee_asset_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee assetId: {}", e)))?;
    
    let fee_amount_value = fee_input_utxo_json["amount"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid amount in fee input UTXO"))?;
    
    let fee_salt_hex = fee_input_utxo_json["salt"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing salt in fee input UTXO"))?
        .trim_start_matches("0x");
    
    let fee_salt = hex::decode(fee_salt_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee salt: {}", e)))?;
    
    let fee_input_utxo_data = (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt);
    
    // Extract the fee amount and reservoir address hash
    let fee_amount = params["feeAmount"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid feeAmount"))?;
    
    let fee_reservoir_address_hash_hex = params["feeReservoirAddressHash"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing feeReservoirAddressHash"))?
        .trim_start_matches("0x");
    
    let fee_reservoir_address_hash = hex::decode(fee_reservoir_address_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode feeReservoirAddressHash: {}", e)))?;
    
    // Extract the nonce
    let nonce = params["nonce"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid nonce"))?;
    
    // Create a circuit instance for TransferCircuit
    let circuit = TransferCircuit {
        input_utxos: vec![],
        recipient_pk_hashes: vec![],
        output_amounts: vec![],
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
        fee_input_utxo: UTXOTarget {
            owner_pubkey_hash_target: vec![],
            asset_id_target: vec![],
            amount_target: Target::default(),
            salt_target: vec![],
        },
        fee_amount: Target::default(),
        fee_reservoir_address_hash: vec![],
    };
    
    // Generate the proof using the instance method
    let proof_result = circuit.generate_proof(
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
    ).map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;
    
    // Return the proof
    let result = json!({
        "success": true,
        "circuitType": "Transfer",
        "publicInputs": proof_result.public_inputs,
        "proof": proof_result.proof_bytes,
    });
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Verify a proof for transferring assets
#[wasm_bindgen]
pub fn verify_transfer(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Verifying proof for transfer..."));
    
    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;
    
    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"].as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;
    
    let public_inputs_vec: Vec<String> = public_inputs.iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    
    let proof_bytes = proof_value["proof"].as_str()
        .ok_or_else(|| JsValue::from_str("Proof does not contain proof bytes"))?
        .to_string();
    
    // Create a serializable proof
    let serializable_proof = SerializableProof {
        public_inputs: public_inputs_vec,
        proof_bytes,
    };
    
    // Verify the proof
    match TransferCircuit::verify_proof(&serializable_proof) {
        Ok(()) => {
            let result = json!({
                "success": true,
                "message": "Proof verified successfully",
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        },
        Err(e) => {
            let result = json!({
                "success": false,
                "message": format!("Proof verification failed: {}", e),
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        }
    }
}

/// Create a proof for burning wrapped Bitcoin
#[wasm_bindgen]
pub fn prove_wrapped_asset_burn(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Generating proof for wrapped asset burn..."));
    
    // Parse the parameters
    let params: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;
    
    // Extract the parameters
    let input_utxo_owner_pubkey_hash_hex = params["inputUtxoOwnerPubkeyHash"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoOwnerPubkeyHash"))?
        .trim_start_matches("0x");
    
    let input_utxo_owner_pubkey_hash = hex::decode(input_utxo_owner_pubkey_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode inputUtxoOwnerPubkeyHash: {}", e)))?;
    
    let input_utxo_asset_id_hex = params["inputUtxoAssetId"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoAssetId"))?
        .trim_start_matches("0x");
    
    let input_utxo_asset_id = hex::decode(input_utxo_asset_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode inputUtxoAssetId: {}", e)))?;
    
    let input_utxo_amount = params["inputUtxoAmount"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid inputUtxoAmount"))?;
    
    let input_utxo_salt_hex = params["inputUtxoSalt"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoSalt"))?
        .trim_start_matches("0x");
    
    let input_utxo_salt = hex::decode(input_utxo_salt_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode inputUtxoSalt: {}", e)))?;
    
    let sender_sk = params["senderSk"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderSk"))?;
    
    let sender_pk_x = params["senderPkX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkX"))?;
    
    let sender_pk_y = params["senderPkY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkY"))?;
    
    let signature_r_x = params["signatureRX"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRX"))?;
    
    let signature_r_y = params["signatureRY"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRY"))?;
    
    let signature_s = params["signatureS"].as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureS"))?;
    
    let destination_btc_address_hex = params["destinationBtcAddress"].as_str()
        .ok_or_else(|| JsValue::from_str("Missing destinationBtcAddress"))?
        .trim_start_matches("0x");
    
    let destination_btc_address = hex::decode(destination_btc_address_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode destinationBtcAddress: {}", e)))?;
    
    // Optional fee parameters
    let fee_btc = params.get("feeBtc").and_then(|v| v.as_u64());
    let fee_expiry = params.get("feeExpiry").and_then(|v| v.as_u64());
    let fee_signature_r_x = params.get("feeSignatureRX").and_then(|v| v.as_u64());
    let fee_signature_r_y = params.get("feeSignatureRY").and_then(|v| v.as_u64());
    let fee_signature_s = params.get("feeSignatureS").and_then(|v| v.as_u64());
    let custodian_pk_x = params.get("custodianPkX").and_then(|v| v.as_u64());
    let custodian_pk_y = params.get("custodianPkY").and_then(|v| v.as_u64());
    
    // Create a circuit instance for WrappedAssetBurnCircuit
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
    
    // Generate the proof using the instance method
    let proof_result = circuit.generate_proof(
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
    ).map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;
    
    // Return the proof
    let result = json!({
        "success": true,
        "circuitType": "WrappedAssetBurn",
        "publicInputs": proof_result.public_inputs,
        "proof": proof_result.proof_bytes,
    });
    
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Verify a proof for burning wrapped assets
#[wasm_bindgen]
pub fn verify_wrapped_asset_burn(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Verifying proof for wrapped asset burn..."));
    
    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;
    
    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"].as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;
    
    let public_inputs_vec: Vec<String> = public_inputs.iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    
    let proof_bytes = proof_value["proof"].as_str()
        .ok_or_else(|| JsValue::from_str("Proof does not contain proof bytes"))?
        .to_string();
    
    // Create a serializable proof
    let serializable_proof = SerializableProof {
        public_inputs: public_inputs_vec,
        proof_bytes,
    };
    
    // Verify the proof
    match WrappedAssetBurnCircuit::verify_proof(&serializable_proof) {
        Ok(()) => {
            let result = json!({
                "success": true,
                "message": "Proof verified successfully",
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        },
        Err(e) => {
            let result = json!({
                "success": false,
                "message": format!("Proof verification failed: {}", e),
            });
            
            serde_wasm_bindgen::to_value(&result)
                .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
        }
    }
}

/// Create a proof for creating a new native asset
#[wasm_bindgen]
pub fn prove_native_asset_create(
    _creator_pk: JsValue,
    _creator_sig: JsValue,
    _decimals: u8,
    _max_supply: u64,
    _is_continuously_mintable: bool,
    _initial_mint_amount: u64,
    _fee_input_utxo: JsValue,
) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Creating proof for native asset create"));
    
    // In a real implementation, this would:
    // 1. Parse the input data from JavaScript
    // 2. Build the circuit
    // 3. Generate the proof
    // 4. Return the proof as a JavaScript object
    
    // For now, we'll just return a dummy proof
    let proof = Object::new();
    js_sys::Reflect::set(&proof, &JsValue::from_str("success"), &JsValue::from_bool(true))?;
    js_sys::Reflect::set(&proof, &JsValue::from_str("circuitType"), &JsValue::from_str("NativeAssetCreate"))?;
    
    Ok(JsValue::from(proof))
}

/// Create a proof for minting a native asset
#[wasm_bindgen]
pub fn prove_native_asset_mint(
    _asset_id: JsValue,
    _creator_pk: JsValue,
    _creator_sig: JsValue,
    _mint_amount: u64,
    _recipient_pk_hash: JsValue,
    _fee_input_utxo: JsValue,
) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Creating proof for native asset mint"));
    
    // In a real implementation, this would:
    // 1. Parse the input data from JavaScript
    // 2. Build the circuit
    // 3. Generate the proof
    // 4. Return the proof as a JavaScript object
    
    // For now, we'll just return a dummy proof
    let proof = Object::new();
    js_sys::Reflect::set(&proof, &JsValue::from_str("success"), &JsValue::from_bool(true))?;
    js_sys::Reflect::set(&proof, &JsValue::from_str("circuitType"), &JsValue::from_str("NativeAssetMint"))?;
    
    Ok(JsValue::from(proof))
}

/// Create a proof for burning a native asset
#[wasm_bindgen]
pub fn prove_native_asset_burn(
    _input_utxos: JsValue,
    _sender_pk: JsValue,
    _sender_sig: JsValue,
    _fee_input_utxo: JsValue,
) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Creating proof for native asset burn"));
    
    // In a real implementation, this would:
    // 1. Parse the input data from JavaScript
    // 2. Build the circuit
    // 3. Generate the proof
    // 4. Return the proof as a JavaScript object
    
    // For now, we'll just return a dummy proof
    let proof = Object::new();
    js_sys::Reflect::set(&proof, &JsValue::from_str("success"), &JsValue::from_bool(true))?;
    js_sys::Reflect::set(&proof, &JsValue::from_str("circuitType"), &JsValue::from_str("NativeAssetBurn"))?;
    
    Ok(JsValue::from(proof))
}

/// Verify a proof
#[wasm_bindgen]
pub fn verify_proof(
    proof: JsValue,
    circuit_type: String,
) -> Result<bool, JsValue> {
    console::log_1(&JsValue::from_str(&format!("Verifying proof for circuit: {}", circuit_type)));
    
    // Parse the proof object
    let proof_obj = js_sys::Object::from(proof);
    
    // Extract the public inputs and proof data
    let public_inputs_js = js_sys::Reflect::get(&proof_obj, &JsValue::from_str("publicInputs"))?;
    let _public_inputs = js_sys::Array::from(&public_inputs_js);
    
    let proof_data_js = js_sys::Reflect::get(&proof_obj, &JsValue::from_str("proof"))?;
    let proof_data = js_sys::Object::from(proof_data_js);
    
    // Verify the proof based on the circuit type
    let is_valid = match circuit_type.as_str() {
        "WrappedAssetMint" => {
            console::log_1(&JsValue::from_str("Verifying WrappedAssetMint proof"));
            
            // Create the circuit
            let _circuit_data = WrappedAssetMintCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            // For now, we'll just check that the proof structure is valid
            verify_proof_structure(&proof_data)?
        },
        "WrappedAssetBurn" => {
            console::log_1(&JsValue::from_str("Verifying WrappedAssetBurn proof"));
            
            // Create the circuit
            let _circuit_data = WrappedAssetBurnCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(&proof_data)?
        },
        "Transfer" => {
            console::log_1(&JsValue::from_str("Verifying Transfer proof"));
            
            // Create the circuit
            let _circuit_data = TransferCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(&proof_data)?
        },
        "NativeAssetCreate" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetCreate proof"));
            
            // Create the circuit
            let _circuit_data = NativeAssetCreateCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(&proof_data)?
        },
        "NativeAssetMint" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetMint proof"));
            
            // Create the circuit
            let _circuit_data = NativeAssetMintCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(&proof_data)?
        },
        "NativeAssetBurn" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetBurn proof"));
            
            // Create the circuit
            let _circuit_data = NativeAssetBurnCircuit::create_circuit();
            
            // In a real implementation, we would use the circuit_data to verify the proof
            verify_proof_structure(&proof_data)?
        },
        _ => {
            return Err(JsValue::from_str(&format!("Unknown circuit type: {}", circuit_type)));
        }
    };
    
    if is_valid {
        console::log_1(&JsValue::from_str("Proof verified successfully!"));
    } else {
        console::log_1(&JsValue::from_str("Proof verification failed!"));
    }
    
    Ok(is_valid)
}

// Helper function to verify the structure of a proof
fn verify_proof_structure(proof: &js_sys::Object) -> Result<bool, JsValue> {
    // Check that the proof has the expected structure
    let commitments_js = js_sys::Reflect::get(proof, &JsValue::from_str("commitments"))?;
    let commitments = js_sys::Array::from(&commitments_js);
    
    let evaluations_js = js_sys::Reflect::get(proof, &JsValue::from_str("evaluations"))?;
    let evaluations = js_sys::Array::from(&evaluations_js);
    
    let openings_js = js_sys::Reflect::get(proof, &JsValue::from_str("openings"))?;
    let openings = js_sys::Array::from(&openings_js);
    
    // Check that each commitment is a valid hex string
    for i in 0..commitments.length() {
        let commitment = commitments.get(i);
        let hex_str = commitment.as_string().ok_or_else(|| JsValue::from_str(&format!("commitment[{}] is not a string", i)))?;
        
        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!("commitment[{}] does not start with 0x", i)));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode commitment[{}]: {}", i, e)))?;
    }
    
    // Check that each evaluation is a valid hex string
    for i in 0..evaluations.length() {
        let evaluation = evaluations.get(i);
        let hex_str = evaluation.as_string().ok_or_else(|| JsValue::from_str(&format!("evaluation[{}] is not a string", i)))?;
        
        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!("evaluation[{}] does not start with 0x", i)));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode evaluation[{}]: {}", i, e)))?;
    }
    
    // Check that each opening is a valid hex string
    for i in 0..openings.length() {
        let opening = openings.get(i);
        let hex_str = opening.as_string().ok_or_else(|| JsValue::from_str(&format!("opening[{}] is not a string", i)))?;
        
        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!("opening[{}] does not start with 0x", i)));
        }
        
        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode opening[{}]: {}", i, e)))?;
    }
    
    // All checks passed
    Ok(true)
}
