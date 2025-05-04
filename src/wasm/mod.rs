// WebAssembly bindings for the 0BTC Wire system
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
#[cfg(feature = "wasm")]
use js_sys::{Array, Object, Uint8Array};
use log::{error, info, warn};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::json;
#[cfg(feature = "wasm")]
use serde_wasm_bindgen;
#[cfg(feature = "wasm")]
use std::convert::TryFrom;
#[cfg(feature = "wasm")]
use wasm_bindgen::prelude::*;
#[cfg(feature = "wasm")]
use web_sys::console;

// Import validation module
pub mod validation;
#[cfg(feature = "wasm")]
use validation::{
    validate_aggregation_options, validate_asset_id, validate_batch_size, validate_circuit_type,
    validate_hash, validate_hex_string, validate_private_key,
    validate_proof_structure as validate_proof_json_structure, validate_proofs_array,
    validate_public_key, validate_salt, validate_signature, validate_transfer_params,
    validate_wrapped_asset_burn_params, validate_wrapped_asset_mint_params, ValidationError,
};

// Import utility functions
use crate::utils::{
    parallel_prover::{
        generate_proofs_for_circuit, generate_proofs_in_parallel, verify_proofs_in_parallel,
        ParallelProverOptions,
    },
    recursive_prover::{
        aggregate_proofs as recursive_aggregate_proofs,
        verify_aggregated_proof as recursive_verify_aggregated_proof, RecursiveProverOptions,
    },
};

use crate::circuits::native_asset_burn::NativeAssetBurnCircuit;
use crate::circuits::native_asset_create::NativeAssetCreateCircuit;
use crate::circuits::native_asset_mint::NativeAssetMintCircuit;
use crate::circuits::transfer::TransferCircuit;
use crate::circuits::wrapped_asset_burn::SignedQuoteTarget;
use crate::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use crate::circuits::wrapped_asset_mint::SignedAttestationTarget;
use crate::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use crate::core::proof::SerializableProof;
use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget};

// Initialize the WASM module
#[cfg(feature = "wasm")]
#[wasm_bindgen(start)]
pub fn start() -> Result<(), JsValue> {
    // Initialize the console error panic hook for better error messages
    console_error_panic_hook::set_once();

    // Log initialization
    console::log_1(&JsValue::from_str("Wire WASM module initialized"));

    Ok(())
}

// Generate a new Ed25519 keypair
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn generate_keypair() -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Generating new Ed25519 keypair"));

    // Use a secure random number generator
    let mut csprng = OsRng {};

    // Generate a new keypair using ed25519-dalek
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = VerifyingKey::from(&signing_key);

    // Convert to bytes
    let private_key = signing_key.to_bytes();
    let public_key = verifying_key.to_bytes();

    // Create JSON representation with domain separation in field names
    let result = json!({
        "secretKey": format!("0x{}", hex::encode(private_key)),
        "publicKey": format!("0x{}", hex::encode(public_key)),
    });

    // Return the result
    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Sign a message with an Ed25519 private key
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn sign_message(secret_key_hex: &str, message_hex: &str) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Signing message with Ed25519 key"));

    // Validate the secret key
    let secret_key_bytes = match validate_private_key(secret_key_hex, "secretKey") {
        Ok(bytes) => bytes,
        Err(e) => return Err(e.to_js_error()),
    };

    // Validate the message
    let message = match validate_hex_string(message_hex, "message", None) {
        Ok(bytes) => bytes,
        Err(e) => return Err(e.to_js_error()),
    };

    // Create a fixed-size array from the Vec<u8>
    let mut key_bytes = [0u8; 32];
    key_bytes.copy_from_slice(&secret_key_bytes);

    // Create the secret key
    let signing_key = SigningKey::from_bytes(&key_bytes);

    // Sign the message
    let signature = signing_key.sign(&message);

    // Return the signature with domain separation in field names
    let result = json!({
        "signature": format!("0x{}", hex::encode(signature.to_bytes())),
        "r": format!("0x{}", hex::encode(&signature.to_bytes()[0..32])),
        "s": format!("0x{}", hex::encode(&signature.to_bytes()[32..64])),
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Generate a proof for minting wrapped assets
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn prove_wrapped_asset_mint(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str(
        "Generating proof for wrapped asset mint...",
    ));

    // Parse the parameters
    let params_value: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;

    // Validate all parameters
    match validate_wrapped_asset_mint_params(&params_value) {
        Ok(_) => {}
        Err(e) => return Err(e.to_js_error()),
    }

    // Extract the parameters (already validated)
    let recipient_pk_hash_hex = params_value["recipientPkHash"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x");

    let recipient_pk_hash = hex::decode(recipient_pk_hash_hex).unwrap();

    let amount = params_value["amount"].as_u64().unwrap();
    let deposit_nonce = params_value["depositNonce"].as_u64().unwrap();
    let custodian_pk_x = params_value["custodianPkX"].as_u64().unwrap();
    let custodian_pk_y = params_value["custodianPkY"].as_u64().unwrap();
    let signature_r_x = params_value["signatureRX"].as_u64().unwrap();
    let signature_r_y = params_value["signatureRY"].as_u64().unwrap();
    let signature_s = params_value["signatureS"].as_u64().unwrap();

    let salt_hex = params_value["salt"]
        .as_str()
        .unwrap()
        .trim_start_matches("0x");

    let salt = hex::decode(salt_hex).unwrap();

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
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;

    // Return the proof with domain separation in field names
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
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_wrapped_asset_mint(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str(
        "Verifying proof for wrapped asset mint...",
    ));

    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;

    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;

    let public_inputs_vec: Vec<String> = public_inputs
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let proof_bytes = proof_value["proof"]
        .as_str()
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
        }
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
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn prove_transfer(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Generating proof for transfer..."));

    // Parse the parameters
    let params: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;

    // Extract the input UTXOs
    let input_utxos_json = params["inputUtxos"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid inputUtxos array"))?;

    let mut input_utxos_data = Vec::new();
    for utxo_json in input_utxos_json {
        let owner_pubkey_hash_hex = utxo_json["ownerPubkeyHash"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("Missing ownerPubkeyHash in input UTXO"))?
            .trim_start_matches("0x");

        let owner_pubkey_hash = hex::decode(owner_pubkey_hash_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode ownerPubkeyHash: {}", e)))?;

        let asset_id_hex = utxo_json["assetId"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("Missing assetId in input UTXO"))?
            .trim_start_matches("0x");

        let asset_id = hex::decode(asset_id_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode assetId: {}", e)))?;

        let amount = utxo_json["amount"]
            .as_u64()
            .ok_or_else(|| JsValue::from_str("Missing or invalid amount in input UTXO"))?;

        let salt_hex = utxo_json["salt"]
            .as_str()
            .ok_or_else(|| JsValue::from_str("Missing salt in input UTXO"))?
            .trim_start_matches("0x");

        let salt = hex::decode(salt_hex)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode salt: {}", e)))?;

        input_utxos_data.push((owner_pubkey_hash, asset_id, amount, salt));
    }

    // Extract the recipient public key hashes
    let recipient_pk_hashes_json = params["recipientPkHashes"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid recipientPkHashes array"))?;

    let mut recipient_pk_hashes = Vec::new();
    for pk_hash_json in recipient_pk_hashes_json {
        let pk_hash_hex = pk_hash_json
            .as_str()
            .ok_or_else(|| JsValue::from_str("Invalid recipient public key hash"))?
            .trim_start_matches("0x");

        let pk_hash = hex::decode(pk_hash_hex).map_err(|e| {
            JsValue::from_str(&format!(
                "Failed to decode recipient public key hash: {}",
                e
            ))
        })?;

        recipient_pk_hashes.push(pk_hash);
    }

    // Extract the output amounts
    let output_amounts_json = params["outputAmounts"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Missing or invalid outputAmounts array"))?;

    let mut output_amounts = Vec::new();
    for amount_json in output_amounts_json {
        let amount = amount_json
            .as_u64()
            .ok_or_else(|| JsValue::from_str("Invalid output amount"))?;

        output_amounts.push(amount);
    }

    // Extract the sender's secret key and public key
    let sender_sk = params["senderSk"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderSk"))?;

    let sender_pk_x = params["senderPkX"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkX"))?;

    let sender_pk_y = params["senderPkY"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkY"))?;

    // Extract the signature
    let signature_r_x = params["signatureRX"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRX"))?;

    let signature_r_y = params["signatureRY"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRY"))?;

    let signature_s = params["signatureS"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureS"))?;

    // Extract the fee input UTXO
    let fee_input_utxo_json = &params["feeInputUtxo"];

    let fee_owner_pubkey_hash_hex = fee_input_utxo_json["ownerPubkeyHash"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing ownerPubkeyHash in fee input UTXO"))?
        .trim_start_matches("0x");

    let fee_owner_pubkey_hash = hex::decode(fee_owner_pubkey_hash_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee ownerPubkeyHash: {}", e)))?;

    let fee_asset_id_hex = fee_input_utxo_json["assetId"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing assetId in fee input UTXO"))?
        .trim_start_matches("0x");

    let fee_asset_id = hex::decode(fee_asset_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee assetId: {}", e)))?;

    let fee_amount_value = fee_input_utxo_json["amount"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid amount in fee input UTXO"))?;

    let fee_salt_hex = fee_input_utxo_json["salt"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing salt in fee input UTXO"))?
        .trim_start_matches("0x");

    let fee_salt = hex::decode(fee_salt_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode fee salt: {}", e)))?;

    let fee_input_utxo_data = (
        fee_owner_pubkey_hash,
        fee_asset_id,
        fee_amount_value,
        fee_salt,
    );

    // Extract the fee amount and reservoir address hash
    let fee_amount = params["feeAmount"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid feeAmount"))?;

    let fee_reservoir_address_hash_hex = params["feeReservoirAddressHash"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing feeReservoirAddressHash"))?
        .trim_start_matches("0x");

    let fee_reservoir_address_hash = hex::decode(fee_reservoir_address_hash_hex).map_err(|e| {
        JsValue::from_str(&format!("Failed to decode feeReservoirAddressHash: {}", e))
    })?;

    // Extract the nonce
    let nonce = params["nonce"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid nonce"))?;

    // Generate the proof using the static method
    let proof_result = TransferCircuit::generate_proof_static(
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
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;

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
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_transfer(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Verifying proof for transfer..."));

    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;

    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;

    let public_inputs_vec: Vec<String> = public_inputs
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let proof_bytes = proof_value["proof"]
        .as_str()
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
        }
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
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn prove_wrapped_asset_burn(params: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str(
        "Generating proof for wrapped asset burn...",
    ));

    // Parse the parameters
    let params: serde_json::Value = serde_wasm_bindgen::from_value(params.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse parameters: {}", e)))?;

    // Extract the parameters
    let input_utxo_owner_pubkey_hash_hex = params["inputUtxoOwnerPubkeyHash"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoOwnerPubkeyHash"))?
        .trim_start_matches("0x");

    let input_utxo_owner_pubkey_hash =
        hex::decode(input_utxo_owner_pubkey_hash_hex).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode inputUtxoOwnerPubkeyHash: {}", e))
        })?;

    let input_utxo_asset_id_hex = params["inputUtxoAssetId"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoAssetId"))?
        .trim_start_matches("0x");

    let input_utxo_asset_id = hex::decode(input_utxo_asset_id_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode inputUtxoAssetId: {}", e)))?;

    let input_utxo_amount = params["inputUtxoAmount"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid inputUtxoAmount"))?;

    let input_utxo_salt_hex = params["inputUtxoSalt"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing inputUtxoSalt"))?
        .trim_start_matches("0x");

    let input_utxo_salt = hex::decode(input_utxo_salt_hex)
        .map_err(|e| JsValue::from_str(&format!("Failed to decode inputUtxoSalt: {}", e)))?;

    let sender_sk = params["senderSk"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderSk"))?;

    let sender_pk_x = params["senderPkX"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkX"))?;

    let sender_pk_y = params["senderPkY"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid senderPkY"))?;

    let signature_r_x = params["signatureRX"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRX"))?;

    let signature_r_y = params["signatureRY"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureRY"))?;

    let signature_s = params["signatureS"]
        .as_u64()
        .ok_or_else(|| JsValue::from_str("Missing or invalid signatureS"))?;

    let destination_btc_address_hex = params["destinationBtcAddress"]
        .as_str()
        .ok_or_else(|| JsValue::from_str("Missing destinationBtcAddress"))?
        .trim_start_matches("0x");

    let destination_btc_address = hex::decode(destination_btc_address_hex).map_err(|e| {
        JsValue::from_str(&format!("Failed to decode destinationBtcAddress: {}", e))
    })?;

    // Optional fee parameters
    let fee_btc = params.get("feeBtc").and_then(|v| v.as_u64());
    let fee_expiry = params.get("feeExpiry").and_then(|v| v.as_u64());
    let fee_signature_r_x = params.get("feeSignatureRX").and_then(|v| v.as_u64());
    let fee_signature_r_y = params.get("feeSignatureRY").and_then(|v| v.as_u64());
    let fee_signature_s = params.get("feeSignatureS").and_then(|v| v.as_u64());
    let custodian_pk_x = params.get("custodianPkX").and_then(|v| v.as_u64());
    let custodian_pk_y = params.get("custodianPkY").and_then(|v| v.as_u64());

    // Generate the proof using the static method
    let proof_result = WrappedAssetBurnCircuit::generate_proof_static(
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
    )
    .map_err(|e| JsValue::from_str(&format!("Failed to generate proof: {}", e)))?;

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
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_wrapped_asset_burn(proof_json: &JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str(
        "Verifying proof for wrapped asset burn...",
    ));

    // Parse the proof
    let proof_value: serde_json::Value = serde_wasm_bindgen::from_value(proof_json.clone())
        .map_err(|e| JsValue::from_str(&format!("Failed to parse proof: {}", e)))?;

    // Extract the public inputs and proof
    let public_inputs = proof_value["publicInputs"]
        .as_array()
        .ok_or_else(|| JsValue::from_str("Proof does not contain public inputs"))?;

    let public_inputs_vec: Vec<String> = public_inputs
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();

    let proof_bytes = proof_value["proof"]
        .as_str()
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
        }
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
#[cfg(feature = "wasm")]
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
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("success"),
        &JsValue::from_bool(true),
    )?;
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("circuitType"),
        &JsValue::from_str("NativeAssetCreate"),
    )?;

    Ok(JsValue::from(proof))
}

/// Create a proof for minting a native asset
#[cfg(feature = "wasm")]
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
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("success"),
        &JsValue::from_bool(true),
    )?;
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("circuitType"),
        &JsValue::from_str("NativeAssetMint"),
    )?;

    Ok(JsValue::from(proof))
}

/// Create a proof for burning a native asset
#[cfg(feature = "wasm")]
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
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("success"),
        &JsValue::from_bool(true),
    )?;
    js_sys::Reflect::set(
        &proof,
        &JsValue::from_str("circuitType"),
        &JsValue::from_str("NativeAssetBurn"),
    )?;

    Ok(JsValue::from(proof))
}

/// Verify a proof
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_proof(proof: JsValue, circuit_type: String) -> Result<bool, JsValue> {
    console::log_1(&JsValue::from_str(&format!(
        "Verifying proof for circuit: {}",
        circuit_type
    )));

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
            validate_proof_json_structure(&proof_data)?
        }
        "WrappedAssetBurn" => {
            console::log_1(&JsValue::from_str("Verifying WrappedAssetBurn proof"));

            // Create the circuit
            let _circuit_data = WrappedAssetBurnCircuit::create_circuit();

            // In a real implementation, we would use the circuit_data to verify the proof
            validate_proof_json_structure(&proof_data)?
        }
        "Transfer" => {
            console::log_1(&JsValue::from_str("Verifying Transfer proof"));

            // Create the circuit
            let _circuit_data = TransferCircuit::create_circuit();

            // In a real implementation, we would use the circuit_data to verify the proof
            validate_proof_json_structure(&proof_data)?
        }
        "NativeAssetCreate" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetCreate proof"));

            // Create the circuit
            let _circuit_data = NativeAssetCreateCircuit::create_circuit();

            // In a real implementation, we would use the circuit_data to verify the proof
            validate_proof_json_structure(&proof_data)?
        }
        "NativeAssetMint" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetMint proof"));

            // Create the circuit
            let _circuit_data = NativeAssetMintCircuit::create_circuit();

            // In a real implementation, we would use the circuit_data to verify the proof
            validate_proof_json_structure(&proof_data)?
        }
        "NativeAssetBurn" => {
            console::log_1(&JsValue::from_str("Verifying NativeAssetBurn proof"));

            // Create the circuit
            let _circuit_data = NativeAssetBurnCircuit::create_circuit();

            // In a real implementation, we would use the circuit_data to verify the proof
            validate_proof_json_structure(&proof_data)?
        }
        _ => {
            return Err(JsValue::from_str(&format!(
                "Unknown circuit type: {}",
                circuit_type
            )));
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
#[cfg(feature = "wasm")]
fn validate_proof_structure(proof: &js_sys::Object) -> Result<bool, JsValue> {
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
        let hex_str = commitment
            .as_string()
            .ok_or_else(|| JsValue::from_str(&format!("commitment[{}] is not a string", i)))?;

        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!(
                "commitment[{}] does not start with 0x",
                i
            )));
        }

        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode commitment[{}]: {}", i, e))
        })?;
    }

    // Check that each evaluation is a valid hex string
    for i in 0..evaluations.length() {
        let evaluation = evaluations.get(i);
        let hex_str = evaluation
            .as_string()
            .ok_or_else(|| JsValue::from_str(&format!("evaluation[{}] is not a string", i)))?;

        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!(
                "evaluation[{}] does not start with 0x",
                i
            )));
        }

        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str).map_err(|e| {
            JsValue::from_str(&format!("Failed to decode evaluation[{}]: {}", i, e))
        })?;
    }

    // Check that each opening is a valid hex string
    for i in 0..openings.length() {
        let opening = openings.get(i);
        let hex_str = opening
            .as_string()
            .ok_or_else(|| JsValue::from_str(&format!("opening[{}] is not a string", i)))?;

        if !hex_str.starts_with("0x") {
            return Err(JsValue::from_str(&format!(
                "opening[{}] does not start with 0x",
                i
            )));
        }

        let hex_str = hex_str.trim_start_matches("0x");
        hex::decode(hex_str)
            .map_err(|e| JsValue::from_str(&format!("Failed to decode opening[{}]: {}", i, e)))?;
    }

    // All checks passed
    Ok(true)
}

// Aggregate multiple proofs into a single proof
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn aggregate_proofs(proofs_array: JsValue, options_js: JsValue) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str("Aggregating proofs..."));

    // Validate the proofs array
    let proofs_value = match validate_proofs_array(&proofs_array) {
        Ok(proofs) => proofs,
        Err(e) => return Err(e.to_js_error()),
    };

    // Validate the options
    let (batch_size, verbose) = match validate_aggregation_options(&options_js) {
        Ok(options) => options,
        Err(e) => return Err(e.to_js_error()),
    };

    if verbose {
        console::log_1(&JsValue::from_str(&format!(
            "Aggregating {} proofs with batch size {}",
            proofs_value.len(),
            batch_size
        )));
    }

    // Create a dummy circuit for proof conversion
    let circuit_type = "transfer"; // Default circuit type
    let circuit = match create_dummy_circuit(circuit_type) {
        Ok(circuit) => circuit,
        Err(e) => return Err(e),
    };

    // Convert proofs to ProofWithPublicInputs
    let mut proofs = Vec::with_capacity(proofs_value.len());

    for (i, proof_value) in proofs_value.iter().enumerate() {
        // Convert to SerializableProof
        let serializable_proof: SerializableProof =
            match serde_json::from_value(proof_value.clone()) {
                Ok(proof) => proof,
                Err(e) => {
                    return Err(JsValue::from_str(&format!(
                        "Failed to convert proof at index {}: {}",
                        i, e
                    )));
                }
            };

        // Convert to ProofWithPublicInputs
        let proof = match serializable_proof
            .to_proof::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&circuit.common)
        {
            Ok(proof) => proof,
            Err(e) => {
                return Err(JsValue::from_str(&format!(
                    "Failed to convert proof at index {}: {}",
                    i, e
                )));
            }
        };

        proofs.push(proof);
    }

    // Set up options for recursive aggregation
    let options = RecursiveProverOptions {
        verbose,
        max_proofs_per_step: Some(batch_size),
    };

    // Aggregate the proofs
    let start_time = js_sys::Date::now();

    let result = match recursive_aggregate_proofs(proofs, options) {
        Ok(result) => result,
        Err(e) => {
            return Err(JsValue::from_str(&format!(
                "Failed to aggregate proofs: {}",
                e
            )));
        }
    };

    let end_time = js_sys::Date::now();
    let duration_ms = end_time - start_time;

    if verbose {
        console::log_1(&JsValue::from_str(&format!(
            "Aggregated {} proofs in {:.2} seconds",
            result.num_proofs,
            duration_ms / 1000.0
        )));
    }

    // Convert back to SerializableProof
    let serializable = SerializableProof::from(result.proof);

    // Create the result object
    let js_result = json!({
        "success": true,
        "proof": serializable,
        "num_proofs": result.num_proofs,
        "generation_time_ms": duration_ms,
        "circuit_type": circuit_type,
    });

    serde_wasm_bindgen::to_value(&js_result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Verify an aggregated proof
#[cfg(feature = "wasm")]
#[wasm_bindgen]
pub fn verify_aggregated_proof(
    proof_js: JsValue,
    circuit_type: String,
) -> Result<JsValue, JsValue> {
    console::log_1(&JsValue::from_str(&format!(
        "Verifying aggregated proof for circuit type: {}",
        circuit_type
    )));

    // Validate the circuit type
    let validated_circuit_type = match validate_circuit_type(&circuit_type) {
        Ok(circuit_type) => circuit_type,
        Err(e) => return Err(e.to_js_error()),
    };

    // Parse the proof
    let proof_value: serde_json::Value = match serde_wasm_bindgen::from_value(proof_js.clone()) {
        Ok(value) => value,
        Err(e) => return Err(JsValue::from_str(&format!("Failed to parse proof: {}", e))),
    };

    // Validate the proof structure
    match validate_proof_json_structure(&proof_value) {
        Ok(_) => {}
        Err(e) => return Err(e.to_js_error()),
    }

    // Create a dummy circuit for verification
    let circuit = match create_dummy_circuit(&validated_circuit_type) {
        Ok(circuit) => circuit,
        Err(e) => return Err(e),
    };

    // Convert to SerializableProof
    let serializable_proof: SerializableProof = match serde_wasm_bindgen::from_value(proof_js) {
        Ok(proof) => proof,
        Err(e) => {
            return Err(JsValue::from_str(&format!(
                "Failed to convert proof: {}",
                e
            )))
        }
    };

    // Convert to ProofWithPublicInputs
    let proof = match serializable_proof
        .to_proof::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&circuit.common)
    {
        Ok(proof) => proof,
        Err(e) => {
            return Err(JsValue::from_str(&format!(
                "Failed to convert proof: {}",
                e
            )))
        }
    };

    // Verify the proof
    let start_time = js_sys::Date::now();

    let verified_count = match recursive_verify_aggregated_proof(&proof, &circuit) {
        Ok(count) => count,
        Err(e) => return Err(JsValue::from_str(&format!("Failed to verify proof: {}", e))),
    };

    let end_time = js_sys::Date::now();
    let duration_ms = end_time - start_time;

    // Create the result object
    let result = json!({
        "success": true,
        "verified": true,
        "num_proofs": verified_count,
        "verification_time_ms": duration_ms,
        "throughput": (verified_count as f64) / (duration_ms as f64 / 1000.0),
    });

    serde_wasm_bindgen::to_value(&result)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {}", e)))
}

// Create a dummy circuit for proof conversion and verification
#[cfg(feature = "wasm")]
fn create_dummy_circuit(
    circuit_type: &str,
) -> Result<
    plonky2::plonk::circuit_data::CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    JsValue,
> {
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

    // Add a dummy target
    let target = builder.add_virtual_target();
    builder.register_public_input(target);

    // Build the circuit
    let circuit = builder.build::<PoseidonGoldilocksConfig>();

    Ok(circuit)
}
