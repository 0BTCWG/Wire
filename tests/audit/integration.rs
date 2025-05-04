//! Integration tests for the 0BTC Wire system
//!
//! These tests verify the integration of components, including CLI, WASM, and recursive proof aggregation.

use crate::audit::utils;
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::core::proof::SerializableProof;
use wire_lib::utils::recursive_prover::{aggregate_proofs, verify_aggregated_proof};

/// Test CLI wrapped mint integration
#[test]
fn test_integration_cli_wrapped_mint() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let input_path = temp_dir.path().join("mint_input.json");
    let output_path = temp_dir.path().join("mint_proof.json");

    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, signature) = utils::generate_test_attestation();
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = signature;

    // Create input JSON
    let input_json = format!(
        r#"{{
            "recipient_pk_hash": {:?},
            "amount": {},
            "deposit_nonce": {},
            "custodian_pk_x": {},
            "custodian_pk_y": {},
            "signature_r_x": {},
            "signature_r_y": {},
            "signature_s": {}
        }}"#,
        recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s
    );

    // Write input JSON to file
    let mut file = File::create(&input_path).expect("Failed to create input file");
    file.write_all(input_json.as_bytes())
        .expect("Failed to write input file");

    // Run the CLI command
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "wire_cli",
            "--",
            "generate-proof",
            "--circuit-type",
            "wrapped-mint",
            "--input-file",
            input_path.to_str().unwrap(),
            "--output-file",
            output_path.to_str().unwrap(),
        ])
        .status();

    // Check if the command succeeded
    match status {
        Ok(exit_status) => {
            assert!(
                exit_status.success(),
                "CLI command failed with status: {}",
                exit_status
            );

            // Check if the output file exists
            assert!(output_path.exists(), "Output file does not exist");

            // Read the output file
            let proof_json = fs::read_to_string(&output_path).expect("Failed to read output file");

            // Parse the proof
            let proof: SerializableProof =
                serde_json::from_str(&proof_json).expect("Failed to parse proof");

            // Verify the proof
            let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof: {:?}",
                verification_result.err()
            );
        }
        Err(err) => {
            // If the command fails, it might be because the CLI is not available
            // In that case, skip the test
            println!("Skipping CLI test: {}", err);
        }
    }
}

/// Test CLI wrapped burn integration
#[test]
fn test_integration_cli_wrapped_burn() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let input_path = temp_dir.path().join("burn_input.json");
    let output_path = temp_dir.path().join("burn_proof.json");

    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Create input JSON
    let input_json = format!(
        r#"{{
            "owner_pubkey_hash": {:?},
            "asset_id": {:?},
            "amount": {},
            "salt": {:?},
            "sender_sk": {},
            "sender_pk_x": {},
            "sender_pk_y": {},
            "signature_r_x": {},
            "signature_r_y": {},
            "signature_s": {},
            "destination_btc_address": {:?}
        }}"#,
        owner_pubkey_hash,
        asset_id,
        amount,
        salt,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        destination_btc_address
    );

    // Write input JSON to file
    let mut file = File::create(&input_path).expect("Failed to create input file");
    file.write_all(input_json.as_bytes())
        .expect("Failed to write input file");

    // Run the CLI command
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "wire_cli",
            "--",
            "generate-proof",
            "--circuit-type",
            "wrapped-burn",
            "--input-file",
            input_path.to_str().unwrap(),
            "--output-file",
            output_path.to_str().unwrap(),
        ])
        .status();

    // Check if the command succeeded
    match status {
        Ok(exit_status) => {
            assert!(
                exit_status.success(),
                "CLI command failed with status: {}",
                exit_status
            );

            // Check if the output file exists
            assert!(output_path.exists(), "Output file does not exist");

            // Read the output file
            let proof_json = fs::read_to_string(&output_path).expect("Failed to read output file");

            // Parse the proof
            let proof: SerializableProof =
                serde_json::from_str(&proof_json).expect("Failed to parse proof");

            // Verify the proof
            let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof: {:?}",
                verification_result.err()
            );
        }
        Err(err) => {
            // If the command fails, it might be because the CLI is not available
            // In that case, skip the test
            println!("Skipping CLI test: {}", err);
        }
    }
}

/// Test CLI transfer integration
#[test]
fn test_integration_cli_transfer() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let input_path = temp_dir.path().join("transfer_input.json");
    let output_path = temp_dir.path().join("transfer_proof.json");

    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create input JSON
    let input_json = format!(
        r#"{{
            "input_utxos": [
                {{
                    "owner_pubkey_hash": {:?},
                    "asset_id": {:?},
                    "amount": {},
                    "salt": {:?}
                }}
            ],
            "recipient_pk_hashes": [
                {:?}
            ],
            "output_amounts": [
                {}
            ],
            "sender_sk": {},
            "sender_pk_x": {},
            "sender_pk_y": {},
            "signature_r_x": {},
            "signature_r_y": {},
            "signature_s": {},
            "fee_input_utxo": {{
                "owner_pubkey_hash": {:?},
                "asset_id": {:?},
                "amount": {},
                "salt": {:?}
            }},
            "fee_amount": {},
            "fee_reservoir_address_hash": {:?},
            "nonce": {}
        }}"#,
        owner_pubkey_hash,
        asset_id,
        amount,
        salt,
        recipient_pk_hash,
        output_amount,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        owner_pubkey_hash,
        asset_id,
        amount,
        salt,
        fee_amount,
        fee_reservoir_address_hash,
        nonce
    );

    // Write input JSON to file
    let mut file = File::create(&input_path).expect("Failed to create input file");
    file.write_all(input_json.as_bytes())
        .expect("Failed to write input file");

    // Run the CLI command
    let status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "wire_cli",
            "--",
            "generate-proof",
            "--circuit-type",
            "transfer",
            "--input-file",
            input_path.to_str().unwrap(),
            "--output-file",
            output_path.to_str().unwrap(),
        ])
        .status();

    // Check if the command succeeded
    match status {
        Ok(exit_status) => {
            assert!(
                exit_status.success(),
                "CLI command failed with status: {}",
                exit_status
            );

            // Check if the output file exists
            assert!(output_path.exists(), "Output file does not exist");

            // Read the output file
            let proof_json = fs::read_to_string(&output_path).expect("Failed to read output file");

            // Parse the proof
            let proof: SerializableProof =
                serde_json::from_str(&proof_json).expect("Failed to parse proof");

            // Verify the proof
            let verification_result = TransferCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof: {:?}",
                verification_result.err()
            );
        }
        Err(err) => {
            // If the command fails, it might be because the CLI is not available
            // In that case, skip the test
            println!("Skipping CLI test: {}", err);
        }
    }
}

/// Test WASM wrapped mint integration
#[test]
#[cfg(feature = "wasm")]
fn test_integration_wasm_wrapped_mint() {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;
    use wire_lib::wasm::{generate_wrapped_mint_proof, verify_wrapped_mint_proof};

    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, signature) = utils::generate_test_attestation();
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = signature;

    // Create input object
    let input = serde_json::json!({
        "recipient_pk_hash": recipient_pk_hash,
        "amount": amount,
        "deposit_nonce": deposit_nonce,
        "custodian_pk_x": custodian_pk_x,
        "custodian_pk_y": custodian_pk_y,
        "signature_r_x": signature_r_x,
        "signature_r_y": signature_r_y,
        "signature_s": signature_s
    });

    // Convert to JsValue
    let input_js = JsValue::from_serde(&input).expect("Failed to convert input to JsValue");

    // Generate proof
    let proof_js = generate_wrapped_mint_proof(input_js).expect("Failed to generate proof");

    // Verify proof
    let result_js = verify_wrapped_mint_proof(proof_js).expect("Failed to verify proof");

    // Convert result to Rust object
    let result: serde_json::Value = result_js
        .into_serde()
        .expect("Failed to convert result to Rust object");

    // Check if verification succeeded
    assert_eq!(result["success"], true, "Proof verification failed");
}

/// Test WASM wrapped burn integration
#[test]
#[cfg(feature = "wasm")]
fn test_integration_wasm_wrapped_burn() {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;
    use wire_lib::wasm::{generate_wrapped_burn_proof, verify_wrapped_burn_proof};

    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Create input object
    let input = serde_json::json!({
        "owner_pubkey_hash": owner_pubkey_hash,
        "asset_id": asset_id,
        "amount": amount,
        "salt": salt,
        "sender_sk": sender_sk,
        "sender_pk_x": sender_pk_x,
        "sender_pk_y": sender_pk_y,
        "signature_r_x": signature_r_x,
        "signature_r_y": signature_r_y,
        "signature_s": signature_s,
        "destination_btc_address": destination_btc_address
    });

    // Convert to JsValue
    let input_js = JsValue::from_serde(&input).expect("Failed to convert input to JsValue");

    // Generate proof
    let proof_js = generate_wrapped_burn_proof(input_js).expect("Failed to generate proof");

    // Verify proof
    let result_js = verify_wrapped_burn_proof(proof_js).expect("Failed to verify proof");

    // Convert result to Rust object
    let result: serde_json::Value = result_js
        .into_serde()
        .expect("Failed to convert result to Rust object");

    // Check if verification succeeded
    assert_eq!(result["success"], true, "Proof verification failed");
}

/// Test WASM transfer integration
#[test]
#[cfg(feature = "wasm")]
fn test_integration_wasm_transfer() {
    use wasm_bindgen::JsValue;
    use wasm_bindgen_test::*;
    use wire_lib::wasm::{generate_transfer_proof, verify_transfer_proof};

    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create input object
    let input = serde_json::json!({
        "input_utxos": [
            {
                "owner_pubkey_hash": owner_pubkey_hash,
                "asset_id": asset_id,
                "amount": amount,
                "salt": salt
            }
        ],
        "recipient_pk_hashes": [
            recipient_pk_hash
        ],
        "output_amounts": [
            output_amount
        ],
        "sender_sk": sender_sk,
        "sender_pk_x": sender_pk_x,
        "sender_pk_y": sender_pk_y,
        "signature_r_x": signature_r_x,
        "signature_r_y": signature_r_y,
        "signature_s": signature_s,
        "fee_input_utxo": {
            "owner_pubkey_hash": owner_pubkey_hash,
            "asset_id": asset_id,
            "amount": amount,
            "salt": salt
        },
        "fee_amount": fee_amount,
        "fee_reservoir_address_hash": fee_reservoir_address_hash,
        "nonce": nonce
    });

    // Convert to JsValue
    let input_js = JsValue::from_serde(&input).expect("Failed to convert input to JsValue");

    // Generate proof
    let proof_js = generate_transfer_proof(input_js).expect("Failed to generate proof");

    // Verify proof
    let result_js = verify_transfer_proof(proof_js).expect("Failed to verify proof");

    // Convert result to Rust object
    let result: serde_json::Value = result_js
        .into_serde()
        .expect("Failed to convert result to Rust object");

    // Check if verification succeeded
    assert_eq!(result["success"], true, "Proof verification failed");
}

/// Test recursive proof aggregation
#[test]
fn test_integration_recursive_aggregation() {
    // Generate test data for wrapped mint
    let (recipient_pk_hash1, amount1, deposit_nonce1, signature1) =
        utils::generate_test_attestation();
    let (_, (custodian_pk_x1, custodian_pk_y1)) = utils::generate_test_key_pair();
    let (signature_r_x1, signature_r_y1, signature_s1) = signature1;

    // Generate test data for wrapped burn
    let (owner_pubkey_hash2, asset_id2, amount2, salt2) = utils::generate_test_utxo();
    let (sender_sk2, (sender_pk_x2, sender_pk_y2)) = utils::generate_test_key_pair();
    let (signature_r_x2, signature_r_y2, signature_s2) = utils::generate_test_signature();
    let destination_btc_address2 = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Generate wrapped mint proof
    let mint_result = WrappedAssetMintCircuit::generate_proof_static(
        &recipient_pk_hash1,
        amount1,
        deposit_nonce1,
        custodian_pk_x1,
        custodian_pk_y1,
        signature_r_x1,
        signature_r_y1,
        signature_s1,
    );

    // Verify that proof generation succeeds
    assert!(
        mint_result.is_ok(),
        "Failed to generate wrapped mint proof: {:?}",
        mint_result.err()
    );

    // Generate wrapped burn proof
    let burn_result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash2,
        &asset_id2,
        amount2,
        &salt2,
        sender_sk2,
        sender_pk_x2,
        sender_pk_y2,
        signature_r_x2,
        signature_r_y2,
        signature_s2,
        &destination_btc_address2,
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
    );

    // Verify that proof generation succeeds
    assert!(
        burn_result.is_ok(),
        "Failed to generate wrapped burn proof: {:?}",
        burn_result.err()
    );

    // Get the proofs
    let mint_proof = mint_result.unwrap();
    let burn_proof = burn_result.unwrap();

    // Aggregate the proofs
    let proofs = vec![mint_proof, burn_proof];
    let aggregation_result = aggregate_proofs(&proofs, "wrapped-mint", 2);

    // Verify that aggregation succeeds
    assert!(
        aggregation_result.is_ok(),
        "Failed to aggregate proofs: {:?}",
        aggregation_result.err()
    );

    // Get the aggregated proof
    let aggregated_proof = aggregation_result.unwrap();

    // Verify the aggregated proof
    let verification_result = verify_aggregated_proof(&aggregated_proof, "wrapped-mint");

    // Verify that verification succeeds
    assert!(
        verification_result.is_ok(),
        "Failed to verify aggregated proof: {:?}",
        verification_result.err()
    );
}

/// Test recursive proof verification
#[test]
fn test_integration_recursive_verification() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().expect("Failed to create temporary directory");
    let input_dir = temp_dir.path().join("proofs");
    let output_path = temp_dir.path().join("aggregated_proof.json");

    // Create the input directory
    fs::create_dir_all(&input_dir).expect("Failed to create input directory");

    // Generate test data for wrapped mint
    let (recipient_pk_hash1, amount1, deposit_nonce1, signature1) =
        utils::generate_test_attestation();
    let (_, (custodian_pk_x1, custodian_pk_y1)) = utils::generate_test_key_pair();
    let (signature_r_x1, signature_r_y1, signature_s1) = signature1;

    // Generate test data for wrapped burn
    let (owner_pubkey_hash2, asset_id2, amount2, salt2) = utils::generate_test_utxo();
    let (sender_sk2, (sender_pk_x2, sender_pk_y2)) = utils::generate_test_key_pair();
    let (signature_r_x2, signature_r_y2, signature_s2) = utils::generate_test_signature();
    let destination_btc_address2 = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Generate wrapped mint proof
    let mint_result = WrappedAssetMintCircuit::generate_proof_static(
        &recipient_pk_hash1,
        amount1,
        deposit_nonce1,
        custodian_pk_x1,
        custodian_pk_y1,
        signature_r_x1,
        signature_r_y1,
        signature_s1,
    );

    // Verify that proof generation succeeds
    assert!(
        mint_result.is_ok(),
        "Failed to generate wrapped mint proof: {:?}",
        mint_result.err()
    );

    // Generate wrapped burn proof
    let burn_result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash2,
        &asset_id2,
        amount2,
        &salt2,
        sender_sk2,
        sender_pk_x2,
        sender_pk_y2,
        signature_r_x2,
        signature_r_y2,
        signature_s2,
        &destination_btc_address2,
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
    );

    // Verify that proof generation succeeds
    assert!(
        burn_result.is_ok(),
        "Failed to generate wrapped burn proof: {:?}",
        burn_result.err()
    );

    // Get the proofs
    let mint_proof = mint_result.unwrap();
    let burn_proof = burn_result.unwrap();

    // Write the proofs to files
    let mint_proof_path = input_dir.join("mint_proof.json");
    let burn_proof_path = input_dir.join("burn_proof.json");

    let mint_proof_json =
        serde_json::to_string(&mint_proof).expect("Failed to serialize mint proof");
    let burn_proof_json =
        serde_json::to_string(&burn_proof).expect("Failed to serialize burn proof");

    let mut mint_file = File::create(&mint_proof_path).expect("Failed to create mint proof file");
    let mut burn_file = File::create(&burn_proof_path).expect("Failed to create burn proof file");

    mint_file
        .write_all(mint_proof_json.as_bytes())
        .expect("Failed to write mint proof file");
    burn_file
        .write_all(burn_proof_json.as_bytes())
        .expect("Failed to write burn proof file");

    // Run the CLI command to aggregate proofs
    let aggregate_status = Command::new("cargo")
        .args(&[
            "run",
            "--bin",
            "wire_cli",
            "--",
            "aggregate-proofs",
            "--input-dir",
            input_dir.to_str().unwrap(),
            "--output-file",
            output_path.to_str().unwrap(),
            "--circuit-type",
            "wrapped-mint",
            "--batch-size",
            "2",
        ])
        .status();

    // Check if the command succeeded
    match aggregate_status {
        Ok(exit_status) => {
            assert!(
                exit_status.success(),
                "Aggregation command failed with status: {}",
                exit_status
            );

            // Check if the output file exists
            assert!(output_path.exists(), "Output file does not exist");

            // Run the CLI command to verify the aggregated proof
            let verify_status = Command::new("cargo")
                .args(&[
                    "run",
                    "--bin",
                    "wire_cli",
                    "--",
                    "verify-aggregated-proof",
                    "--proof-file",
                    output_path.to_str().unwrap(),
                    "--circuit-type",
                    "wrapped-mint",
                ])
                .status();

            // Check if the command succeeded
            match verify_status {
                Ok(exit_status) => {
                    assert!(
                        exit_status.success(),
                        "Verification command failed with status: {}",
                        exit_status
                    );
                }
                Err(err) => {
                    // If the command fails, it might be because the CLI is not available
                    // In that case, skip the test
                    println!("Skipping CLI verification test: {}", err);
                }
            }
        }
        Err(err) => {
            // If the command fails, it might be because the CLI is not available
            // In that case, skip the test
            println!("Skipping CLI aggregation test: {}", err);
        }
    }
}
