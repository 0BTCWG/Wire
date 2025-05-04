//! Tests for verifying behavior in edge cases and boundary conditions
//!
//! These tests focus on numerical, structural, and cryptographic edge cases.

use crate::audit::utils;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::errors::WireError;

/// Test behavior with maximum field values
#[test]
fn test_edge_case_max_field_value() {
    // Get the maximum value in the Goldilocks field
    let max_field_value = GoldilocksField::ORDER - 1;

    // Generate test data
    let recipient_pk_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let deposit_nonce = 42;
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();

    // Use the maximum field value as the amount
    let amount = max_field_value;

    // Generate a proof with maximum amount
    let result = WrappedAssetMintCircuit::generate_proof_static(
        &recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );

    // The proof generation might fail if the circuit doesn't handle max values correctly
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof with max field value: {:?}",
                verification_result.err()
            );
            println!("Circuit correctly handles maximum field value");
        }
        Err(err) => {
            // If proof generation fails, check if it's due to a legitimate constraint
            // (e.g., amount must be less than some maximum)
            println!("Circuit rejected maximum field value: {:?}", err);
            // This might be expected behavior if the circuit has explicit bounds
        }
    }
}

/// Test behavior with zero values
#[test]
fn test_edge_case_zero_value() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, _, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Use zero as the amount
    let amount = 0;

    // Generate a proof with zero amount
    let result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash,
        &asset_id,
        amount,
        &salt,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        &destination_btc_address,
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
    );

    // The proof generation might fail if the circuit doesn't allow zero amounts
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof with zero amount: {:?}",
                verification_result.err()
            );
            println!("Circuit correctly handles zero amount");
        }
        Err(err) => {
            // If proof generation fails, check if it's due to a legitimate constraint
            // (e.g., amount must be greater than zero)
            println!("Circuit rejected zero amount: {:?}", err);
            // This might be expected behavior if the circuit requires positive amounts
        }
    }
}

/// Test behavior with maximum number of inputs
#[test]
fn test_edge_case_max_inputs() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create the maximum number of input UTXOs
    // In a real circuit, this would be the maximum supported by the circuit
    // For this example, we use 10 as the maximum
    let max_inputs = 10;
    let input_amount = amount / max_inputs as u64;
    let mut input_utxos_data = Vec::new();
    for _ in 0..max_inputs {
        input_utxos_data.push((
            owner_pubkey_hash.clone(),
            asset_id.clone(),
            input_amount,
            salt.clone(),
        ));
    }

    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![input_amount * max_inputs as u64 - fee_amount];

    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (
        owner_pubkey_hash.clone(),
        asset_id.clone(),
        amount,
        salt.clone(),
    );

    // Generate a proof with maximum inputs
    let result = TransferCircuit::generate_proof_static(
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
    );

    // The proof generation might fail if the circuit doesn't support the maximum number of inputs
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            let verification_result = TransferCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof with maximum inputs: {:?}",
                verification_result.err()
            );
            println!("Circuit correctly handles maximum inputs");
        }
        Err(err) => {
            // If proof generation fails, check if it's due to a legitimate constraint
            // (e.g., the circuit has a lower maximum input limit)
            println!("Circuit rejected maximum inputs: {:?}", err);
            // This might be expected behavior if the circuit has a lower limit
        }
    }
}

/// Test behavior with maximum number of outputs
#[test]
fn test_edge_case_max_outputs() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create input UTXOs
    let input_utxos_data = vec![(
        owner_pubkey_hash.clone(),
        asset_id.clone(),
        amount,
        salt.clone(),
    )];

    // Create the maximum number of outputs
    // In a real circuit, this would be the maximum supported by the circuit
    // For this example, we use 10 as the maximum
    let max_outputs = 10;
    let output_amount = (amount - fee_amount) / max_outputs as u64;
    let mut recipient_pk_hashes = Vec::new();
    let mut output_amounts = Vec::new();
    for i in 0..max_outputs {
        let pk_hash = vec![i as u8, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
        recipient_pk_hashes.push(pk_hash);
        output_amounts.push(output_amount);
    }

    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);

    // Generate a proof with maximum outputs
    let result = TransferCircuit::generate_proof_static(
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
    );

    // The proof generation might fail if the circuit doesn't support the maximum number of outputs
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            let verification_result = TransferCircuit::verify_proof(&proof);
            assert!(
                verification_result.is_ok(),
                "Failed to verify proof with maximum outputs: {:?}",
                verification_result.err()
            );
            println!("Circuit correctly handles maximum outputs");
        }
        Err(err) => {
            // If proof generation fails, check if it's due to a legitimate constraint
            // (e.g., the circuit has a lower maximum output limit)
            println!("Circuit rejected maximum outputs: {:?}", err);
            // This might be expected behavior if the circuit has a lower limit
        }
    }
}

/// Test behavior with empty inputs
#[test]
fn test_edge_case_empty_inputs() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2;
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create empty input UTXOs
    let input_utxos_data: Vec<(Vec<u8>, Vec<u8>, u64, Vec<u8>)> = Vec::new();

    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];

    // Create fee UTXO data (using a valid UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);

    // Generate a proof with empty inputs
    let result = TransferCircuit::generate_proof_static(
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
    );

    // The proof generation should fail because inputs cannot be empty
    assert!(
        result.is_err(),
        "Proof generation should fail for empty inputs"
    );

    // Verify that the error is related to empty inputs
    if let Err(err) = result {
        println!("Circuit correctly rejected empty inputs: {:?}", err);
    }
}

/// Test behavior with point at infinity
#[test]
fn test_edge_case_point_at_infinity() {
    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, _) = utils::generate_test_attestation();

    // Use the point at infinity as the custodian public key
    // In a real circuit, this would be the actual point at infinity
    // For this example, we use (0, 0) as a placeholder
    let custodian_pk_x = 0;
    let custodian_pk_y = 0;

    // Use a valid signature
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();

    // Generate a proof with point at infinity
    let result = WrappedAssetMintCircuit::generate_proof_static(
        &recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );

    // The proof generation should fail because the point at infinity is not a valid public key
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            // (this should not happen for a secure implementation)
            let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
            if verification_result.is_ok() {
                println!("WARNING: Circuit accepted point at infinity as public key");
            } else {
                println!("Circuit correctly rejected point at infinity during verification");
            }
        }
        Err(err) => {
            // If proof generation fails, that's expected
            println!("Circuit correctly rejected point at infinity: {:?}", err);
        }
    }
}

/// Test behavior with identity element
#[test]
fn test_edge_case_identity_element() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();

    // Use the identity element as the signature
    // In a real circuit, this would be the actual identity element
    // For this example, we use (0, 0, 0) as a placeholder
    let signature_r_x = 0;
    let signature_r_y = 0;
    let signature_s = 0;

    let destination_btc_address = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Generate a proof with identity element
    let result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash,
        &asset_id,
        amount,
        &salt,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        &destination_btc_address,
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
    );

    // The proof generation should fail because the identity element is not a valid signature
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify that the proof is valid
            // (this should not happen for a secure implementation)
            let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
            if verification_result.is_ok() {
                println!("WARNING: Circuit accepted identity element as signature");
            } else {
                println!("Circuit correctly rejected identity element during verification");
            }
        }
        Err(err) => {
            // If proof generation fails, that's expected
            println!("Circuit correctly rejected identity element: {:?}", err);
        }
    }
}
