//! Tests for measuring performance characteristics of the 0BTC Wire system
//!
//! These tests focus on proof generation time, verification time, and memory usage.

use crate::audit::utils;
use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::transfer::TransferCircuit;
use std::time::Duration;

/// Test proof generation performance for wrapped mint circuit
#[test]
fn test_performance_wrapped_mint_generation() {
    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, signature) = utils::generate_test_attestation();
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = signature;
    
    // Measure proof generation time
    let (result, duration) = utils::measure_time(|| {
        WrappedAssetMintCircuit::generate_proof_static(
            &recipient_pk_hash,
            amount,
            deposit_nonce,
            custodian_pk_x,
            custodian_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        )
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the duration
    println!("Wrapped mint proof generation time: {:?}", duration);
    
    // Verify that the proof is valid
    let proof = result.unwrap();
    let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_secs(10);
    assert!(duration <= expected_max_duration, 
            "Proof generation took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test proof generation performance for wrapped burn circuit
#[test]
fn test_performance_wrapped_burn_generation() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac];
    
    // Measure proof generation time
    let (result, duration) = utils::measure_time(|| {
        WrappedAssetBurnCircuit::generate_proof_static(
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
        )
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the duration
    println!("Wrapped burn proof generation time: {:?}", duration);
    
    // Verify that the proof is valid
    let proof = result.unwrap();
    let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_secs(10);
    assert!(duration <= expected_max_duration, 
            "Proof generation took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test proof generation performance for transfer circuit
#[test]
fn test_performance_transfer_generation() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;
    
    // Create input UTXOs
    let input_utxos_data = vec![(owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone())];
    
    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];
    
    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);
    
    // Measure proof generation time
    let (result, duration) = utils::measure_time(|| {
        TransferCircuit::generate_proof_static(
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
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the duration
    println!("Transfer proof generation time: {:?}", duration);
    
    // Verify that the proof is valid
    let proof = result.unwrap();
    let verification_result = TransferCircuit::verify_proof(&proof);
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_secs(10);
    assert!(duration <= expected_max_duration, 
            "Proof generation took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test proof verification performance for wrapped mint circuit
#[test]
fn test_performance_wrapped_mint_verification() {
    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, signature) = utils::generate_test_attestation();
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = signature;
    
    // Generate a valid proof
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
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Get the proof
    let proof = result.unwrap();
    
    // Measure verification time
    let (verification_result, duration) = utils::measure_time(|| {
        WrappedAssetMintCircuit::verify_proof(&proof)
    });
    
    // Verify that the proof is valid
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Log the duration
    println!("Wrapped mint proof verification time: {:?}", duration);
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_millis(100);
    assert!(duration <= expected_max_duration, 
            "Proof verification took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test proof verification performance for wrapped burn circuit
#[test]
fn test_performance_wrapped_burn_verification() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac];
    
    // Generate a valid proof
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
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Get the proof
    let proof = result.unwrap();
    
    // Measure verification time
    let (verification_result, duration) = utils::measure_time(|| {
        WrappedAssetBurnCircuit::verify_proof(&proof)
    });
    
    // Verify that the proof is valid
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Log the duration
    println!("Wrapped burn proof verification time: {:?}", duration);
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_millis(100);
    assert!(duration <= expected_max_duration, 
            "Proof verification took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test proof verification performance for transfer circuit
#[test]
fn test_performance_transfer_verification() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;
    
    // Create input UTXOs
    let input_utxos_data = vec![(owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone())];
    
    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];
    
    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);
    
    // Generate a valid proof
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
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Get the proof
    let proof = result.unwrap();
    
    // Measure verification time
    let (verification_result, duration) = utils::measure_time(|| {
        TransferCircuit::verify_proof(&proof)
    });
    
    // Verify that the proof is valid
    assert!(verification_result.is_ok(), "Failed to verify valid proof: {:?}", verification_result.err());
    
    // Log the duration
    println!("Transfer proof verification time: {:?}", duration);
    
    // Check if the performance meets the expected threshold
    // This is a placeholder threshold, adjust based on actual performance measurements
    let expected_max_duration = Duration::from_millis(100);
    assert!(duration <= expected_max_duration, 
            "Proof verification took too long: {:?} (expected <= {:?})", 
            duration, expected_max_duration);
}

/// Test memory usage for wrapped mint proof generation
#[test]
fn test_memory_usage_wrapped_mint() {
    // Generate test data
    let (recipient_pk_hash, amount, deposit_nonce, signature) = utils::generate_test_attestation();
    let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = signature;
    
    // Measure memory usage
    let (result, memory_usage) = utils::measure_memory(|| {
        WrappedAssetMintCircuit::generate_proof_static(
            &recipient_pk_hash,
            amount,
            deposit_nonce,
            custodian_pk_x,
            custodian_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        )
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the memory usage
    println!("Wrapped mint proof generation memory usage: {} bytes", memory_usage);
    
    // In a real test, we would check if the memory usage meets the expected threshold
    // For this example, we just log the memory usage
}

/// Test memory usage for wrapped burn proof generation
#[test]
fn test_memory_usage_wrapped_burn() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let destination_btc_address = vec![0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac];
    
    // Measure memory usage
    let (result, memory_usage) = utils::measure_memory(|| {
        WrappedAssetBurnCircuit::generate_proof_static(
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
        )
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the memory usage
    println!("Wrapped burn proof generation memory usage: {} bytes", memory_usage);
    
    // In a real test, we would check if the memory usage meets the expected threshold
    // For this example, we just log the memory usage
}

/// Test memory usage for transfer proof generation
#[test]
fn test_memory_usage_transfer() {
    // Generate test data
    let (owner_pubkey_hash, asset_id, amount, salt) = utils::generate_test_utxo();
    let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;
    
    // Create input UTXOs
    let input_utxos_data = vec![(owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone())];
    
    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];
    
    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);
    
    // Measure memory usage
    let (result, memory_usage) = utils::measure_memory(|| {
        TransferCircuit::generate_proof_static(
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
    });
    
    // Verify that proof generation succeeds
    assert!(result.is_ok(), "Failed to generate valid proof: {:?}", result.err());
    
    // Log the memory usage
    println!("Transfer proof generation memory usage: {} bytes", memory_usage);
    
    // In a real test, we would check if the memory usage meets the expected threshold
    // For this example, we just log the memory usage
}
