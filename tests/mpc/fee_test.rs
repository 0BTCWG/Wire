// MPC Fee Consolidation Tests
//
// This file contains tests for the MPC fee consolidation workflow.

use wire_lib::mpc::{MPCCore, MPCConfig, MPCResult};
use wire_lib::mpc::fee::{FeeUTXO, FeeManager, FeeUTXOStatus, FeeConsolidation, FeeConsolidationStatus};
use wire_lib::mpc::ceremonies::SigningCeremony;
use std::path::PathBuf;
use std::fs;
use tempfile::tempdir;

/// Test creating a fee UTXO
#[test]
fn test_fee_utxo_creation() {
    let utxo = FeeUTXO {
        id: "test-utxo-1".to_string(),
        owner_pubkey_hash: [0u8; 32],
        asset_id: [0u8; 32],
        amount: 100_000, // 0.001 BTC
        salt: [0u8; 32],
        txid: "fee-tx-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        timestamp: 1714500000,
        status: FeeUTXOStatus::Available,
    };
    
    assert_eq!(utxo.id, "test-utxo-1");
    assert_eq!(utxo.amount, 100_000);
    assert_eq!(utxo.txid, "fee-tx-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assert_eq!(utxo.timestamp, 1714500000);
    assert_eq!(utxo.status, FeeUTXOStatus::Available);
}

/// Test serializing and deserializing a fee UTXO
#[test]
fn test_fee_utxo_serialization() {
    let utxo = FeeUTXO {
        id: "test-utxo-2".to_string(),
        owner_pubkey_hash: [1u8; 32],
        asset_id: [0u8; 32],
        amount: 200_000, // 0.002 BTC
        salt: [1u8; 32],
        txid: "fee-tx-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        timestamp: 1714600000,
        status: FeeUTXOStatus::Consolidating,
    };
    
    // Serialize
    let serialized = serde_json::to_string(&utxo).expect("Failed to serialize UTXO");
    
    // Deserialize
    let deserialized: FeeUTXO = serde_json::from_str(&serialized).expect("Failed to deserialize UTXO");
    
    assert_eq!(deserialized.id, utxo.id);
    assert_eq!(deserialized.owner_pubkey_hash, utxo.owner_pubkey_hash);
    assert_eq!(deserialized.asset_id, utxo.asset_id);
    assert_eq!(deserialized.amount, utxo.amount);
    assert_eq!(deserialized.salt, utxo.salt);
    assert_eq!(deserialized.txid, utxo.txid);
    assert_eq!(deserialized.timestamp, utxo.timestamp);
    assert_eq!(deserialized.status, utxo.status);
}

/// Test creating a fee consolidation
#[test]
fn test_fee_consolidation_creation() {
    let consolidation = FeeConsolidation {
        id: "test-consolidation-1".to_string(),
        input_utxos: vec!["utxo-1".to_string(), "utxo-2".to_string(), "utxo-3".to_string()],
        total_amount: 500_000, // 0.005 BTC
        destination_address: [2u8; 32],
        txid: Some("consolidation-tx-1234567890abcdef".to_string()),
        timestamp: 1714700000,
        status: FeeConsolidationStatus::Pending,
    };
    
    assert_eq!(consolidation.id, "test-consolidation-1");
    assert_eq!(consolidation.input_utxos.len(), 3);
    assert_eq!(consolidation.total_amount, 500_000);
    assert_eq!(consolidation.timestamp, 1714700000);
    assert_eq!(consolidation.status, FeeConsolidationStatus::Pending);
    assert_eq!(consolidation.txid, Some("consolidation-tx-1234567890abcdef".to_string()));
}

/// Test serializing and deserializing a fee consolidation
#[test]
fn test_fee_consolidation_serialization() {
    let consolidation = FeeConsolidation {
        id: "test-consolidation-2".to_string(),
        input_utxos: vec!["utxo-4".to_string(), "utxo-5".to_string()],
        total_amount: 300_000, // 0.003 BTC
        destination_address: [3u8; 32],
        txid: None,
        timestamp: 1714800000,
        status: FeeConsolidationStatus::InProgress,
    };
    
    // Serialize
    let serialized = serde_json::to_string(&consolidation).expect("Failed to serialize consolidation");
    
    // Deserialize
    let deserialized: FeeConsolidation = serde_json::from_str(&serialized).expect("Failed to deserialize consolidation");
    
    assert_eq!(deserialized.id, consolidation.id);
    assert_eq!(deserialized.input_utxos, consolidation.input_utxos);
    assert_eq!(deserialized.total_amount, consolidation.total_amount);
    assert_eq!(deserialized.destination_address, consolidation.destination_address);
    assert_eq!(deserialized.txid, consolidation.txid);
    assert_eq!(deserialized.timestamp, consolidation.timestamp);
    assert_eq!(deserialized.status, consolidation.status);
}

/// Test the fee manager
#[test]
fn test_fee_manager() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("fees.json").to_str().unwrap().to_string();
    
    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: "key_share.json".to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };
    
    let mpc_core = MPCCore::new(config)?;
    
    // Create a fee manager
    let mut manager = FeeManager::new(
        mpc_core.clone(),
        db_path,
        [4u8; 32], // Fee reservoir address
        100_000,   // Minimum consolidation amount
        5,         // Maximum UTXOs per consolidation
    )?;
    
    // Add some UTXOs
    let utxo1 = FeeUTXO {
        id: "test-utxo-10".to_string(),
        owner_pubkey_hash: [4u8; 32], // Same as fee reservoir address
        asset_id: [0u8; 32],
        amount: 50_000, // 0.0005 BTC
        salt: [5u8; 32],
        txid: "fee-tx-1".to_string(),
        timestamp: 1714900000,
        status: FeeUTXOStatus::Available,
    };
    
    let utxo2 = FeeUTXO {
        id: "test-utxo-11".to_string(),
        owner_pubkey_hash: [4u8; 32], // Same as fee reservoir address
        asset_id: [0u8; 32],
        amount: 75_000, // 0.00075 BTC
        salt: [6u8; 32],
        txid: "fee-tx-2".to_string(),
        timestamp: 1714910000,
        status: FeeUTXOStatus::Available,
    };
    
    manager.add_utxo(utxo1)?;
    manager.add_utxo(utxo2)?;
    
    // Get available UTXOs
    let available_utxos = manager.get_available_utxos();
    assert_eq!(available_utxos.len(), 2);
    
    // Create a consolidation
    let consolidation = manager.create_consolidation([7u8; 32])?;
    
    // Check the consolidation
    assert_eq!(consolidation.input_utxos.len(), 2);
    assert_eq!(consolidation.total_amount, 125_000); // 0.00125 BTC
    assert_eq!(consolidation.status, FeeConsolidationStatus::Pending);
    
    // Generate a consolidation proof
    let proof = manager.generate_consolidation_proof(&consolidation.id)?;
    
    // Check that the consolidation status has changed
    let in_progress = manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(in_progress.status, FeeConsolidationStatus::InProgress);
    
    // Complete the consolidation
    manager.complete_consolidation(&consolidation.id)?;
    
    // Check that the consolidation status has changed
    let completed = manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(completed.status, FeeConsolidationStatus::Completed);
    
    // Check that the input UTXOs are now spent
    for utxo_id in &consolidation.input_utxos {
        let utxo = manager.get_utxo(utxo_id).unwrap();
        assert_eq!(utxo.status, FeeUTXOStatus::Spent);
    }
    
    // Check that a new UTXO has been created for the consolidated amount
    let all_utxos = manager.get_all_utxos();
    assert_eq!(all_utxos.len(), 3); // 2 original + 1 new
    
    // Find the new UTXO
    let new_utxo = all_utxos.iter()
        .find(|u| u.status == FeeUTXOStatus::Available && u.id != "test-utxo-10" && u.id != "test-utxo-11")
        .unwrap();
    
    assert_eq!(new_utxo.amount, 125_000);
    assert_eq!(new_utxo.owner_pubkey_hash, [7u8; 32]); // The destination address
    
    Ok(())
}

/// Test the full fee consolidation workflow
#[test]
fn test_fee_consolidation_workflow() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("fees.json").to_str().unwrap().to_string();
    
    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: "key_share.json".to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };
    
    let mpc_core = MPCCore::new(config)?;
    
    // Step 1: Create a fee manager
    let mut manager = FeeManager::new(
        mpc_core.clone(),
        db_path,
        [8u8; 32], // Fee reservoir address
        100_000,   // Minimum consolidation amount
        5,         // Maximum UTXOs per consolidation
    )?;
    
    // Step 2: Add some UTXOs
    for i in 0..10 {
        let utxo = FeeUTXO {
            id: format!("workflow-utxo-{}", i),
            owner_pubkey_hash: [8u8; 32], // Same as fee reservoir address
            asset_id: [0u8; 32],
            amount: 20_000, // 0.0002 BTC
            salt: [i as u8; 32],
            txid: format!("fee-tx-{}", i),
            timestamp: 1715000000 + i as u64,
            status: FeeUTXOStatus::Available,
        };
        
        manager.add_utxo(utxo)?;
    }
    
    // Step 3: Scan for UTXOs
    let new_utxos = manager.scan_for_utxos()?;
    
    // Step 4: Get available UTXOs
    let available_utxos = manager.get_available_utxos();
    assert_eq!(available_utxos.len(), 10);
    
    // Step 5: Create a consolidation
    let consolidation = manager.create_consolidation([9u8; 32])?;
    
    // Step 6: Check the consolidation
    assert_eq!(consolidation.input_utxos.len(), 5); // Limited by max_consolidation_utxos
    assert_eq!(consolidation.total_amount, 100_000); // 0.001 BTC
    assert_eq!(consolidation.status, FeeConsolidationStatus::Pending);
    
    // Step 7: Create a signing ceremony for the consolidation
    let message = format!("consolidate:{}", consolidation.id);
    let mut signing_ceremony = SigningCeremony::new(
        format!("sign-consolidation-{}", consolidation.id),
        message.as_bytes().to_vec(),
        mpc_core.clone(),
    )?;
    
    // Step 8: Start the signing ceremony
    signing_ceremony.start()?;
    
    // Step 9: Complete the signing ceremony (simulated)
    signing_ceremony.complete()?;
    
    // Step 10: Get the signature
    let signature = signing_ceremony.get_signature()?;
    
    // Step 11: Generate a consolidation proof
    let proof = manager.generate_consolidation_proof(&consolidation.id)?;
    
    // Step 12: Complete the consolidation
    manager.complete_consolidation(&consolidation.id)?;
    
    // Step 13: Verify the consolidation is completed
    let completed = manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(completed.status, FeeConsolidationStatus::Completed);
    
    // Step 14: Check that the input UTXOs are now spent
    for utxo_id in &consolidation.input_utxos {
        let utxo = manager.get_utxo(utxo_id).unwrap();
        assert_eq!(utxo.status, FeeUTXOStatus::Spent);
    }
    
    // Step 15: Check that a new UTXO has been created for the consolidated amount
    let all_utxos = manager.get_all_utxos();
    assert_eq!(all_utxos.len(), 11); // 10 original + 1 new
    
    // Step 16: Find the new UTXO
    let new_utxo = all_utxos.iter()
        .find(|u| u.status == FeeUTXOStatus::Available && u.owner_pubkey_hash == [9u8; 32])
        .unwrap();
    
    assert_eq!(new_utxo.amount, 100_000);
    
    Ok(())
}

/// Test handling failed consolidations
#[test]
fn test_failed_consolidation() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("fees.json").to_str().unwrap().to_string();
    
    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: "key_share.json".to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };
    
    let mpc_core = MPCCore::new(config)?;
    
    // Create a fee manager
    let mut manager = FeeManager::new(
        mpc_core.clone(),
        db_path,
        [10u8; 32], // Fee reservoir address
        100_000,    // Minimum consolidation amount
        5,          // Maximum UTXOs per consolidation
    )?;
    
    // Add some UTXOs
    for i in 0..5 {
        let utxo = FeeUTXO {
            id: format!("fail-utxo-{}", i),
            owner_pubkey_hash: [10u8; 32], // Same as fee reservoir address
            asset_id: [0u8; 32],
            amount: 30_000, // 0.0003 BTC
            salt: [i as u8; 32],
            txid: format!("fee-tx-{}", i),
            timestamp: 1715100000 + i as u64,
            status: FeeUTXOStatus::Available,
        };
        
        manager.add_utxo(utxo)?;
    }
    
    // Create a consolidation
    let consolidation = manager.create_consolidation([11u8; 32])?;
    
    // Check the consolidation
    assert_eq!(consolidation.input_utxos.len(), 5);
    assert_eq!(consolidation.total_amount, 150_000); // 0.0015 BTC
    assert_eq!(consolidation.status, FeeConsolidationStatus::Pending);
    
    // Generate a consolidation proof
    let proof = manager.generate_consolidation_proof(&consolidation.id)?;
    
    // Check that the consolidation status has changed
    let in_progress = manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(in_progress.status, FeeConsolidationStatus::InProgress);
    
    // Fail the consolidation
    manager.fail_consolidation(&consolidation.id, "Simulated failure")?;
    
    // Check that the consolidation status has changed
    let failed = manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(failed.status, FeeConsolidationStatus::Failed);
    
    // Check that the input UTXOs are available again
    for utxo_id in &consolidation.input_utxos {
        let utxo = manager.get_utxo(utxo_id).unwrap();
        assert_eq!(utxo.status, FeeUTXOStatus::Available);
    }
    
    Ok(())
}
