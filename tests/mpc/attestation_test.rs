// MPC Attestation Tests
//
// This file contains tests for the MPC mint attestation workflow.

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use wire_lib::mpc::attestation::{AttestationManager, MintAttestation};
use wire_lib::mpc::ceremonies::SigningCeremony;
use wire_lib::mpc::{MPCConfig, MPCCore, MPCResult};

/// Test creating a mint attestation
#[test]
fn test_mint_attestation_creation() {
    let attestation = MintAttestation {
        id: "test-attestation-1".to_string(),
        bitcoin_txid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        bitcoin_vout: 0,
        recipient_pubkey_hash: [0u8; 32],
        amount: 100_000_000, // 1 BTC
        nonce: 12345,
        expiry: 1714500000, // Some time in the future
        signature: None,
        status: wire_lib::mpc::attestation::AttestationStatus::Pending,
    };

    assert_eq!(attestation.id, "test-attestation-1");
    assert_eq!(
        attestation.bitcoin_txid,
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    );
    assert_eq!(attestation.bitcoin_vout, 0);
    assert_eq!(attestation.amount, 100_000_000);
    assert_eq!(attestation.nonce, 12345);
    assert_eq!(attestation.expiry, 1714500000);
    assert_eq!(
        attestation.status,
        wire_lib::mpc::attestation::AttestationStatus::Pending
    );
    assert!(attestation.signature.is_none());
}

/// Test serializing and deserializing a mint attestation
#[test]
fn test_mint_attestation_serialization() {
    let attestation = MintAttestation {
        id: "test-attestation-2".to_string(),
        bitcoin_txid: "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
            .to_string(),
        bitcoin_vout: 0,
        recipient_pubkey_hash: [1u8; 32],
        amount: 50_000_000, // 0.5 BTC
        nonce: 67890,
        expiry: 1714600000, // Some time in the future
        signature: Some(vec![1, 2, 3, 4, 5]),
        status: wire_lib::mpc::attestation::AttestationStatus::Signed,
    };

    // Serialize
    let serialized = serde_json::to_string(&attestation).expect("Failed to serialize attestation");

    // Deserialize
    let deserialized: MintAttestation =
        serde_json::from_str(&serialized).expect("Failed to deserialize attestation");

    assert_eq!(deserialized.id, attestation.id);
    assert_eq!(deserialized.bitcoin_txid, attestation.bitcoin_txid);
    assert_eq!(deserialized.bitcoin_vout, attestation.bitcoin_vout);
    assert_eq!(
        deserialized.recipient_pubkey_hash,
        attestation.recipient_pubkey_hash
    );
    assert_eq!(deserialized.amount, attestation.amount);
    assert_eq!(deserialized.nonce, attestation.nonce);
    assert_eq!(deserialized.expiry, attestation.expiry);
    assert_eq!(deserialized.status, attestation.status);
    assert_eq!(deserialized.signature, attestation.signature);
}

/// Test the attestation manager
#[test]
fn test_attestation_manager() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("attestations.json");

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

    // Create an attestation manager
    let mut manager =
        AttestationManager::new(mpc_core.clone(), db_path.to_str().unwrap().to_string())?;

    // Create an attestation
    let attestation = manager.create_attestation(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        0,
        [2u8; 32],
        75_000_000, // 0.75 BTC
    )?;

    // Get the attestation
    let retrieved = manager.get_attestation(&attestation.id)?;

    assert_eq!(retrieved.id, attestation.id);
    assert_eq!(retrieved.bitcoin_txid, attestation.bitcoin_txid);
    assert_eq!(retrieved.bitcoin_vout, attestation.bitcoin_vout);
    assert_eq!(
        retrieved.recipient_pubkey_hash,
        attestation.recipient_pubkey_hash
    );
    assert_eq!(retrieved.amount, attestation.amount);

    // Update the attestation status
    manager.update_attestation_status(
        &attestation.id,
        wire_lib::mpc::attestation::AttestationStatus::Signing,
    )?;

    let updated = manager.get_attestation(&attestation.id)?;
    assert_eq!(
        updated.status,
        wire_lib::mpc::attestation::AttestationStatus::Signing
    );

    // Add a signature
    let signature = vec![10, 11, 12, 13, 14];
    manager.add_signature(&attestation.id, signature.clone())?;

    let signed = manager.get_attestation(&attestation.id)?;
    assert_eq!(
        signed.status,
        wire_lib::mpc::attestation::AttestationStatus::Signed
    );
    assert_eq!(signed.signature.unwrap(), signature);

    Ok(())
}

/// Test the full attestation workflow
#[test]
fn test_attestation_workflow() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("attestations.json");

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

    // Create an attestation manager
    let mut manager =
        AttestationManager::new(mpc_core.clone(), db_path.to_str().unwrap().to_string())?;

    // Step 1: Create an attestation
    let attestation = manager.create_attestation(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        0,
        [3u8; 32],
        25_000_000, // 0.25 BTC
    )?;

    // Step 2: Initiate signing
    manager.update_attestation_status(
        &attestation.id,
        wire_lib::mpc::attestation::AttestationStatus::Signing,
    )?;

    // Step 3: Create a signing ceremony
    let message = attestation.to_message_bytes()?;
    let mut signing_ceremony = SigningCeremony::new(
        format!("sign-attestation-{}", attestation.id),
        message,
        mpc_core.clone(),
    )?;

    // Step 4: Start the signing ceremony
    signing_ceremony.start()?;

    // Step 5: Complete the signing ceremony (simulated)
    signing_ceremony.complete()?;

    // Step 6: Get the signature
    let signature = signing_ceremony.get_signature()?;

    // Step 7: Add the signature to the attestation
    manager.add_signature(&attestation.id, signature)?;

    // Step 8: Verify the attestation is signed
    let signed_attestation = manager.get_attestation(&attestation.id)?;
    assert_eq!(
        signed_attestation.status,
        wire_lib::mpc::attestation::AttestationStatus::Signed
    );
    assert!(signed_attestation.signature.is_some());

    // Step 9: Verify the attestation
    let verification_result = signed_attestation.verify(&mpc_core.get_public_key()?);
    assert!(verification_result.is_ok());

    Ok(())
}

/// Test handling invalid attestations
#[test]
fn test_invalid_attestation() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let db_path = temp_dir.path().join("attestations.json");

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

    // Create an attestation manager
    let mut manager =
        AttestationManager::new(mpc_core.clone(), db_path.to_str().unwrap().to_string())?;

    // Try to get a non-existent attestation
    let result = manager.get_attestation("non-existent-id");
    assert!(result.is_err());

    // Create an attestation with an invalid Bitcoin txid
    let result = manager.create_attestation("invalid-txid".to_string(), 0, [4u8; 32], 10_000_000);
    assert!(result.is_err());

    // Create a valid attestation
    let attestation = manager.create_attestation(
        "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".to_string(),
        0,
        [5u8; 32],
        15_000_000,
    )?;

    // Try to add a signature to a non-existent attestation
    let result = manager.add_signature("non-existent-id", vec![1, 2, 3]);
    assert!(result.is_err());

    // Try to update the status of a non-existent attestation
    let result = manager.update_attestation_status(
        "non-existent-id",
        wire_lib::mpc::attestation::AttestationStatus::Signing,
    );
    assert!(result.is_err());

    Ok(())
}
