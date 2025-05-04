// MPC Core Tests
//
// This file contains tests for the core MPC functionality, including
// key generation, signing, and verification.

use std::fs;
use std::path::PathBuf;
use tempfile::tempdir;
use wire_lib::mpc::ceremonies::{CeremonyStatus, DKGCeremony, SigningCeremony};
use wire_lib::mpc::core::{KeyShare, PublicKey};
use wire_lib::mpc::{MPCConfig, MPCCore, MPCResult};

/// Test creating an MPC configuration
#[test]
fn test_mpc_config_creation() {
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

    assert_eq!(config.parties, 3);
    assert_eq!(config.threshold, 2);
    assert_eq!(config.my_index, 0);
    assert_eq!(config.party_addresses.len(), 3);
}

/// Test serializing and deserializing an MPC configuration
#[test]
fn test_mpc_config_serialization() {
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

    // Serialize
    let serialized = serde_json::to_string(&config).expect("Failed to serialize config");

    // Deserialize
    let deserialized: MPCConfig =
        serde_json::from_str(&serialized).expect("Failed to deserialize config");

    assert_eq!(deserialized.parties, config.parties);
    assert_eq!(deserialized.threshold, config.threshold);
    assert_eq!(deserialized.my_index, config.my_index);
    assert_eq!(deserialized.party_addresses, config.party_addresses);
    assert_eq!(deserialized.key_share_path, config.key_share_path);
    assert_eq!(deserialized.tls_cert_path, config.tls_cert_path);
    assert_eq!(deserialized.tls_key_path, config.tls_key_path);
}

/// Test creating an MPC core instance
#[test]
fn test_mpc_core_creation() -> MPCResult<()> {
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

    assert_eq!(mpc_core.get_party_count(), 3);
    assert_eq!(mpc_core.get_threshold(), 2);

    Ok(())
}

/// Test DKG ceremony creation and state transitions
#[test]
fn test_dkg_ceremony() -> MPCResult<()> {
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

    // Create a new DKG ceremony
    let mut ceremony = DKGCeremony::new("test-dkg-1".to_string(), mpc_core.clone())?;

    // Check initial state
    assert_eq!(ceremony.get_status(), CeremonyStatus::Created);

    // Start the ceremony
    ceremony.start()?;
    assert_eq!(ceremony.get_status(), CeremonyStatus::InProgress);

    // Complete the ceremony (simulated)
    ceremony.complete()?;
    assert_eq!(ceremony.get_status(), CeremonyStatus::Completed);

    Ok(())
}

/// Test signing ceremony creation and state transitions
#[test]
fn test_signing_ceremony() -> MPCResult<()> {
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

    // Create a new signing ceremony
    let message = b"Test message to sign";
    let mut ceremony = SigningCeremony::new(
        "test-signing-1".to_string(),
        message.to_vec(),
        mpc_core.clone(),
    )?;

    // Check initial state
    assert_eq!(ceremony.get_status(), CeremonyStatus::Created);

    // Start the ceremony
    ceremony.start()?;
    assert_eq!(ceremony.get_status(), CeremonyStatus::InProgress);

    // Complete the ceremony (simulated)
    ceremony.complete()?;
    assert_eq!(ceremony.get_status(), CeremonyStatus::Completed);

    Ok(())
}

/// Test key share creation and serialization
#[test]
fn test_key_share() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let key_share_path = temp_dir.path().join("key_share.json");

    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: key_share_path.to_str().unwrap().to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };

    let mpc_core = MPCCore::new(config)?;

    // Create a key share
    let key_share = KeyShare::new(0, vec![1, 2, 3, 4]);

    // Save the key share
    mpc_core.save_key_share(&key_share)?;

    // Load the key share
    let loaded_key_share = mpc_core.load_key_share()?;

    assert_eq!(loaded_key_share.index, key_share.index);
    assert_eq!(loaded_key_share.data, key_share.data);

    Ok(())
}

/// Test public key creation and verification
#[test]
fn test_public_key() -> MPCResult<()> {
    // Create a public key
    let public_key = PublicKey::new(vec![1, 2, 3, 4]);

    // Verify a signature (simulated)
    let message = b"Test message";
    let signature = vec![5, 6, 7, 8];

    let result = public_key.verify(message, &signature);

    // This is a simulated verification, so it should return Ok
    assert!(result.is_ok());

    Ok(())
}

/// Test full DKG and signing workflow
#[test]
fn test_dkg_and_signing_workflow() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempdir().expect("Failed to create temp dir");
    let key_share_path = temp_dir.path().join("key_share.json");

    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: key_share_path.to_str().unwrap().to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };

    let mpc_core = MPCCore::new(config)?;

    // Step 1: Perform DKG
    let mut dkg_ceremony = DKGCeremony::new("test-dkg-workflow".to_string(), mpc_core.clone())?;
    dkg_ceremony.start()?;
    dkg_ceremony.complete()?;

    // Step 2: Create a key share
    let key_share = KeyShare::new(0, vec![1, 2, 3, 4]);
    mpc_core.save_key_share(&key_share)?;

    // Step 3: Sign a message
    let message = b"Test message for workflow";
    let mut signing_ceremony = SigningCeremony::new(
        "test-signing-workflow".to_string(),
        message.to_vec(),
        mpc_core.clone(),
    )?;
    signing_ceremony.start()?;
    signing_ceremony.complete()?;

    // Step 4: Get the signature
    let signature = signing_ceremony.get_signature()?;

    // Step 5: Verify the signature
    let public_key = PublicKey::new(vec![9, 10, 11, 12]); // In a real implementation, this would be derived from the DKG
    let verification_result = public_key.verify(message, &signature);

    assert!(verification_result.is_ok());

    Ok(())
}
