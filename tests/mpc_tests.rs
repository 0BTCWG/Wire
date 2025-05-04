// MPC Integration Tests
//
// This file includes all the MPC test modules for integration testing.

// Include the test modules
mod mpc {
    mod attestation_test;
    mod burn_test;
    mod core_test;
    mod fee_test;
}

// Import the required dependencies
use wire_lib::mpc::attestation::{AttestationManager, MintAttestation};
use wire_lib::mpc::burn::{BurnManager, BurnProof};
use wire_lib::mpc::ceremonies::{CeremonyStatus, DKGCeremony, SigningCeremony};
use wire_lib::mpc::fee::{FeeManager, FeeUTXO};
use wire_lib::mpc::{MPCConfig, MPCCore, MPCResult};

/// Test the full mint-transfer-burn lifecycle with MPC integration
#[test]
fn test_full_lifecycle() -> MPCResult<()> {
    // Create a temporary directory for the test
    let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
    let attestation_db_path = temp_dir
        .path()
        .join("attestations.json")
        .to_str()
        .unwrap()
        .to_string();
    let burn_db_path = temp_dir
        .path()
        .join("burns.json")
        .to_str()
        .unwrap()
        .to_string();

    // Create MPC configuration
    let config = MPCConfig {
        parties: 3,
        threshold: 2,
        party_addresses: vec![
            "localhost:50051".to_string(),
            "localhost:50052".to_string(),
            "localhost:50053".to_string(),
        ],
        my_index: 0,
        key_share_path: temp_dir
            .path()
            .join("key_share.json")
            .to_str()
            .unwrap()
            .to_string(),
        tls_cert_path: "tls_cert.pem".to_string(),
        tls_key_path: "tls_key.pem".to_string(),
    };

    // Initialize MPC core
    let mpc_core = MPCCore::new(config)?;

    // Step 1: Perform DKG
    println!("Step 1: Performing Distributed Key Generation (DKG)");
    let mut dkg_ceremony = DKGCeremony::new("lifecycle-dkg".to_string(), mpc_core.clone())?;
    dkg_ceremony.start()?;
    dkg_ceremony.complete()?;
    println!("DKG completed successfully");

    // Step 2: Create attestation manager
    println!("Step 2: Creating attestation manager");
    let mut attestation_manager = AttestationManager::new(mpc_core.clone(), attestation_db_path)?;

    // Step 3: Create a mint attestation
    println!("Step 3: Creating mint attestation");
    let bitcoin_txid = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let bitcoin_vout = 0;
    let recipient_pubkey_hash = [1u8; 32];
    let amount = 100_000_000; // 1 BTC

    let attestation = attestation_manager.create_attestation(
        bitcoin_txid.to_string(),
        bitcoin_vout,
        recipient_pubkey_hash,
        amount,
    )?;
    println!("Created attestation: {}", attestation.id);

    // Step 4: Sign the attestation
    println!("Step 4: Signing the attestation");
    attestation_manager.update_attestation_status(
        &attestation.id,
        wire_lib::mpc::attestation::AttestationStatus::Signing,
    )?;

    let message = attestation.to_message_bytes()?;
    let mut signing_ceremony = SigningCeremony::new(
        format!("sign-attestation-{}", attestation.id),
        message,
        mpc_core.clone(),
    )?;

    signing_ceremony.start()?;
    signing_ceremony.complete()?;

    let signature = signing_ceremony.get_signature()?;
    attestation_manager.add_signature(&attestation.id, signature)?;

    let signed_attestation = attestation_manager.get_attestation(&attestation.id)?;
    assert_eq!(
        signed_attestation.status,
        wire_lib::mpc::attestation::AttestationStatus::Signed
    );
    println!("Attestation signed successfully");

    // Step 5: Create burn manager
    println!("Step 5: Creating burn manager");
    let mut burn_manager = BurnManager::new(mpc_core.clone(), burn_db_path)?;

    // Step 6: Create a burn proof
    println!("Step 6: Creating burn proof");
    let burn_txid = "burn-tx-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    let bitcoin_address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq";
    let burn_amount = 50_000_000; // 0.5 BTC
    let fee = 1_000; // 1000 satoshis

    let burn_proof = burn_manager.create_burn_proof(
        burn_txid.to_string(),
        bitcoin_address.to_string(),
        burn_amount,
        fee,
    )?;
    println!("Created burn proof: {}", burn_proof.id);

    // Step 7: Process the burn proof
    println!("Step 7: Processing the burn proof");
    burn_manager.update_burn_proof_status(
        &burn_proof.id,
        wire_lib::mpc::burn::BurnProofStatus::Processing,
    )?;

    let tx_data = format!(
        "{{\"address\":\"{}\",\"amount\":{},\"fee\":{}}}",
        burn_proof.bitcoin_address, burn_proof.amount, burn_proof.fee
    );

    let mut signing_ceremony = SigningCeremony::new(
        format!("sign-withdrawal-{}", burn_proof.id),
        tx_data.as_bytes().to_vec(),
        mpc_core.clone(),
    )?;

    signing_ceremony.start()?;
    signing_ceremony.complete()?;

    let signature = signing_ceremony.get_signature()?;

    // Step 8: Complete the burn proof
    println!("Step 8: Completing the burn proof");
    let withdrawal_txid = "btc-tx-1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    burn_manager.set_withdrawal_txid(&burn_proof.id, withdrawal_txid.to_string())?;

    let completed_burn = burn_manager.get_burn_proof(&burn_proof.id)?;
    assert_eq!(
        completed_burn.status,
        wire_lib::mpc::burn::BurnProofStatus::Completed
    );
    println!("Burn proof completed successfully");

    // Step 9: Create fee manager for fee consolidation
    println!("Step 9: Creating fee manager");
    let fee_db_path = temp_dir
        .path()
        .join("fees.json")
        .to_str()
        .unwrap()
        .to_string();
    let mut fee_manager = FeeManager::new(
        mpc_core.clone(),
        fee_db_path,
        [2u8; 32], // Fee reservoir address
        100_000,   // Minimum consolidation amount
        5,         // Maximum UTXOs per consolidation
    )?;

    // Step 10: Add some fee UTXOs
    println!("Step 10: Adding fee UTXOs");
    for i in 0..5 {
        let utxo = FeeUTXO {
            id: format!("lifecycle-utxo-{}", i),
            owner_pubkey_hash: [2u8; 32], // Same as fee reservoir address
            asset_id: [0u8; 32],
            amount: 30_000, // 0.0003 BTC
            salt: [i as u8; 32],
            txid: format!("fee-tx-{}", i),
            timestamp: 1715200000 + i as u64,
            status: FeeUTXOStatus::Available,
        };

        fee_manager.add_utxo(utxo)?;
    }

    // Step 11: Create a fee consolidation
    println!("Step 11: Creating fee consolidation");
    let consolidation = fee_manager.create_consolidation([3u8; 32])?;
    println!("Created consolidation: {}", consolidation.id);

    // Step 12: Generate a consolidation proof
    println!("Step 12: Generating consolidation proof");
    let proof = fee_manager.generate_consolidation_proof(&consolidation.id)?;

    // Step 13: Complete the consolidation
    println!("Step 13: Completing the consolidation");
    fee_manager.complete_consolidation(&consolidation.id)?;

    let completed_consolidation = fee_manager.get_consolidation(&consolidation.id).unwrap();
    assert_eq!(
        completed_consolidation.status,
        FeeConsolidationStatus::Completed
    );
    println!("Fee consolidation completed successfully");

    println!("Full lifecycle test completed successfully");

    Ok(())
}
