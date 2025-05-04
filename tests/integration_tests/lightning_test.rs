// Integration tests for the Lightning Network feature
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

use wire::circuits::ln_burn::LNBurnCircuit;
use wire::circuits::ln_mint::LNMintCircuit;
use wire::core::proof::SerializableProof;
use wire::mpc::lightning::LightningMPC;

/// Test the full Lightning Network mint flow
#[test]
fn test_lightning_mint_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Initialize the Lightning MPC
    let invoices_dir = temp_path.join("invoices");
    let payments_dir = temp_path.join("payments");
    let attestations_dir = temp_path.join("attestations");

    fs::create_dir_all(&invoices_dir).unwrap();
    fs::create_dir_all(&payments_dir).unwrap();
    fs::create_dir_all(&attestations_dir).unwrap();

    let mpc = LightningMPC::new(
        invoices_dir.to_str().unwrap(),
        payments_dir.to_str().unwrap(),
        attestations_dir.to_str().unwrap(),
    );

    // Step 1: Generate an invoice
    let amount = 100000; // 0.001 BTC in sats
    let invoice_result = mpc.generate_invoice(amount).unwrap();

    let invoice_path = temp_path.join("invoice.json");
    let mut file = File::create(&invoice_path).unwrap();
    let invoice_json = serde_json::to_string_pretty(&invoice_result).unwrap();
    file.write_all(invoice_json.as_bytes()).unwrap();

    // Step 2: Simulate payment confirmation
    let payment_result = mpc.confirm_payment(&invoice_result.invoice_hash).unwrap();

    let payment_path = temp_path.join("payment.json");
    let mut file = File::create(&payment_path).unwrap();
    let payment_json = serde_json::to_string_pretty(&payment_result).unwrap();
    file.write_all(payment_json.as_bytes()).unwrap();

    // Step 3: Generate a mint attestation
    let attestation_result = mpc
        .generate_mint_attestation(&invoice_result.invoice_hash)
        .unwrap();

    let attestation_path = temp_path.join("attestation.json");
    let mut file = File::create(&attestation_path).unwrap();
    let attestation_json = serde_json::to_string_pretty(&attestation_result).unwrap();
    file.write_all(attestation_json.as_bytes()).unwrap();

    // Step 4: Generate a mint proof
    let user_pk_x = 123456789;
    let user_pk_y = 987654321;

    let proof_result = LNMintCircuit::generate_proof(
        attestation_result.invoice_hash,
        attestation_result.payment_amount,
        attestation_result.timestamp,
        attestation_result.mpc_pk.0,
        attestation_result.mpc_pk.1,
        attestation_result.signature.0,
        attestation_result.signature.1,
        attestation_result.signature.2,
        user_pk_x,
        user_pk_y,
    )
    .unwrap();

    let proof_path = temp_path.join("mint_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();

    // Step 5: Verify the mint proof
    let verify_result = LNMintCircuit::verify_proof(&proof_result);
    assert!(
        verify_result.is_ok(),
        "Mint proof verification failed: {:?}",
        verify_result.err()
    );
}

/// Test the full Lightning Network burn flow
#[test]
fn test_lightning_burn_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Create a mock wBTC UTXO
    let input_utxo_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let input_utxo_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let input_utxo_asset_id = 1; // WBTC_ASSET_ID
    let input_utxo_amount = 100000; // 0.001 BTC in sats
    let input_utxo_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];

    // Step 1: Generate a burn proof
    let ln_address = "ln1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    let withdrawal_amount = 90000; // 0.0009 BTC in sats
    let fee = 10000; // 0.0001 BTC in sats

    let user_pk_x = 123456789;
    let user_pk_y = 987654321;
    let user_signature_r_x = 111111111;
    let user_signature_r_y = 222222222;
    let user_signature_s = 333333333;

    let proof_result = LNBurnCircuit::generate_proof(
        &input_utxo_commitment,
        &input_utxo_nullifier,
        input_utxo_asset_id,
        input_utxo_amount,
        &input_utxo_owner,
        ln_address,
        withdrawal_amount,
        fee,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    )
    .unwrap();

    let proof_path = temp_path.join("burn_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();

    // Step 2: Verify the burn proof
    let verify_result = LNBurnCircuit::verify_proof(&proof_result);
    assert!(
        verify_result.is_ok(),
        "Burn proof verification failed: {:?}",
        verify_result.err()
    );

    // Step 3: Initialize the Lightning MPC
    let invoices_dir = temp_path.join("invoices");
    let payments_dir = temp_path.join("payments");
    let attestations_dir = temp_path.join("attestations");

    fs::create_dir_all(&invoices_dir).unwrap();
    fs::create_dir_all(&payments_dir).unwrap();
    fs::create_dir_all(&attestations_dir).unwrap();

    let mpc = LightningMPC::new(
        invoices_dir.to_str().unwrap(),
        payments_dir.to_str().unwrap(),
        attestations_dir.to_str().unwrap(),
    );

    // Step 4: Process the burn proof
    let process_result = mpc
        .process_burn_proof(&proof_result, ln_address, withdrawal_amount, fee)
        .unwrap();

    let process_path = temp_path.join("burn_process.json");
    let mut file = File::create(&process_path).unwrap();
    let process_json = serde_json::to_string_pretty(&process_result).unwrap();
    file.write_all(process_json.as_bytes()).unwrap();

    // Check that the burn was processed successfully
    assert_eq!(process_result.ln_address, ln_address);
    assert_eq!(process_result.amount, withdrawal_amount);
    assert_eq!(process_result.fee, fee);
    assert!(process_result.status.contains("pending"));
}
