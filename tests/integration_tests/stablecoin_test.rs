// Integration tests for the Stablecoin feature
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

use wire::circuits::stablecoin_mint::StablecoinMintCircuit;
use wire::circuits::stablecoin_redeem::StablecoinRedeemCircuit;
use wire::mpc::stablecoin::{StablecoinMPC, PriceAttestation, RedeemAttestation};
use wire::core::proof::SerializableProof;

/// Test the full stablecoin mint flow
#[test]
fn test_stablecoin_mint_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Initialize the Stablecoin MPC
    let price_attestations_dir = temp_path.join("price_attestations");
    let redeem_requests_dir = temp_path.join("redeem_requests");
    let redeem_attestations_dir = temp_path.join("redeem_attestations");
    
    fs::create_dir_all(&price_attestations_dir).unwrap();
    fs::create_dir_all(&redeem_requests_dir).unwrap();
    fs::create_dir_all(&redeem_attestations_dir).unwrap();
    
    let mpc = StablecoinMPC::new(
        price_attestations_dir.to_str().unwrap(),
        redeem_requests_dir.to_str().unwrap(),
        redeem_attestations_dir.to_str().unwrap(),
    );
    
    // Step 1: Generate a price attestation
    let price_attestation = mpc.generate_price_attestation().unwrap();
    
    let price_attestation_path = temp_path.join("price_attestation.json");
    let mut file = File::create(&price_attestation_path).unwrap();
    let price_attestation_json = serde_json::to_string_pretty(&price_attestation).unwrap();
    file.write_all(price_attestation_json.as_bytes()).unwrap();
    
    // Create a mock wBTC UTXO
    let input_utxo_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let input_utxo_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let input_utxo_asset_id = 1; // WBTC_ASSET_ID
    let input_utxo_amount = 1000000; // 1.0 wBTC
    let input_utxo_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];
    
    // Step 2: Generate a mint proof
    // Current timestamp and time window
    let current_timestamp = price_attestation.timestamp + 100; // 100 seconds later
    let time_window = 3600; // 1 hour
    
    // Overcollateralization ratio (150%)
    let overcollateralization_ratio = 1500000; // 1.5 with 6 decimal places
    
    // zUSD amount to mint
    let zusd_amount = 20000000000; // $20,000 with 6 decimal places
    
    // MPC public key
    let mpc_pk_x = 123456789;
    let mpc_pk_y = 987654321;
    
    // User public key and signature
    let user_pk_x = 111111111;
    let user_pk_y = 222222222;
    let user_signature_r_x = 333333333;
    let user_signature_r_y = 444444444;
    let user_signature_s = 555555555;
    
    let proof_result = StablecoinMintCircuit::generate_proof(
        &input_utxo_commitment,
        &input_utxo_nullifier,
        input_utxo_asset_id,
        input_utxo_amount,
        &input_utxo_owner,
        price_attestation.timestamp,
        price_attestation.btc_usd_price,
        current_timestamp,
        time_window,
        overcollateralization_ratio,
        zusd_amount,
        mpc_pk_x,
        mpc_pk_y,
        price_attestation.signature.0,
        price_attestation.signature.1,
        price_attestation.signature.2,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    ).unwrap();
    
    let proof_path = temp_path.join("mint_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();
    
    // Step 3: Verify the mint proof
    let verify_result = StablecoinMintCircuit::verify_proof(&proof_result);
    assert!(verify_result.is_ok(), "Mint proof verification failed: {:?}", verify_result.err());
    
    // Calculate the required wBTC collateral
    let zusd_with_ratio = zusd_amount * overcollateralization_ratio;
    let required_wbtc = zusd_with_ratio / price_attestation.btc_usd_price / 1_000_000;
    
    // Check that the required collateral is not more than the input amount
    assert!(required_wbtc <= input_utxo_amount, 
        "Required collateral {} is more than input amount {}", 
        required_wbtc, input_utxo_amount);
}

/// Test the full stablecoin redeem flow
#[test]
fn test_stablecoin_redeem_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Initialize the Stablecoin MPC
    let price_attestations_dir = temp_path.join("price_attestations");
    let redeem_requests_dir = temp_path.join("redeem_requests");
    let redeem_attestations_dir = temp_path.join("redeem_attestations");
    
    fs::create_dir_all(&price_attestations_dir).unwrap();
    fs::create_dir_all(&redeem_requests_dir).unwrap();
    fs::create_dir_all(&redeem_attestations_dir).unwrap();
    
    let mpc = StablecoinMPC::new(
        price_attestations_dir.to_str().unwrap(),
        redeem_requests_dir.to_str().unwrap(),
        redeem_attestations_dir.to_str().unwrap(),
    );
    
    // Step 1: Generate a price attestation
    let price_attestation = mpc.generate_price_attestation().unwrap();
    
    let price_attestation_path = temp_path.join("price_attestation.json");
    let mut file = File::create(&price_attestation_path).unwrap();
    let price_attestation_json = serde_json::to_string_pretty(&price_attestation).unwrap();
    file.write_all(price_attestation_json.as_bytes()).unwrap();
    
    // Step 2: Submit a redeem request
    let user_pkh = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let zusd_amount = 20000000000; // $20,000 with 6 decimal places
    
    let redeem_request = mpc.submit_redeem_request(&user_pkh, zusd_amount).unwrap();
    
    let redeem_request_path = temp_path.join("redeem_request.json");
    let mut file = File::create(&redeem_request_path).unwrap();
    let redeem_request_json = serde_json::to_string_pretty(&redeem_request).unwrap();
    file.write_all(redeem_request_json.as_bytes()).unwrap();
    
    // Step 3: Process the redeem request
    let redeem_attestation = mpc.process_redeem_request(redeem_request_path.to_str().unwrap()).unwrap();
    
    let redeem_attestation_path = temp_path.join("redeem_attestation.json");
    let mut file = File::create(&redeem_attestation_path).unwrap();
    let redeem_attestation_json = serde_json::to_string_pretty(&redeem_attestation).unwrap();
    file.write_all(redeem_attestation_json.as_bytes()).unwrap();
    
    // Create a mock zUSD UTXO
    let input_utxo_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let input_utxo_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let input_utxo_asset_id = 2; // ZUSD_ASSET_ID
    let input_utxo_amount = zusd_amount;
    let input_utxo_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];
    
    // Step 4: Generate a redeem proof
    // Current timestamp and time window
    let current_timestamp = redeem_attestation.timestamp + 100; // 100 seconds later
    let time_window = 3600; // 1 hour
    
    // MPC public key
    let mpc_pk_x = 123456789;
    let mpc_pk_y = 987654321;
    
    // User public key and signature
    let user_pk_x = 111111111;
    let user_pk_y = 222222222;
    let user_signature_r_x = 333333333;
    let user_signature_r_y = 444444444;
    let user_signature_s = 555555555;
    
    let proof_result = StablecoinRedeemCircuit::generate_proof(
        &input_utxo_commitment,
        &input_utxo_nullifier,
        input_utxo_asset_id,
        input_utxo_amount,
        &input_utxo_owner,
        price_attestation.timestamp,
        price_attestation.btc_usd_price,
        &user_pkh,
        zusd_amount,
        redeem_attestation.timestamp,
        current_timestamp,
        time_window,
        mpc_pk_x,
        mpc_pk_y,
        price_attestation.signature.0,
        price_attestation.signature.1,
        price_attestation.signature.2,
        redeem_attestation.signature.0,
        redeem_attestation.signature.1,
        redeem_attestation.signature.2,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    ).unwrap();
    
    let proof_path = temp_path.join("redeem_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();
    
    // Step 5: Verify the redeem proof
    let verify_result = StablecoinRedeemCircuit::verify_proof(&proof_result);
    assert!(verify_result.is_ok(), "Redeem proof verification failed: {:?}", verify_result.err());
    
    // Calculate the expected wBTC amount
    let wbtc_amount_scaled = zusd_amount * 1_000_000;
    let wbtc_amount = wbtc_amount_scaled / price_attestation.btc_usd_price;
    
    // Check that the wBTC amount is reasonable
    assert!(wbtc_amount > 0, "wBTC amount should be greater than 0");
}

/// Test the CLI commands for stablecoin operations
#[test]
fn test_stablecoin_cli_commands() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();
    
    // Step 1: Generate a price attestation using the CLI
    let price_attestation_path = temp_path.join("price_attestation.json");
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "generate-price-attestation",
            "--output",
            price_attestation_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(price_attestation_path.exists());
    
    // Step 2: Get the latest price attestation using the CLI
    let latest_price_attestation_path = temp_path.join("latest_price_attestation.json");
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "get-latest-price-attestation",
            "--output",
            latest_price_attestation_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(latest_price_attestation_path.exists());
    
    // Step 3: Create a mock wBTC UTXO
    let utxo_path = temp_path.join("utxo.json");
    
    let utxo = serde_json::json!({
        "commitment": "0123456789abcdef",
        "nullifier": "fedcba9876543210",
        "asset_id": 1, // WBTC_ASSET_ID
        "amount": 1000000, // 1.0 wBTC
        "owner": "9876543210abcdef"
    });
    
    let mut file = File::create(&utxo_path).unwrap();
    let utxo_json = serde_json::to_string_pretty(&utxo).unwrap();
    file.write_all(utxo_json.as_bytes()).unwrap();
    
    // Step 4: Mint zUSD using the CLI
    let mint_result_path = temp_path.join("mint_result.json");
    let zusd_amount = 20000000000; // $20,000 with 6 decimal places
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "mint-zusd",
            "--input-utxo",
            utxo_path.to_str().unwrap(),
            "--price-attestation",
            latest_price_attestation_path.to_str().unwrap(),
            "--zusd-amount",
            &zusd_amount.to_string(),
            "--output",
            mint_result_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(mint_result_path.exists());
    
    // Step 5: Submit a redeem request using the CLI
    let user_pkh = "0123456789abcdef"; // Hex-encoded public key hash
    let redeem_request_path = temp_path.join("redeem_request.json");
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "submit-redeem-request",
            "--user-pkh",
            user_pkh,
            "--zusd-amount",
            &zusd_amount.to_string(),
            "--output",
            redeem_request_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(redeem_request_path.exists());
    
    // Step 6: List redeem requests using the CLI
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "list-redeem-requests",
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    
    // Step 7: Process a redeem request using the CLI
    let redeem_attestation_path = temp_path.join("redeem_attestation.json");
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "process-redeem-request",
            "--request-file",
            redeem_request_path.to_str().unwrap(),
            "--output",
            redeem_attestation_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(redeem_attestation_path.exists());
    
    // Step 8: Create a mock zUSD UTXO
    let zusd_utxo_path = temp_path.join("zusd_utxo.json");
    
    let zusd_utxo = serde_json::json!({
        "commitment": "0123456789abcdef",
        "nullifier": "fedcba9876543210",
        "asset_id": 2, // ZUSD_ASSET_ID
        "amount": zusd_amount,
        "owner": "9876543210abcdef"
    });
    
    let mut file = File::create(&zusd_utxo_path).unwrap();
    let zusd_utxo_json = serde_json::to_string_pretty(&zusd_utxo).unwrap();
    file.write_all(zusd_utxo_json.as_bytes()).unwrap();
    
    // Step 9: Redeem zUSD using the CLI
    let redeem_result_path = temp_path.join("redeem_result.json");
    
    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "stablecoin",
            "redeem-zusd",
            "--input-utxo",
            zusd_utxo_path.to_str().unwrap(),
            "--price-attestation",
            latest_price_attestation_path.to_str().unwrap(),
            "--redeem-attestation",
            redeem_attestation_path.to_str().unwrap(),
            "--output",
            redeem_result_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");
    
    assert!(status.success());
    assert!(redeem_result_path.exists());
}
