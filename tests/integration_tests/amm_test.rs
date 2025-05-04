// Integration tests for the AMM feature
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;

use wire::circuits::add_liquidity::AddLiquidityCircuit;
use wire::circuits::pool_state::PoolStateTarget;
use wire::circuits::remove_liquidity::RemoveLiquidityCircuit;
use wire::circuits::swap::SwapCircuit;
use wire::core::proof::SerializableProof;

/// Test the full AMM swap flow
#[test]
fn test_amm_swap_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Create a mock input UTXO
    let input_utxo_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let input_utxo_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let input_utxo_asset_id = 1; // Token A
    let input_utxo_amount = 1000000; // 1.0 tokens
    let input_utxo_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];

    // Create a mock pool state
    let pool_commitment = vec![10, 11, 12, 13, 14, 15, 16, 17];
    let pool_nullifier = vec![17, 16, 15, 14, 13, 12, 11, 10];
    let token_a_id = 1;
    let token_b_id = 2;
    let token_a_reserve = 10000000; // 10.0 tokens
    let token_b_reserve = 20000000; // 20.0 tokens
    let lp_token_supply = 14142135; // sqrt(10*20) * 10^6

    // Swap parameters
    let output_asset_id = 2; // Token B
    let min_output_amount = 1800000; // 1.8 tokens

    // User keys and signature
    let user_pk_x = 123456789;
    let user_pk_y = 987654321;
    let user_signature_r_x = 111111111;
    let user_signature_r_y = 222222222;
    let user_signature_s = 333333333;

    // Step 1: Generate a swap proof
    let proof_result = SwapCircuit::generate_proof(
        &input_utxo_commitment,
        &input_utxo_nullifier,
        input_utxo_asset_id,
        input_utxo_amount,
        &input_utxo_owner,
        &pool_commitment,
        &pool_nullifier,
        token_a_id,
        token_b_id,
        token_a_reserve,
        token_b_reserve,
        lp_token_supply,
        output_asset_id,
        min_output_amount,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    )
    .unwrap();

    let proof_path = temp_path.join("swap_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();

    // Step 2: Verify the swap proof
    let verify_result = SwapCircuit::verify_proof(&proof_result);
    assert!(
        verify_result.is_ok(),
        "Swap proof verification failed: {:?}",
        verify_result.err()
    );

    // Calculate the expected output amount using the CPMM formula
    // output_amount = (token_b_reserve * input_amount) / (token_a_reserve + input_amount)
    let numerator = token_b_reserve * input_utxo_amount;
    let denominator = token_a_reserve + input_utxo_amount;
    let expected_output_amount = numerator / denominator;

    // Check that the output amount is at least the minimum
    assert!(
        expected_output_amount >= min_output_amount,
        "Expected output amount {} is less than minimum {}",
        expected_output_amount,
        min_output_amount
    );
}

/// Test the full AMM add liquidity flow
#[test]
fn test_amm_add_liquidity_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Create mock input UTXOs
    let input_utxo_a_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let input_utxo_a_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let input_utxo_a_asset_id = 1; // Token A
    let input_utxo_a_amount = 1000000; // 1.0 tokens
    let input_utxo_a_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];

    let input_utxo_b_commitment = vec![21, 22, 23, 24, 25, 26, 27, 28];
    let input_utxo_b_nullifier = vec![28, 27, 26, 25, 24, 23, 22, 21];
    let input_utxo_b_asset_id = 2; // Token B
    let input_utxo_b_amount = 2000000; // 2.0 tokens
    let input_utxo_b_owner = vec![9, 8, 7, 6, 5, 4, 3, 2]; // Same owner

    // Create a mock pool state
    let pool_commitment = vec![10, 11, 12, 13, 14, 15, 16, 17];
    let pool_nullifier = vec![17, 16, 15, 14, 13, 12, 11, 10];
    let token_a_id = 1;
    let token_b_id = 2;
    let token_a_reserve = 10000000; // 10.0 tokens
    let token_b_reserve = 20000000; // 20.0 tokens
    let lp_token_supply = 14142135; // sqrt(10*20) * 10^6

    // Add liquidity parameters
    let min_lp_tokens = 1400000; // 1.4 LP tokens

    // User keys and signature
    let user_pk_x = 123456789;
    let user_pk_y = 987654321;
    let user_signature_r_x = 111111111;
    let user_signature_r_y = 222222222;
    let user_signature_s = 333333333;

    // Step 1: Generate an add liquidity proof
    let proof_result = AddLiquidityCircuit::generate_proof(
        &input_utxo_a_commitment,
        &input_utxo_a_nullifier,
        input_utxo_a_asset_id,
        input_utxo_a_amount,
        &input_utxo_a_owner,
        &input_utxo_b_commitment,
        &input_utxo_b_nullifier,
        input_utxo_b_asset_id,
        input_utxo_b_amount,
        &input_utxo_b_owner,
        &pool_commitment,
        &pool_nullifier,
        token_a_id,
        token_b_id,
        token_a_reserve,
        token_b_reserve,
        lp_token_supply,
        min_lp_tokens,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    )
    .unwrap();

    let proof_path = temp_path.join("add_liquidity_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();

    // Step 2: Verify the add liquidity proof
    let verify_result = AddLiquidityCircuit::verify_proof(&proof_result);
    assert!(
        verify_result.is_ok(),
        "Add liquidity proof verification failed: {:?}",
        verify_result.err()
    );

    // Calculate the expected LP tokens using the formula
    // lp_tokens = min(input_a_amount * lp_token_supply / token_a_reserve, input_b_amount * lp_token_supply / token_b_reserve)
    let lp_tokens_a = input_utxo_a_amount * lp_token_supply / token_a_reserve;
    let lp_tokens_b = input_utxo_b_amount * lp_token_supply / token_b_reserve;
    let expected_lp_tokens = std::cmp::min(lp_tokens_a, lp_tokens_b);

    // Check that the LP tokens are at least the minimum
    assert!(
        expected_lp_tokens >= min_lp_tokens,
        "Expected LP tokens {} is less than minimum {}",
        expected_lp_tokens,
        min_lp_tokens
    );
}

/// Test the full AMM remove liquidity flow
#[test]
fn test_amm_remove_liquidity_flow() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Create a mock LP share UTXO
    let lp_share_commitment = vec![1, 2, 3, 4, 5, 6, 7, 8];
    let lp_share_nullifier = vec![8, 7, 6, 5, 4, 3, 2, 1];
    let lp_share_amount = 1000000; // 1.0 LP tokens
    let lp_share_owner = vec![9, 8, 7, 6, 5, 4, 3, 2];

    // Create a mock pool state
    let pool_commitment = vec![10, 11, 12, 13, 14, 15, 16, 17];
    let pool_nullifier = vec![17, 16, 15, 14, 13, 12, 11, 10];
    let token_a_id = 1;
    let token_b_id = 2;
    let token_a_reserve = 10000000; // 10.0 tokens
    let token_b_reserve = 20000000; // 20.0 tokens
    let lp_token_supply = 14142135; // sqrt(10*20) * 10^6

    // Remove liquidity parameters
    let min_amount_a = 700000; // 0.7 tokens A
    let min_amount_b = 1400000; // 1.4 tokens B

    // User keys and signature
    let user_pk_x = 123456789;
    let user_pk_y = 987654321;
    let user_signature_r_x = 111111111;
    let user_signature_r_y = 222222222;
    let user_signature_s = 333333333;

    // Step 1: Generate a remove liquidity proof
    let proof_result = RemoveLiquidityCircuit::generate_proof(
        &lp_share_commitment,
        &lp_share_nullifier,
        lp_share_amount,
        &lp_share_owner,
        &pool_commitment,
        &pool_nullifier,
        token_a_id,
        token_b_id,
        token_a_reserve,
        token_b_reserve,
        lp_token_supply,
        min_amount_a,
        min_amount_b,
        user_pk_x,
        user_pk_y,
        user_signature_r_x,
        user_signature_r_y,
        user_signature_s,
    )
    .unwrap();

    let proof_path = temp_path.join("remove_liquidity_proof.json");
    let mut file = File::create(&proof_path).unwrap();
    let proof_json = serde_json::to_string_pretty(&proof_result).unwrap();
    file.write_all(proof_json.as_bytes()).unwrap();

    // Step 2: Verify the remove liquidity proof
    let verify_result = RemoveLiquidityCircuit::verify_proof(&proof_result);
    assert!(
        verify_result.is_ok(),
        "Remove liquidity proof verification failed: {:?}",
        verify_result.err()
    );

    // Calculate the expected token amounts using the formula
    // amount_a = lp_share_amount * token_a_reserve / lp_token_supply
    // amount_b = lp_share_amount * token_b_reserve / lp_token_supply
    let expected_amount_a = lp_share_amount * token_a_reserve / lp_token_supply;
    let expected_amount_b = lp_share_amount * token_b_reserve / lp_token_supply;

    // Check that the token amounts are at least the minimum
    assert!(
        expected_amount_a >= min_amount_a,
        "Expected amount A {} is less than minimum {}",
        expected_amount_a,
        min_amount_a
    );
    assert!(
        expected_amount_b >= min_amount_b,
        "Expected amount B {} is less than minimum {}",
        expected_amount_b,
        min_amount_b
    );
}

/// Test the CLI commands for AMM operations
#[test]
fn test_amm_cli_commands() {
    // Create a temporary directory for test files
    let temp_dir = tempdir().unwrap();
    let temp_path = temp_dir.path();

    // Step 1: Create a pool using the CLI
    let pool_path = temp_path.join("pool.json");
    let token_a = "0000000000000001"; // Token A ID
    let token_b = "0000000000000002"; // Token B ID

    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "amm",
            "create-pool",
            "--token-a",
            token_a,
            "--token-b",
            token_b,
            "--output",
            pool_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");

    assert!(status.success());
    assert!(pool_path.exists());

    // Step 2: Create mock UTXOs for swapping and adding liquidity
    let utxo_a_path = temp_path.join("utxo_a.json");
    let utxo_a = serde_json::json!({
        "commitment": "0123456789abcdef",
        "nullifier": "fedcba9876543210",
        "asset_id": 1,
        "amount": 1000000,
        "owner": "9876543210abcdef"
    });

    let mut file = File::create(&utxo_a_path).unwrap();
    let utxo_a_json = serde_json::to_string_pretty(&utxo_a).unwrap();
    file.write_all(utxo_a_json.as_bytes()).unwrap();

    let utxo_b_path = temp_path.join("utxo_b.json");
    let utxo_b = serde_json::json!({
        "commitment": "0123456789abcdef",
        "nullifier": "fedcba9876543210",
        "asset_id": 2,
        "amount": 2000000,
        "owner": "9876543210abcdef"
    });

    let mut file = File::create(&utxo_b_path).unwrap();
    let utxo_b_json = serde_json::to_string_pretty(&utxo_b).unwrap();
    file.write_all(utxo_b_json.as_bytes()).unwrap();

    // Step 3: Swap tokens using the CLI
    let swap_output_path = temp_path.join("swap_result.json");

    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "amm",
            "swap",
            "--input-utxo",
            utxo_a_path.to_str().unwrap(),
            "--pool-state",
            pool_path.to_str().unwrap(),
            "--output-asset-id",
            "0000000000000002",
            "--min-output-amount",
            "1800000",
            "--output",
            swap_output_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");

    assert!(status.success());
    assert!(swap_output_path.exists());

    // Step 4: Add liquidity using the CLI
    let add_liquidity_output_path = temp_path.join("add_liquidity_result.json");

    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "amm",
            "add-liquidity",
            "--input-utxo-a",
            utxo_a_path.to_str().unwrap(),
            "--input-utxo-b",
            utxo_b_path.to_str().unwrap(),
            "--pool-state",
            pool_path.to_str().unwrap(),
            "--min-lp-tokens",
            "1400000",
            "--output",
            add_liquidity_output_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");

    assert!(status.success());
    assert!(add_liquidity_output_path.exists());

    // Step 5: Create a mock LP share UTXO
    let lp_share_path = temp_path.join("lp_share.json");
    let lp_share = serde_json::json!({
        "commitment": "0123456789abcdef",
        "nullifier": "fedcba9876543210",
        "asset_id": 3, // LP token ID
        "amount": 1000000,
        "owner": "9876543210abcdef"
    });

    let mut file = File::create(&lp_share_path).unwrap();
    let lp_share_json = serde_json::to_string_pretty(&lp_share).unwrap();
    file.write_all(lp_share_json.as_bytes()).unwrap();

    // Step 6: Remove liquidity using the CLI
    let remove_liquidity_output_path = temp_path.join("remove_liquidity_result.json");

    let status = Command::new("cargo")
        .args([
            "run",
            "--",
            "amm",
            "remove-liquidity",
            "--lp-share",
            lp_share_path.to_str().unwrap(),
            "--pool-state",
            pool_path.to_str().unwrap(),
            "--min-amount-a",
            "700000",
            "--min-amount-b",
            "1400000",
            "--output",
            remove_liquidity_output_path.to_str().unwrap(),
        ])
        .status()
        .expect("Failed to execute command");

    assert!(status.success());
    assert!(remove_liquidity_output_path.exists());
}
