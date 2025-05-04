//! Edge case tests for Stablecoin circuits
//!
//! These tests focus on numerical, structural, and cryptographic edge cases
//! specific to the Stablecoin circuits (StablecoinMint, StablecoinRedeem).

use crate::audit::utils;
use wire_lib::circuits::stablecoin_mint::StablecoinMintCircuit;
use wire_lib::circuits::stablecoin_redeem::StablecoinRedeemCircuit;
use wire_lib::errors::WireError;
use wire_lib::core::{UTXOTarget, PublicKeyTarget, CollateralUTXOTarget, CollateralMetadataTarget};
use wire_lib::gadgets::fixed_point;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

/// Test behavior with minimum collateralization ratio
#[test]
fn test_mint_minimum_collateralization() {
    // Test with the minimum allowed collateralization ratio (150%)
    let collateral_amount = 150;
    let zusd_amount = 100;
    let price = 1; // 1:1 price ratio for simplicity
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (_, (mpc_pk_x, mpc_pk_y)) = utils::generate_test_key_pair(); // MPC committee key
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let (price_sig_r_x, price_sig_r_y, price_sig_s) = utils::generate_test_signature();
    
    // Create input UTXO for collateral
    let input_utxo = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x01; 32], // Asset ID for wBTC
        collateral_amount
    );
    
    // Create collateral metadata
    let collateral_metadata = CollateralMetadataTarget {
        issuance_id: 1,
        lock_timestamp: 12345,
        timelock_period: 86400, // 1 day in seconds
        lock_price: price,
        collateral_ratio: 150, // Minimum ratio
    };
    
    // Generate a mint proof with minimum collateralization
    let result = StablecoinMintCircuit::generate_proof_static(
        &input_utxo,
        zusd_amount,
        price,
        mpc_pk_x,
        mpc_pk_y,
        &collateral_metadata,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        price_sig_r_x,
        price_sig_r_y,
        price_sig_s,
    );
    
    // The proof generation should succeed with minimum collateralization
    assert!(result.is_ok(), "Failed to generate proof with minimum collateralization: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = StablecoinMintCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with minimum collateralization: {:?}", verification_result.err());
    }
}

/// Test behavior with below minimum collateralization ratio (should fail)
#[test]
fn test_mint_below_minimum_collateralization() {
    // Test with below the minimum allowed collateralization ratio (149%)
    let collateral_amount = 149;
    let zusd_amount = 100;
    let price = 1; // 1:1 price ratio for simplicity
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (_, (mpc_pk_x, mpc_pk_y)) = utils::generate_test_key_pair(); // MPC committee key
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let (price_sig_r_x, price_sig_r_y, price_sig_s) = utils::generate_test_signature();
    
    // Create input UTXO for collateral
    let input_utxo = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x01; 32], // Asset ID for wBTC
        collateral_amount
    );
    
    // Create collateral metadata
    let collateral_metadata = CollateralMetadataTarget {
        issuance_id: 1,
        lock_timestamp: 12345,
        timelock_period: 86400, // 1 day in seconds
        lock_price: price,
        collateral_ratio: 149, // Below minimum ratio
    };
    
    // Generate a mint proof with below minimum collateralization
    let result = StablecoinMintCircuit::generate_proof_static(
        &input_utxo,
        zusd_amount,
        price,
        mpc_pk_x,
        mpc_pk_y,
        &collateral_metadata,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        price_sig_r_x,
        price_sig_r_y,
        price_sig_s,
    );
    
    // The proof generation should fail with below minimum collateralization
    assert!(result.is_err(), "Proof generation should fail with below minimum collateralization");
    
    // Check that the error is related to collateralization ratio
    if let Err(err) = result {
        assert!(format!("{:?}", err).contains("collateralization"), 
                "Error should be related to collateralization ratio: {:?}", err);
    }
}

/// Test behavior with timelock expiration in redeem
#[test]
fn test_redeem_timelock_expiration() {
    // Test redeeming with expired timelock
    let collateral_amount = 150;
    let zusd_amount = 100;
    let price = 1; // 1:1 price ratio for simplicity
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (_, (mpc_pk_x, mpc_pk_y)) = utils::generate_test_key_pair(); // MPC committee key
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let (price_sig_r_x, price_sig_r_y, price_sig_s) = utils::generate_test_signature();
    let (redeem_sig_r_x, redeem_sig_r_y, redeem_sig_s) = utils::generate_test_signature();
    
    // Create input UTXO for zUSD
    let input_utxo = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x02; 32], // Asset ID for zUSD
        zusd_amount
    );
    
    // Current timestamp is after lock_timestamp + timelock_period
    let current_timestamp = 12345 + 86400 + 1;
    
    // Create collateral UTXO
    let collateral_metadata = CollateralMetadataTarget {
        issuance_id: 1,
        lock_timestamp: 12345,
        timelock_period: 86400, // 1 day in seconds
        lock_price: price,
        collateral_ratio: 150,
    };
    
    let collateral_utxo = CollateralUTXOTarget::new_test(
        mpc_pk_x, mpc_pk_y, 
        [0x01; 32], // Asset ID for wBTC
        collateral_amount,
        collateral_metadata
    );
    
    // Generate a redeem proof with expired timelock
    let result = StablecoinRedeemCircuit::generate_proof_static(
        &input_utxo,
        &collateral_utxo,
        price,
        current_timestamp,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        price_sig_r_x,
        price_sig_r_y,
        price_sig_s,
        redeem_sig_r_x,
        redeem_sig_r_y,
        redeem_sig_s,
    );
    
    // The proof generation should succeed with expired timelock
    assert!(result.is_ok(), "Failed to generate proof with expired timelock: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = StablecoinRedeemCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with expired timelock: {:?}", verification_result.err());
    }
}

/// Test behavior with unexpired timelock in redeem (should fail)
#[test]
fn test_redeem_unexpired_timelock() {
    // Test redeeming with unexpired timelock
    let collateral_amount = 150;
    let zusd_amount = 100;
    let price = 1; // 1:1 price ratio for simplicity
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (_, (mpc_pk_x, mpc_pk_y)) = utils::generate_test_key_pair(); // MPC committee key
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let (price_sig_r_x, price_sig_r_y, price_sig_s) = utils::generate_test_signature();
    let (redeem_sig_r_x, redeem_sig_r_y, redeem_sig_s) = utils::generate_test_signature();
    
    // Create input UTXO for zUSD
    let input_utxo = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x02; 32], // Asset ID for zUSD
        zusd_amount
    );
    
    // Current timestamp is before lock_timestamp + timelock_period
    let current_timestamp = 12345 + 86400 - 1;
    
    // Create collateral UTXO
    let collateral_metadata = CollateralMetadataTarget {
        issuance_id: 1,
        lock_timestamp: 12345,
        timelock_period: 86400, // 1 day in seconds
        lock_price: price,
        collateral_ratio: 150,
    };
    
    let collateral_utxo = CollateralUTXOTarget::new_test(
        mpc_pk_x, mpc_pk_y, 
        [0x01; 32], // Asset ID for wBTC
        collateral_amount,
        collateral_metadata
    );
    
    // Generate a redeem proof with unexpired timelock
    let result = StablecoinRedeemCircuit::generate_proof_static(
        &input_utxo,
        &collateral_utxo,
        price,
        current_timestamp,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        price_sig_r_x,
        price_sig_r_y,
        price_sig_s,
        redeem_sig_r_x,
        redeem_sig_r_y,
        redeem_sig_s,
    );
    
    // The proof generation should fail with unexpired timelock
    assert!(result.is_err(), "Proof generation should fail with unexpired timelock");
    
    // Check that the error is related to timelock
    if let Err(err) = result {
        assert!(format!("{:?}", err).contains("timelock"), 
                "Error should be related to timelock: {:?}", err);
    }
}

/// Test behavior with price change in redeem
#[test]
fn test_redeem_price_change() {
    // Test redeeming with a price change
    let collateral_amount = 200; // Extra collateral to handle price changes
    let zusd_amount = 100;
    let lock_price = 1; // Original price
    let current_price = 0.8; // 20% price drop
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (_, (mpc_pk_x, mpc_pk_y)) = utils::generate_test_key_pair(); // MPC committee key
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    let (price_sig_r_x, price_sig_r_y, price_sig_s) = utils::generate_test_signature();
    let (redeem_sig_r_x, redeem_sig_r_y, redeem_sig_s) = utils::generate_test_signature();
    
    // Create input UTXO for zUSD
    let input_utxo = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x02; 32], // Asset ID for zUSD
        zusd_amount
    );
    
    // Current timestamp is after lock_timestamp + timelock_period
    let current_timestamp = 12345 + 86400 + 1;
    
    // Create collateral UTXO
    let collateral_metadata = CollateralMetadataTarget {
        issuance_id: 1,
        lock_timestamp: 12345,
        timelock_period: 86400, // 1 day in seconds
        lock_price: lock_price,
        collateral_ratio: 200, // Higher ratio to handle price drop
    };
    
    let collateral_utxo = CollateralUTXOTarget::new_test(
        mpc_pk_x, mpc_pk_y, 
        [0x01; 32], // Asset ID for wBTC
        collateral_amount,
        collateral_metadata
    );
    
    // Generate a redeem proof with price change
    let result = StablecoinRedeemCircuit::generate_proof_static(
        &input_utxo,
        &collateral_utxo,
        current_price,
        current_timestamp,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        price_sig_r_x,
        price_sig_r_y,
        price_sig_s,
        redeem_sig_r_x,
        redeem_sig_r_y,
        redeem_sig_s,
    );
    
    // The proof generation should succeed with price change
    assert!(result.is_ok(), "Failed to generate proof with price change: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = StablecoinRedeemCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with price change: {:?}", verification_result.err());
    }
}
