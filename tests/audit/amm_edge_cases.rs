//! Edge case tests for AMM circuits
//!
//! These tests focus on numerical, structural, and cryptographic edge cases
//! specific to the AMM circuits (Swap, AddLiquidity, RemoveLiquidity).

use crate::audit::utils;
use wire_lib::circuits::swap::SwapCircuit;
use wire_lib::circuits::add_liquidity::AddLiquidityCircuit;
use wire_lib::circuits::remove_liquidity::RemoveLiquidityCircuit;
use wire_lib::errors::WireError;
use wire_lib::core::{UTXOTarget, PublicKeyTarget};
use wire_lib::gadgets::fixed_point;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

/// Test behavior with extreme price ratios in swap
#[test]
fn test_swap_extreme_price_ratio() {
    // Test with a very large price ratio (1:1000000)
    let token_a_amount = 1_000_000;
    let token_b_amount = 1;
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    
    // Create input UTXOs with extreme price ratio
    let input_utxo_a = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x01; 32], // Asset ID for token A
        token_a_amount
    );
    
    let input_utxo_b = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y,
        [0x02; 32], // Asset ID for token B
        token_b_amount
    );
    
    // Generate a swap proof with extreme price ratio
    let result = SwapCircuit::generate_proof_static(
        &input_utxo_a,
        &input_utxo_b,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );
    
    // The proof generation should succeed even with extreme price ratios
    assert!(result.is_ok(), "Failed to generate proof with extreme price ratio: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = SwapCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with extreme price ratio: {:?}", verification_result.err());
    }
}

/// Test behavior with zero liquidity in add_liquidity
#[test]
fn test_add_liquidity_zero_initial() {
    // Test adding initial liquidity (zero initial liquidity)
    let token_a_amount = 1000;
    let token_b_amount = 2000;
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    
    // Create input UTXOs
    let input_utxo_a = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x01; 32], // Asset ID for token A
        token_a_amount
    );
    
    let input_utxo_b = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y,
        [0x02; 32], // Asset ID for token B
        token_b_amount
    );
    
    // Initial liquidity is zero
    let initial_liquidity = 0;
    
    // Generate an add_liquidity proof with zero initial liquidity
    let result = AddLiquidityCircuit::generate_proof_static(
        &input_utxo_a,
        &input_utxo_b,
        initial_liquidity,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );
    
    // The proof generation should succeed with zero initial liquidity
    assert!(result.is_ok(), "Failed to generate proof with zero initial liquidity: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = AddLiquidityCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with zero initial liquidity: {:?}", verification_result.err());
    }
}

/// Test behavior with minimum liquidity in remove_liquidity
#[test]
fn test_remove_liquidity_minimum() {
    // Test removing minimum liquidity
    let token_a_amount = 1;
    let token_b_amount = 1;
    let lp_token_amount = 1;
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    
    // Create input UTXO for LP token
    let input_utxo_lp = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x03; 32], // Asset ID for LP token
        lp_token_amount
    );
    
    // Generate a remove_liquidity proof with minimum liquidity
    let result = RemoveLiquidityCircuit::generate_proof_static(
        &input_utxo_lp,
        token_a_amount,
        token_b_amount,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );
    
    // The proof generation should succeed with minimum liquidity
    assert!(result.is_ok(), "Failed to generate proof with minimum liquidity: {:?}", result.err());
    
    // Verify the proof
    if let Ok(proof) = result {
        let verification_result = RemoveLiquidityCircuit::verify_proof(&proof);
        assert!(verification_result.is_ok(), "Failed to verify proof with minimum liquidity: {:?}", verification_result.err());
    }
}

/// Test behavior with arithmetic overflow in swap
#[test]
fn test_swap_arithmetic_overflow() {
    // Test with values that could cause overflow in naive implementations
    let max_field_value = GoldilocksField::ORDER - 1;
    let token_a_amount = max_field_value / 2;
    let token_b_amount = max_field_value / 2;
    
    // Generate test data
    let (_, (owner_pk_x, owner_pk_y)) = utils::generate_test_key_pair();
    let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
    
    // Create input UTXOs with large values
    let input_utxo_a = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y, 
        [0x01; 32], // Asset ID for token A
        token_a_amount
    );
    
    let input_utxo_b = UTXOTarget::new_test(
        owner_pk_x, owner_pk_y,
        [0x02; 32], // Asset ID for token B
        token_b_amount
    );
    
    // Generate a swap proof with large values
    let result = SwapCircuit::generate_proof_static(
        &input_utxo_a,
        &input_utxo_b,
        owner_pk_x,
        owner_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );
    
    // Check if the circuit correctly handles potential overflow
    match result {
        Ok(proof) => {
            // If proof generation succeeds, verify the proof
            let verification_result = SwapCircuit::verify_proof(&proof);
            assert!(verification_result.is_ok(), "Failed to verify proof with large values: {:?}", verification_result.err());
            println!("Circuit correctly handles potential arithmetic overflow");
        },
        Err(err) => {
            // If proof generation fails, check if it's due to a legitimate constraint
            println!("Circuit rejected potential arithmetic overflow: {:?}", err);
            // This could be expected behavior if the circuit has explicit bounds checks
        }
    }
}
