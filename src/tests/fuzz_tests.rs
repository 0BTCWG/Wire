// Fuzz testing module for the 0BTC Wire system
// This module contains fuzz tests for various components of the system
// to ensure robustness against malformed or unexpected inputs.

use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::errors::{WireError, CryptoError, WireResult};
use crate::gadgets::hash;
use crate::gadgets::merkle;
use crate::gadgets::signature;
use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Run all fuzz tests
pub fn run_all_fuzz_tests() -> WireResult<()> {
    println!("Running fuzz tests for hash gadgets...");
    fuzz_test_hash_gadgets(100)?;
    
    println!("Running fuzz tests for Merkle proof verification...");
    fuzz_test_merkle_verification(100)?;
    
    println!("Running fuzz tests for signature verification...");
    fuzz_test_signature_verification(100)?;
    
    println!("All fuzz tests passed!");
    Ok(())
}

/// Fuzz test hash gadgets with various inputs
fn fuzz_test_hash_gadgets(num_tests: usize) -> WireResult<()> {
    let mut rng = StdRng::seed_from_u64(42); // Use a fixed seed for reproducibility
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());
    
    // Test 1: Empty inputs
    let result = hash::hash(&mut builder, &[]);
    assert!(result.is_err(), "Empty input should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::HashError(msg))) = result {
        assert!(msg.contains("Empty input"), "Error message should mention empty input");
    } else {
        panic!("Expected HashError");
    }
    
    // Test 2: Very large inputs
    let mut large_input = Vec::with_capacity(1025);
    for _ in 0..1025 {
        large_input.push(builder.add_virtual_target());
    }
    
    let result = hash::hash(&mut builder, &large_input);
    assert!(result.is_err(), "Large input should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::HashError(msg))) = result {
        assert!(msg.contains("exceeds maximum"), "Error message should mention size limit");
    } else {
        panic!("Expected HashError");
    }
    
    // Test 3: Random valid inputs
    for _ in 0..num_tests {
        let input_size = rng.gen_range(1..100);
        let mut input = Vec::with_capacity(input_size);
        
        for _ in 0..input_size {
            input.push(builder.add_virtual_target());
        }
        
        let domain = if rng.gen_bool(0.5) {
            Some("test_domain")
        } else {
            None
        };
        
        let result = match domain {
            Some(d) => hash::hash_n(&mut builder, &input, d),
            None => hash::hash(&mut builder, &input),
        };
        
        assert!(result.is_ok(), "Valid input should not return an error");
    }
    
    // Test 4: Invalid domain separators
    let input = vec![builder.add_virtual_target()];
    let result = hash::hash_n(&mut builder, &input, "");
    
    assert!(result.is_err(), "Empty domain separator should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::HashError(msg))) = result {
        assert!(msg.contains("domain separator"), "Error message should mention domain separator");
    } else {
        panic!("Expected HashError");
    }
    
    Ok(())
}

/// Fuzz test Merkle proof verification with various inputs
fn fuzz_test_merkle_verification(num_tests: usize) -> WireResult<()> {
    let mut rng = StdRng::seed_from_u64(43); // Use a fixed seed for reproducibility
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());
    
    // Test 1: Empty siblings
    let leaf = builder.add_virtual_target();
    let index = builder.add_virtual_target();
    let root = builder.add_virtual_target();
    let siblings: Vec<Target> = Vec::new();
    
    let result = merkle::verify_merkle_proof(&mut builder, leaf, index, root, &siblings);
    assert!(result.is_err(), "Empty siblings should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::MerkleError(msg))) = result {
        assert!(msg.contains("siblings cannot be empty"), "Error message should mention empty siblings");
    } else {
        panic!("Expected MerkleError");
    }
    
    // Test 2: Excessive tree height
    let mut siblings = Vec::with_capacity(300);
    for _ in 0..300 {
        siblings.push(builder.add_virtual_target());
    }
    
    let result = merkle::verify_merkle_proof(&mut builder, leaf, index, root, &siblings);
    assert!(result.is_err(), "Excessive tree height should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::MerkleError(msg))) = result {
        assert!(msg.contains("exceeds maximum"), "Error message should mention height limit");
    } else {
        panic!("Expected MerkleError");
    }
    
    // Test 3: Random valid inputs
    for _ in 0..num_tests {
        let height = rng.gen_range(1..32);
        let mut siblings = Vec::with_capacity(height);
        
        for _ in 0..height {
            siblings.push(builder.add_virtual_target());
        }
        
        let result = merkle::verify_merkle_proof(&mut builder, leaf, index, root, &siblings);
        assert!(result.is_ok(), "Valid input should not return an error");
    }
    
    // Test 4: Fixed height mismatch
    let expected_height = 10;
    let mut siblings = Vec::with_capacity(8);
    for _ in 0..8 {
        siblings.push(builder.add_virtual_target());
    }
    
    let result = merkle::assert_merkle_proof_fixed_height(
        &mut builder, leaf, index, root, &siblings, expected_height
    );
    
    assert!(result.is_err(), "Height mismatch should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::MerkleError(msg))) = result {
        assert!(msg.contains("mismatch"), "Error message should mention height mismatch");
    } else {
        panic!("Expected MerkleError");
    }
    
    Ok(())
}

/// Fuzz test signature verification with various inputs
fn fuzz_test_signature_verification(num_tests: usize) -> WireResult<()> {
    let mut rng = StdRng::seed_from_u64(44); // Use a fixed seed for reproducibility
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());
    
    // Test 1: Empty message
    let message: Vec<Target> = Vec::new();
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };
    let public_key = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };
    
    let result = signature::verify_message_signature(&mut builder, &message, &signature, &public_key);
    assert!(result.is_err(), "Empty message should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
        assert!(msg.contains("Empty message"), "Error message should mention empty message");
    } else {
        panic!("Expected SignatureError");
    }
    
    // Test 2: Oversized message
    let mut large_message = Vec::with_capacity(1025);
    for _ in 0..1025 {
        large_message.push(builder.add_virtual_target());
    }
    
    let result = signature::verify_message_signature(&mut builder, &large_message, &signature, &public_key);
    assert!(result.is_err(), "Oversized message should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
        assert!(msg.contains("too large"), "Error message should mention size limit");
    } else {
        panic!("Expected SignatureError");
    }
    
    // Test 3: Random valid inputs
    for _ in 0..num_tests {
        let message_size = rng.gen_range(1..100);
        let mut message = Vec::with_capacity(message_size);
        
        for _ in 0..message_size {
            message.push(builder.add_virtual_target());
        }
        
        let result = signature::verify_message_signature(&mut builder, &message, &signature, &public_key);
        assert!(result.is_ok(), "Valid input should not return an error");
    }
    
    // Test 4: Batch verification with mismatched inputs
    let messages = vec![vec![builder.add_virtual_target()]];
    let signatures = vec![signature.clone(), signature.clone()]; // Two signatures
    let public_keys = vec![public_key.clone()]; // But only one public key
    
    let result = signature::batch_verify_signatures(&mut builder, &messages, &signatures, &public_keys);
    assert!(result.is_err(), "Mismatched inputs should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
        assert!(msg.contains("Mismatched number"), "Error message should mention mismatched inputs");
    } else {
        panic!("Expected SignatureError");
    }
    
    // Test 5: Excessive batch size
    let mut messages = Vec::with_capacity(300);
    let mut signatures = Vec::with_capacity(300);
    let mut public_keys = Vec::with_capacity(300);
    
    for _ in 0..300 {
        messages.push(vec![builder.add_virtual_target()]);
        signatures.push(signature.clone());
        public_keys.push(public_key.clone());
    }
    
    let result = signature::batch_verify_signatures(&mut builder, &messages, &signatures, &public_keys);
    assert!(result.is_err(), "Excessive batch size should return an error");
    
    if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
        assert!(msg.contains("Batch size too large"), "Error message should mention batch size limit");
    } else {
        panic!("Expected SignatureError");
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_hash_gadget_fuzz() {
        let result = fuzz_test_hash_gadgets(10);
        assert!(result.is_ok(), "Hash gadget fuzz tests failed");
    }
    
    #[test]
    fn test_merkle_verification_fuzz() {
        let result = fuzz_test_merkle_verification(10);
        assert!(result.is_ok(), "Merkle verification fuzz tests failed");
    }
    
    #[test]
    fn test_signature_verification_fuzz() {
        let result = fuzz_test_signature_verification(10);
        assert!(result.is_ok(), "Signature verification fuzz tests failed");
    }
    
    #[test]
    fn test_all_fuzz_tests() {
        let result = run_all_fuzz_tests();
        assert!(result.is_ok(), "Some fuzz tests failed");
    }
}
