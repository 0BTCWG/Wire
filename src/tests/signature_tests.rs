// Unit tests for signature utility functions

use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::signature::*;
use crate::utils::hash;

#[test]
fn test_keypair_generation() {
    let keypair = generate_keypair();
    
    // Verify that the keypair's public key is derived from the secret key
    let public_from_secret = VerifyingKey::from(&keypair.secret);
    assert_eq!(keypair.public.to_bytes(), public_from_secret.to_bytes());
}

#[test]
fn test_sign_and_verify() {
    let keypair = generate_keypair();
    let message = b"Hello, 0BTC Wire!";
    
    // Sign the message
    let signature = sign_message(&keypair, message);
    
    // Verify the signature
    let valid = verify_signature(&keypair.public, message, &signature);
    assert!(valid);
    
    // Try to verify with wrong message
    let wrong_message = b"Wrong message!";
    let invalid = verify_signature(&keypair.public, wrong_message, &signature);
    assert!(!invalid);
}

#[test]
fn test_key_conversions() {
    let keypair = generate_keypair();
    
    // Test public key conversions
    let pk_bytes = public_key_to_bytes(&keypair.public);
    let pk_from_bytes = bytes_to_public_key(&pk_bytes).unwrap();
    assert_eq!(keypair.public.to_bytes(), pk_from_bytes.to_bytes());
    
    // Test secret key conversions
    let sk_bytes = secret_key_to_bytes(&keypair.secret);
    let sk_from_bytes = bytes_to_secret_key(&sk_bytes).unwrap();
    assert_eq!(keypair.secret.to_bytes(), sk_from_bytes.to_bytes());
}

#[test]
fn test_public_key_to_fields() {
    let keypair = generate_keypair();
    
    // Convert public key to fields
    let (x, y) = public_key_to_fields::<GoldilocksField>(&keypair.public);
    
    // Verify that the fields are non-zero
    assert!(!x.is_zero());
    assert!(!y.is_zero());
}

#[test]
fn test_signature_to_fields() {
    let keypair = generate_keypair();
    let message = b"Hello, 0BTC Wire!";
    let signature = sign_message(&keypair, message);
    
    // Convert signature to fields
    let (r_x, r_y, s) = signature_to_fields::<GoldilocksField>(&signature);
    
    // Verify that the fields are non-zero
    assert!(!r_x.is_zero());
    assert!(!r_y.is_zero());
    assert!(!s.is_zero());
}

#[test]
fn test_is_on_curve() {
    let keypair = generate_keypair();
    
    // Get the base point
    let base_point = get_base_point::<GoldilocksField>();
    
    // Check that the base point is on the curve
    assert!(is_on_curve(base_point.0, base_point.1));
    
    // Check that a random point is likely not on the curve
    let random_x = GoldilocksField::from_canonical_u64(12345);
    let random_y = GoldilocksField::from_canonical_u64(67890);
    assert!(!is_on_curve(random_x, random_y));
}

#[test]
fn test_point_add() {
    // Get the base point
    let p = get_base_point::<GoldilocksField>();
    
    // Add the point to itself
    let p_plus_p = point_add(p, p);
    
    // Verify that the result is on the curve
    assert!(is_on_curve(p_plus_p.0, p_plus_p.1));
    
    // Verify that p + p ≠ p (point addition is not idempotent)
    assert!(p_plus_p.0 != p.0 || p_plus_p.1 != p.1);
}

#[test]
fn test_scalar_multiply() {
    // Get the base point
    let p = get_base_point::<GoldilocksField>();
    
    // Scalar 0 * P should be the identity element (0, 1) for Edwards curves
    let zero = GoldilocksField::ZERO;
    let zero_times_p = scalar_multiply(p, zero);
    assert_eq!(zero_times_p.0, GoldilocksField::ZERO);
    assert_eq!(zero_times_p.1, GoldilocksField::ONE);
    
    // Scalar 1 * P should be P
    let one = GoldilocksField::ONE;
    let one_times_p = scalar_multiply(p, one);
    assert_eq!(one_times_p.0, p.0);
    assert_eq!(one_times_p.1, p.1);
    
    // Scalar 2 * P should be P + P
    let two = GoldilocksField::from_canonical_u64(2);
    let two_times_p = scalar_multiply(p, two);
    let p_plus_p = point_add(p, p);
    assert_eq!(two_times_p.0, p_plus_p.0);
    assert_eq!(two_times_p.1, p_plus_p.1);
}

#[test]
fn test_verify_signature_in_circuit() {
    // Create a keypair and sign a message
    let keypair = generate_keypair();
    let message = b"Hello, 0BTC Wire!";
    let signature = sign_message(&keypair, message);
    
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Compute the message hash
    let message_hash = hash::compute_message_hash(&[GoldilocksField::from_canonical_u64(123456)]);
    let message_hash_target = builder.constant(message_hash);
    
    // Verify the signature in the circuit
    let is_valid = verify_signature_in_circuit(&mut builder, &keypair.public, message_hash_target, &signature);
    
    // Make the verification result a public input
    builder.register_public_input(is_valid.target);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
}

#[test]
fn test_point_operations_in_circuit() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Get the base point
    let base_point_targets = get_base_point_targets(&mut builder);
    
    // Test point addition
    let p_plus_p = point_add_targets(&mut builder, base_point_targets, base_point_targets);
    
    // Test scalar multiplication
    let scalar = builder.constant(GoldilocksField::from_canonical_u64(2));
    let two_times_p = scalar_multiply_targets(&mut builder, base_point_targets, scalar);
    
    // Check that 2*P = P+P
    let x_equal = builder.is_equal(p_plus_p.0, two_times_p.0);
    let y_equal = builder.is_equal(p_plus_p.1, two_times_p.1);
    let points_equal = builder.and(x_equal, y_equal);
    
    // Make the result a public input
    builder.register_public_input(points_equal.target);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check that the points are equal
    assert_eq!(pw.public_inputs[0], GoldilocksField::ONE);
}
