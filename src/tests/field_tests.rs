// Unit tests for field utility functions

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::field::*;

#[test]
fn test_field_to_bits() {
    let value = GoldilocksField::from_canonical_u64(42);
    let bits = field_to_bits(value);
    
    // 42 in binary is 101010
    assert_eq!(bits[0], false); // LSB
    assert_eq!(bits[1], true);
    assert_eq!(bits[2], false);
    assert_eq!(bits[3], true);
    assert_eq!(bits[4], false);
    assert_eq!(bits[5], true);
    
    // All other bits should be 0
    for i in 6..64 {
        assert_eq!(bits[i], false);
    }
}

#[test]
fn test_field_to_bits_with_length() {
    let value = GoldilocksField::from_canonical_u64(42);
    let bits = field_to_bits_with_length(value, 8);
    
    // 42 in binary is 00101010 (8 bits)
    assert_eq!(bits.len(), 8);
    assert_eq!(bits[0], false); // LSB
    assert_eq!(bits[1], true);
    assert_eq!(bits[2], false);
    assert_eq!(bits[3], true);
    assert_eq!(bits[4], false);
    assert_eq!(bits[5], true);
    assert_eq!(bits[6], false);
    assert_eq!(bits[7], false);
}

#[test]
fn test_bits_to_field() {
    // 42 in binary is 00101010
    let bits = vec![false, true, false, true, false, true, false, false];
    let value = bits_to_field::<GoldilocksField>(&bits);
    
    assert_eq!(value.to_canonical_u64(), 42);
}

#[test]
fn test_field_to_bits_le_target() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create a target with value 42
    let value = GoldilocksField::from_canonical_u64(42);
    let target = builder.constant(value);
    
    // Convert to bits
    let bits = field_to_bits_le_target(&mut builder, target, 8);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Extract the bits from the proof witness
    let witness = pw.public_inputs;
    
    // 42 in binary is 00101010
    // The bits should be in little-endian order: 01010100
    assert_eq!(bits.len(), 8);
}

#[test]
fn test_u64_to_field_and_field_to_u64() {
    let original = 12345u64;
    let field_value = u64_to_field::<GoldilocksField>(original);
    let back_to_u64 = field_to_u64(field_value);
    
    assert_eq!(original, back_to_u64);
}

#[test]
fn test_add_field_targets() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create two targets
    let a = builder.constant(GoldilocksField::from_canonical_u64(10));
    let b = builder.constant(GoldilocksField::from_canonical_u64(20));
    
    // Add them
    let sum = add_field_targets(&mut builder, a, b);
    
    // Add a public output
    builder.register_public_input(sum);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check the result
    assert_eq!(pw.public_inputs[0], GoldilocksField::from_canonical_u64(30));
}

#[test]
fn test_mul_field_targets() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create two targets
    let a = builder.constant(GoldilocksField::from_canonical_u64(10));
    let b = builder.constant(GoldilocksField::from_canonical_u64(20));
    
    // Multiply them
    let product = mul_field_targets(&mut builder, a, b);
    
    // Add a public output
    builder.register_public_input(product);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check the result
    assert_eq!(pw.public_inputs[0], GoldilocksField::from_canonical_u64(200));
}

#[test]
fn test_goldilocks_field_range() {
    let modulus = goldilocks_modulus();
    
    // Test values within range
    assert!(is_in_goldilocks_field_range(0));
    assert!(is_in_goldilocks_field_range(modulus - 1));
    
    // Test values outside range
    assert!(!is_in_goldilocks_field_range(modulus));
    assert!(!is_in_goldilocks_field_range(modulus + 1));
    
    // Test reduction
    assert_eq!(reduce_to_goldilocks_field_range(modulus), 0);
    assert_eq!(reduce_to_goldilocks_field_range(modulus + 42), 42);
}
