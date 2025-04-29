// Tests for the nullifier gadget
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::gadgets::{calculate_nullifier, calculate_and_register_nullifier};
use wire_lib::core::HASH_SIZE;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_nullifier_calculation() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create a salt and secret key
    let salt: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let sk = builder.add_virtual_target();
    
    // Calculate the nullifier
    let nullifier = calculate_nullifier(&mut builder, &salt, sk);
    
    // Make the nullifier a public input
    builder.register_public_input(nullifier);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    for (i, s) in salt.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64(i as u64));
    }
    pw.set_target(sk, F::from_canonical_u64(123456));
    
    // Generate the proof
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    circuit.verify(proof.clone()).unwrap();
    
    // Check the nullifier
    assert_ne!(proof.public_inputs[0], F::ZERO);
}

#[test]
fn test_nullifier_deterministic() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create a salt and secret key
    let salt: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let sk = builder.add_virtual_target();
    
    // Calculate the nullifier twice
    let nullifier1 = calculate_nullifier(&mut builder, &salt, sk);
    let nullifier2 = calculate_nullifier(&mut builder, &salt, sk);
    
    // Check if they're equal
    let nullifiers_equal = builder.is_equal(nullifier1, nullifier2);
    
    // Convert BoolTarget to Target
    let one = builder.one();
    let zero = builder.zero();
    let nullifiers_equal_target = builder.select(nullifiers_equal, one, zero);
    
    // Make the result a public input
    builder.register_public_input(nullifiers_equal_target);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    for (i, s) in salt.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64(i as u64));
    }
    pw.set_target(sk, F::from_canonical_u64(123456));
    
    // Generate the proof
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    circuit.verify(proof.clone()).unwrap();
    
    // Check that the nullifiers are equal (should be 1)
    assert_eq!(proof.public_inputs[0], F::ONE);
}

#[test]
fn test_nullifier_different_salt() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create two salts and a secret key
    let salt1: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let salt2: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let sk = builder.add_virtual_target();
    
    // Calculate the nullifiers
    let nullifier1 = calculate_nullifier(&mut builder, &salt1, sk);
    let nullifier2 = calculate_nullifier(&mut builder, &salt2, sk);
    
    // Check if they're equal
    let nullifiers_equal = builder.is_equal(nullifier1, nullifier2);
    let nullifiers_different = builder.not(nullifiers_equal);
    
    // Convert BoolTarget to Target
    let one = builder.one();
    let zero = builder.zero();
    let nullifiers_different_target = builder.select(nullifiers_different, one, zero);
    
    // Make the result a public input
    builder.register_public_input(nullifiers_different_target);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    for (i, s) in salt1.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64(i as u64));
    }
    for (i, s) in salt2.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64((i + 100) as u64));
    }
    pw.set_target(sk, F::from_canonical_u64(123456));
    
    // Generate the proof
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    circuit.verify(proof.clone()).unwrap();
    
    // Check that the nullifiers are different (should be 1)
    assert_eq!(proof.public_inputs[0], F::ONE);
}

#[test]
fn test_nullifier_different_sk() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create a salt and two secret keys
    let salt: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let sk1 = builder.add_virtual_target();
    let sk2 = builder.add_virtual_target();
    
    // Calculate the nullifiers
    let nullifier1 = calculate_nullifier(&mut builder, &salt, sk1);
    let nullifier2 = calculate_nullifier(&mut builder, &salt, sk2);
    
    // Check if they're equal
    let nullifiers_equal = builder.is_equal(nullifier1, nullifier2);
    let nullifiers_different = builder.not(nullifiers_equal);
    
    // Convert BoolTarget to Target
    let one = builder.one();
    let zero = builder.zero();
    let nullifiers_different_target = builder.select(nullifiers_different, one, zero);
    
    // Make the result a public input
    builder.register_public_input(nullifiers_different_target);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    for (i, s) in salt.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64(i as u64));
    }
    pw.set_target(sk1, F::from_canonical_u64(123456));
    pw.set_target(sk2, F::from_canonical_u64(654321));
    
    // Generate the proof
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    circuit.verify(proof.clone()).unwrap();
    
    // Check that the nullifiers are different (should be 1)
    assert_eq!(proof.public_inputs[0], F::ONE);
}

#[test]
fn test_calculate_and_register_nullifier() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create a salt and secret key
    let salt: Vec<_> = (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect();
    let sk = builder.add_virtual_target();
    
    // Calculate and register the nullifier
    let nullifier = calculate_and_register_nullifier(&mut builder, &salt, sk);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    for (i, s) in salt.iter().enumerate() {
        pw.set_target(*s, F::from_canonical_u64(i as u64));
    }
    pw.set_target(sk, F::from_canonical_u64(123456));
    
    // Generate the proof
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    circuit.verify(proof.clone()).unwrap();
    
    // Check the nullifier
    assert_ne!(proof.public_inputs[0], F::ZERO);
}
