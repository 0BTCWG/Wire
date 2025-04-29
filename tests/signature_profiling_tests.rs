use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use std::time::Instant;

use wire::gadgets::signature::{count_signature_verification_gates, count_batch_signature_verification_gates};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

#[test]
fn test_signature_verification_gate_count() {
    // Create a circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Count the gates for a single signature verification
    let gates = count_signature_verification_gates(&mut builder);
    
    println!("Single signature verification gate count: {}", gates);
    
    // Count the gates for batch verification with different batch sizes
    let batch_sizes = [2, 4, 8, 16];
    for &batch_size in &batch_sizes {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let gates = count_batch_signature_verification_gates(&mut builder, batch_size);
        
        println!("Batch signature verification gate count (size {}): {}", batch_size, gates);
        println!("Average gates per signature in batch: {}", gates as f64 / batch_size as f64);
    }
}

#[test]
fn benchmark_signature_verification() {
    println!("Benchmarking signature verification...");
    
    // Create a circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Count the gates for a single signature verification
    let gates = count_signature_verification_gates(&mut builder);
    
    // Build the circuit
    let start = Instant::now();
    let circuit = builder.build::<C>();
    let circuit_creation_time = start.elapsed();
    
    // Create a partial witness
    let pw = PartialWitness::new();
    
    // Generate a proof
    let start = Instant::now();
    let proof = circuit.prove(pw).unwrap();
    let proof_generation_time = start.elapsed();
    
    // Verify the proof
    let start = Instant::now();
    circuit.verify(proof).unwrap();
    let verification_time = start.elapsed();
    
    println!("Signature verification benchmark results:");
    println!("  Gate count: {}", gates);
    println!("  Circuit creation time: {:?}", circuit_creation_time);
    println!("  Proof generation time: {:?}", proof_generation_time);
    println!("  Proof verification time: {:?}", verification_time);
}

#[test]
fn benchmark_batch_signature_verification() {
    println!("Benchmarking batch signature verification...");
    
    // Test with batch size 4
    let batch_size = 4;
    
    // Create a circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Count the gates for batch signature verification
    let gates = count_batch_signature_verification_gates(&mut builder, batch_size);
    
    // Build the circuit
    let start = Instant::now();
    let circuit = builder.build::<C>();
    let circuit_creation_time = start.elapsed();
    
    // Create a partial witness
    let pw = PartialWitness::new();
    
    // Generate a proof
    let start = Instant::now();
    let proof = circuit.prove(pw).unwrap();
    let proof_generation_time = start.elapsed();
    
    // Verify the proof
    let start = Instant::now();
    circuit.verify(proof).unwrap();
    let verification_time = start.elapsed();
    
    println!("Batch signature verification (size {}) benchmark results:", batch_size);
    println!("  Gate count: {}", gates);
    println!("  Average gates per signature: {}", gates as f64 / batch_size as f64);
    println!("  Circuit creation time: {:?}", circuit_creation_time);
    println!("  Proof generation time: {:?}", proof_generation_time);
    println!("  Proof verification time: {:?}", verification_time);
}
