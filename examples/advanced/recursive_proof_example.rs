// Example demonstrating how to use recursive proof aggregation
use std::time::Instant;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

// Import the recursive prover utilities
// Note: Update these imports to match your project structure
use wire_lib::utils::{
    aggregate_proofs,
    verify_aggregated_proof,
    RecursiveProverOptions,
};
use wire_lib::gadgets::hash::hash_single;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn main() {
    println!("Recursive Proof Aggregation Example");
    println!("==================================");
    
    // Create a simple hash circuit for testing
    println!("Creating test circuit...");
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Add inputs
    let input = builder.add_virtual_target();
    let pub_output = builder.add_virtual_target();
    builder.register_public_input(pub_output);
    
    // Perform a hash operation
    let hash_result = hash_single(&mut builder, input);
    builder.connect(hash_result, pub_output);
    
    // Build the circuit
    let start = Instant::now();
    let circuit = builder.build::<C>();
    let circuit_creation_time = start.elapsed();
    println!("Circuit creation time: {:?}", circuit_creation_time);
    
    // Define the number of proofs to aggregate
    let num_proofs = 8;
    println!("\nGenerating {} individual proofs...", num_proofs);
    
    // Create multiple proofs
    let mut proofs = Vec::with_capacity(num_proofs);
    let proof_generation_start = Instant::now();
    
    for i in 0..num_proofs {
        let mut pw = PartialWitness::new();
        pw.set_target(input, F::from_canonical_u64(i as u64));
        let proof = circuit.prove(pw).unwrap();
        proofs.push(proof);
        println!("Generated proof {}/{}", i + 1, num_proofs);
    }
    
    let proof_generation_time = proof_generation_start.elapsed();
    println!("Generated {} individual proofs in {:?}", num_proofs, proof_generation_time);
    
    // Verify each proof individually
    println!("\nVerifying proofs individually...");
    let individual_verify_start = Instant::now();
    
    for (i, proof) in proofs.iter().enumerate() {
        circuit.verify(proof).unwrap();
        println!("Verified proof {}/{}", i + 1, num_proofs);
    }
    
    let individual_verify_time = individual_verify_start.elapsed();
    println!("Verified {} proofs individually in {:?}", num_proofs, individual_verify_time);
    println!("Individual verification throughput: {:.2} proofs/second", 
        num_proofs as f64 / individual_verify_time.as_secs_f64());
    
    // Aggregate the proofs
    println!("\nAggregating proofs...");
    let options = RecursiveProverOptions {
        verbose: true,
        max_proofs_per_step: Some(4), // Aggregate in steps of 4 proofs
    };
    
    let aggregation_start = Instant::now();
    let result = aggregate_proofs(proofs, options).unwrap();
    let aggregation_time = aggregation_start.elapsed();
    
    println!("Aggregated {} proofs in {:?}", num_proofs, aggregation_time);
    println!("Aggregation throughput: {:.2} proofs/second", 
        num_proofs as f64 / aggregation_time.as_secs_f64());
    
    // Verify the aggregated proof
    println!("\nVerifying aggregated proof...");
    let aggregated_verify_start = Instant::now();
    let num_aggregated = verify_aggregated_proof(&result.proof, &circuit).unwrap();
    let aggregated_verify_time = aggregated_verify_start.elapsed();
    
    println!("Verified aggregated proof containing {} proofs in {:?}", num_aggregated, aggregated_verify_time);
    println!("Aggregated verification throughput: {:.2} proofs/second", 
        num_aggregated as f64 / aggregated_verify_time.as_secs_f64());
    
    // Calculate speedup
    let speedup = individual_verify_time.as_secs_f64() / aggregated_verify_time.as_secs_f64();
    println!("\nVerification speedup from recursive aggregation: {:.2}x", speedup);
    
    // Demonstrate how to use recursive proof aggregation in a real-world scenario
    println!("\nReal-world scenario: Batching multiple transaction proofs");
    println!("=======================================================");
    println!("In a blockchain system like 0BTC Wire, you can use recursive proof aggregation to:");
    println!("1. Generate individual proofs for each transaction");
    println!("2. Aggregate them into a single proof");
    println!("3. Verify the single proof instead of all individual proofs");
    println!("4. Achieve significant verification speedup, especially for large batches");
    
    println!("\nBenefits:");
    println!("- Reduced verification time: {:.2}x speedup", speedup);
    println!("- Lower gas costs for on-chain verification");
    println!("- Improved scalability for high-throughput systems");
    println!("- Simplified proof management");
}
