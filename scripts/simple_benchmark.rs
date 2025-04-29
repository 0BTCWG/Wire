// Simple benchmark script for 0BTC Wire
// This script measures the performance of basic operations without relying on the full benchmarking framework

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use std::time::Instant;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn main() {
    println!("Running 0BTC Wire Simple Benchmarks");
    println!("===================================");
    
    // Benchmark a simple addition circuit
    benchmark_simple_circuit();
    
    // Benchmark hash operations
    benchmark_hash_operations();
}

fn benchmark_simple_circuit() {
    println!("\nSimple Addition Circuit Benchmark");
    println!("--------------------------------");
    
    // Measure circuit creation time
    let start = Instant::now();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    
    // Create a simple addition circuit
    let x = builder.add_virtual_target();
    let y = builder.add_virtual_target();
    let z = builder.add(x, y);
    builder.register_public_input(z);
    
    let circuit_creation_time = start.elapsed();
    println!("Circuit creation time: {:?}", circuit_creation_time);
    
    // Build the circuit
    let start = Instant::now();
    let circuit_data = builder.build::<C>();
    let circuit_build_time = start.elapsed();
    println!("Circuit build time: {:?}", circuit_build_time);
    
    // Count gates
    let gate_count = circuit_data.common.gates.len();
    println!("Gate count: {}", gate_count);
    
    // Create a witness
    let mut pw = PartialWitness::new();
    pw.set_target(x, F::from_canonical_u64(2));
    pw.set_target(y, F::from_canonical_u64(3));
    
    // Generate a proof
    let start = Instant::now();
    let proof = circuit_data.prove(pw).expect("Failed to generate proof");
    let proof_time = start.elapsed();
    println!("Proof generation time: {:?}", proof_time);
    
    // Verify the proof
    let start = Instant::now();
    circuit_data.verify(proof.clone()).expect("Failed to verify proof");
    let verify_time = start.elapsed();
    println!("Proof verification time: {:?}", verify_time);
    
    // Calculate throughput
    println!("Proof generation throughput: {:.2} proofs/second", 1.0 / proof_time.as_secs_f64());
    println!("Proof verification throughput: {:.2} proofs/second", 1.0 / verify_time.as_secs_f64());
}

fn benchmark_hash_operations() {
    println!("\nHash Operations Benchmark");
    println!("------------------------");
    
    // Measure circuit creation time
    let start = Instant::now();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    
    // Create hash operations
    let input = builder.add_virtual_target();
    let hash_result = builder.hash_n_to_hash_no_pad::<PoseidonGoldilocksConfig>(&[input]);
    builder.register_public_input(hash_result.elements[0]);
    
    let circuit_creation_time = start.elapsed();
    println!("Circuit creation time: {:?}", circuit_creation_time);
    
    // Build the circuit
    let start = Instant::now();
    let circuit_data = builder.build::<C>();
    let circuit_build_time = start.elapsed();
    println!("Circuit build time: {:?}", circuit_build_time);
    
    // Count gates
    let gate_count = circuit_data.common.gates.len();
    println!("Gate count: {}", gate_count);
    
    // Create a witness
    let mut pw = PartialWitness::new();
    pw.set_target(input, F::from_canonical_u64(42));
    
    // Generate a proof
    let start = Instant::now();
    let proof = circuit_data.prove(pw).expect("Failed to generate proof");
    let proof_time = start.elapsed();
    println!("Proof generation time: {:?}", proof_time);
    
    // Verify the proof
    let start = Instant::now();
    circuit_data.verify(proof.clone()).expect("Failed to verify proof");
    let verify_time = start.elapsed();
    println!("Proof verification time: {:?}", verify_time);
    
    // Calculate throughput
    println!("Proof generation throughput: {:.2} proofs/second", 1.0 / proof_time.as_secs_f64());
    println!("Proof verification throughput: {:.2} proofs/second", 1.0 / verify_time.as_secs_f64());
}
