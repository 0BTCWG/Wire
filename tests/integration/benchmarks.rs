use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use std::time::Instant;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

#[test]
fn run_basic_benchmarks() {
    // Skip this test in CI environments or when running with --test
    if std::env::var("CI").is_ok() || !std::env::args().any(|arg| arg == "--nocapture") {
        println!("Skipping benchmarks in CI or non-verbose mode");
        println!("Run with 'cargo test --test integration_benchmarks -- --nocapture' to execute");
        return;
    }
    
    println!("Running basic benchmarks...");
    
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
    
    // Print summary
    println!("\nBenchmark Summary:");
    println!("------------------");
    println!("Circuit creation time: {:?}", circuit_creation_time);
    println!("Circuit build time: {:?}", circuit_build_time);
    println!("Gate count: {}", gate_count);
    println!("Proof generation time: {:?}", proof_time);
    println!("Proof verification time: {:?}", verify_time);
    println!("Proof generation throughput: {:.2} proofs/second", 1.0 / proof_time.as_secs_f64());
    println!("Proof verification throughput: {:.2} proofs/second", 1.0 / verify_time.as_secs_f64());
}
