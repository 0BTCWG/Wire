// Standalone benchmark script for 0BTC Wire
// This script can be run with: cargo run --release --bin benchmark_standalone

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use std::time::Instant;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn main() {
    println!("Running 0BTC Wire Standalone Benchmarks");
    println!("=======================================");

    // Benchmark a simple addition circuit
    benchmark_simple_circuit();

    // Benchmark hash operations
    benchmark_hash_operations();

    // Benchmark a more complex circuit (simulating a transfer)
    benchmark_complex_circuit();
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
    let _ = pw.set_target(x, F::from_canonical_u64(2));
    let _ = pw.set_target(y, F::from_canonical_u64(3));

    // Generate a proof
    let start = Instant::now();
    let proof = circuit_data.prove(pw).expect("Failed to generate proof");
    let proof_time = start.elapsed();
    println!("Proof generation time: {:?}", proof_time);

    // Verify the proof
    let start = Instant::now();
    circuit_data
        .verify(proof.clone())
        .expect("Failed to verify proof");
    let verify_time = start.elapsed();
    println!("Proof verification time: {:?}", verify_time);

    // Calculate throughput
    println!(
        "Proof generation throughput: {:.2} proofs/second",
        1.0 / proof_time.as_secs_f64()
    );
    println!(
        "Proof verification throughput: {:.2} proofs/second",
        1.0 / verify_time.as_secs_f64()
    );
}

fn benchmark_hash_operations() {
    println!("\nHash Operations Benchmark");
    println!("------------------------");

    // Measure circuit creation time
    let start = Instant::now();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // Create hash operations
    let input = builder.add_virtual_target();
    let hash_result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![input]);
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
    let _ = pw.set_target(input, F::from_canonical_u64(42));

    // Generate a proof
    let start = Instant::now();
    let proof = circuit_data.prove(pw).expect("Failed to generate proof");
    let proof_time = start.elapsed();
    println!("Proof generation time: {:?}", proof_time);

    // Verify the proof
    let start = Instant::now();
    circuit_data
        .verify(proof.clone())
        .expect("Failed to verify proof");
    let verify_time = start.elapsed();
    println!("Proof verification time: {:?}", verify_time);

    // Calculate throughput
    println!(
        "Proof generation throughput: {:.2} proofs/second",
        1.0 / proof_time.as_secs_f64()
    );
    println!(
        "Proof verification throughput: {:.2} proofs/second",
        1.0 / verify_time.as_secs_f64()
    );
}

fn benchmark_complex_circuit() {
    println!("\nComplex Circuit Benchmark (Transfer Simulation)");
    println!("---------------------------------------------");

    // Measure circuit creation time
    let start = Instant::now();
    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());

    // Create a more complex circuit simulating a transfer
    // Input UTXO fields
    let input_pubkey_hash = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<_>>();
    let input_asset_id = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<_>>();
    let input_amount = builder.add_virtual_target();
    let input_salt = builder.add_virtual_target();

    // Output UTXO fields
    let output_pubkey_hash = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<_>>();
    let output_asset_id = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect::<Vec<_>>();
    let output_amount = builder.add_virtual_target();
    let output_salt = builder.add_virtual_target();

    // Signature fields
    let sig_r_x = builder.add_virtual_target();
    let sig_r_y = builder.add_virtual_target();
    let sig_s = builder.add_virtual_target();

    // Public key fields
    let pk_x = builder.add_virtual_target();
    let pk_y = builder.add_virtual_target();

    // Hash the input UTXO
    let mut input_hash_inputs = Vec::new();
    input_hash_inputs.extend_from_slice(&input_pubkey_hash);
    input_hash_inputs.extend_from_slice(&input_asset_id);
    input_hash_inputs.push(input_amount);
    input_hash_inputs.push(input_salt);

    let input_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(input_hash_inputs);

    // Hash the output UTXO
    let mut output_hash_inputs = Vec::new();
    output_hash_inputs.extend_from_slice(&output_pubkey_hash);
    output_hash_inputs.extend_from_slice(&output_asset_id);
    output_hash_inputs.push(output_amount);
    output_hash_inputs.push(output_salt);

    let output_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(output_hash_inputs);

    // Register public inputs
    builder.register_public_input(input_hash.elements[0]);
    builder.register_public_input(output_hash.elements[0]);

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

    // Set input UTXO values
    for i in 0..32 {
        let _ = pw.set_target(input_pubkey_hash[i], F::from_canonical_u64(i as u64));
        let _ = pw.set_target(input_asset_id[i], F::from_canonical_u64((i + 32) as u64));
        let _ = pw.set_target(
            output_pubkey_hash[i],
            F::from_canonical_u64((i + 64) as u64),
        );
        let _ = pw.set_target(output_asset_id[i], F::from_canonical_u64((i + 32) as u64));
        // Same asset ID
    }

    let _ = pw.set_target(input_amount, F::from_canonical_u64(1000));
    let _ = pw.set_target(input_salt, F::from_canonical_u64(12345));
    let _ = pw.set_target(output_amount, F::from_canonical_u64(900)); // Transfer amount minus fee
    let _ = pw.set_target(output_salt, F::from_canonical_u64(67890));

    // Set signature values
    let _ = pw.set_target(sig_r_x, F::from_canonical_u64(1));
    let _ = pw.set_target(sig_r_y, F::from_canonical_u64(2));
    let _ = pw.set_target(sig_s, F::from_canonical_u64(3));

    // Set public key values
    let _ = pw.set_target(pk_x, F::from_canonical_u64(4));
    let _ = pw.set_target(pk_y, F::from_canonical_u64(5));

    // Generate a proof
    let start = Instant::now();
    let proof = circuit_data.prove(pw).expect("Failed to generate proof");
    let proof_time = start.elapsed();
    println!("Proof generation time: {:?}", proof_time);

    // Verify the proof
    let start = Instant::now();
    circuit_data
        .verify(proof.clone())
        .expect("Failed to verify proof");
    let verify_time = start.elapsed();
    println!("Proof verification time: {:?}", verify_time);

    // Calculate throughput
    println!(
        "Proof generation throughput: {:.2} proofs/second",
        1.0 / proof_time.as_secs_f64()
    );
    println!(
        "Proof verification throughput: {:.2} proofs/second",
        1.0 / verify_time.as_secs_f64()
    );
}
