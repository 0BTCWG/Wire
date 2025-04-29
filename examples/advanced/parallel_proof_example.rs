// Example demonstrating how to use parallel proof generation
use std::time::Instant;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

// Import the parallel prover utilities
// Note: Update these imports to match your project structure
use wire_lib::utils::{
    generate_proofs_for_circuit,
    verify_proofs_in_parallel,
    ParallelProverOptions,
};
use wire_lib::gadgets::hash::hash_single;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

fn main() {
    println!("Parallel Proof Generation Example");
    println!("================================");
    
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
    
    // Define batch sizes to test
    let batch_sizes = [1, 2, 4, 8];
    
    for &batch_size in &batch_sizes {
        println!("\nTesting with batch size: {}", batch_size);
        
        // Create multiple witnesses
        let mut witnesses = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let mut pw = PartialWitness::new();
            pw.set_target(input, F::from_canonical_u64(i as u64));
            witnesses.push(pw);
        }
        
        // Sequential proof generation
        println!("Generating proofs sequentially...");
        let seq_start = Instant::now();
        let mut seq_proofs = Vec::with_capacity(batch_size);
        for witness in &witnesses {
            let proof = circuit.prove(witness.clone()).unwrap();
            seq_proofs.push(proof);
        }
        let seq_time = seq_start.elapsed();
        println!("Sequential proof generation time: {:?}", seq_time);
        
        // Parallel proof generation
        println!("Generating proofs in parallel...");
        let par_options = ParallelProverOptions {
            num_threads: None, // Auto-select optimal number of threads
            verbose: true,
        };
        let par_start = Instant::now();
        let par_proofs = generate_proofs_for_circuit(&circuit, witnesses, par_options);
        let par_time = par_start.elapsed();
        println!("Parallel proof generation time: {:?}", par_time);
        
        // Calculate speedup
        let speedup = seq_time.as_secs_f64() / par_time.as_secs_f64();
        println!("Speedup: {:.2}x", speedup);
        
        // Verify all proofs
        println!("Verifying proofs...");
        for proof in &par_proofs {
            circuit.verify(proof).unwrap();
        }
        println!("All proofs verified successfully!");
        
        // Parallel verification
        println!("Verifying proofs in parallel...");
        let circuit_refs = vec![&circuit; batch_size];
        let proof_refs: Vec<_> = par_proofs.iter().collect();
        
        let par_verify_options = ParallelProverOptions {
            num_threads: None,
            verbose: true,
        };
        let verify_results = verify_proofs_in_parallel(circuit_refs, proof_refs, par_verify_options);
        
        // Check verification results
        for result in verify_results {
            assert!(result.is_ok(), "Proof verification failed");
        }
        println!("All proofs verified successfully in parallel!");
    }
}
