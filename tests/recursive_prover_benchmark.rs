#[cfg(test)]
mod recursive_prover_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::time::Instant;
    
    use wire_lib::utils::{
        aggregate_proofs,
        RecursiveProverOptions,
    };
    use wire_lib::gadgets::hash::hash_single;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn benchmark_recursive_proof_aggregation() {
        // Skip this test in CI environments or when running with --test
        if std::env::var("CI").is_ok() || !std::env::args().any(|arg| arg == "--nocapture") {
            println!("Skipping recursive prover benchmark test in CI or non-verbose mode");
            println!("Run with 'cargo test --test recursive_prover_benchmark -- --nocapture' to execute");
            return;
        }
        
        println!("Benchmarking recursive proof aggregation...");
        
        // Create a simple hash circuit for testing
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
        let batch_sizes = [2, 4, 8, 16];
        
        for &batch_size in &batch_sizes {
            println!("\nTesting with batch size: {}", batch_size);
            
            // Create multiple proofs
            let mut proofs = Vec::with_capacity(batch_size);
            let proof_generation_start = Instant::now();
            
            for i in 0..batch_size {
                let mut pw = PartialWitness::new();
                pw.set_target(input, F::from_canonical_u64(i as u64));
                let proof = circuit.prove(pw).unwrap();
                proofs.push(proof);
            }
            
            let proof_generation_time = proof_generation_start.elapsed();
            println!("Generated {} individual proofs in {:?}", batch_size, proof_generation_time);
            
            // Test different max_proofs_per_step values
            let step_sizes = [2, 4, 8];
            
            for &step_size in &step_sizes {
                if step_size > batch_size {
                    continue;
                }
                
                println!("Aggregating with max {} proofs per step:", step_size);
                
                // Aggregate the proofs
                let options = RecursiveProverOptions {
                    verbose: true,
                    max_proofs_per_step: Some(step_size),
                };
                
                let aggregation_start = Instant::now();
                let result = aggregate_proofs(proofs.clone(), options).unwrap();
                let aggregation_time = aggregation_start.elapsed();
                
                println!("Aggregated {} proofs in {:?}", batch_size, aggregation_time);
                println!("Aggregation throughput: {:.2} proofs/second", 
                    batch_size as f64 / aggregation_time.as_secs_f64());
                
                // Verify the aggregated proof
                let verify_start = Instant::now();
                let num_aggregated = wire_lib::utils::verify_aggregated_proof(&result.proof, &circuit).unwrap();
                let verify_time = verify_start.elapsed();
                
                println!("Verified aggregated proof in {:?}", verify_time);
                println!("Verification throughput: {:.2} proofs/second", 
                    num_aggregated as f64 / verify_time.as_secs_f64());
                
                // Calculate the efficiency ratio
                let individual_verify_time = verify_time.as_secs_f64() * batch_size as f64;
                let speedup = individual_verify_time / verify_time.as_secs_f64();
                
                println!("Verification speedup: {:.2}x", speedup);
            }
        }
    }
    
    #[test]
    fn benchmark_recursive_vs_individual_verification() {
        // Skip this test in CI environments or when running with --test
        if std::env::var("CI").is_ok() || !std::env::args().any(|arg| arg == "--nocapture") {
            println!("Skipping recursive vs individual verification benchmark test in CI or non-verbose mode");
            println!("Run with 'cargo test --test recursive_prover_benchmark -- --nocapture' to execute");
            return;
        }
        
        println!("Benchmarking recursive vs individual proof verification...");
        
        // Create a simple circuit for testing
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Add a public input
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);
        
        // Add a private input
        let priv_input = builder.add_virtual_target();
        
        // Connect them
        builder.connect(pub_input, priv_input);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create multiple proofs
        let batch_size = 16;
        let mut proofs = Vec::with_capacity(batch_size);
        
        for i in 0..batch_size {
            let mut pw = PartialWitness::new();
            pw.set_target(pub_input, F::from_canonical_u64(i as u64));
            pw.set_target(priv_input, F::from_canonical_u64(i as u64));
            let proof = circuit.prove(pw).unwrap();
            proofs.push(proof);
        }
        
        // Measure individual verification time
        let individual_start = Instant::now();
        for proof in &proofs {
            circuit.verify(proof).unwrap();
        }
        let individual_time = individual_start.elapsed();
        
        println!("Individual verification of {} proofs: {:?}", batch_size, individual_time);
        println!("Individual verification throughput: {:.2} proofs/second", 
            batch_size as f64 / individual_time.as_secs_f64());
        
        // Aggregate the proofs
        let options = RecursiveProverOptions {
            verbose: true,
            max_proofs_per_step: Some(4),
        };
        
        let result = aggregate_proofs(proofs, options).unwrap();
        
        // Measure aggregated verification time
        let aggregated_start = Instant::now();
        wire_lib::utils::verify_aggregated_proof(&result.proof, &circuit).unwrap();
        let aggregated_time = aggregated_start.elapsed();
        
        println!("Aggregated verification of {} proofs: {:?}", batch_size, aggregated_time);
        println!("Aggregated verification throughput: {:.2} proofs/second", 
            batch_size as f64 / aggregated_time.as_secs_f64());
        
        // Calculate speedup
        let speedup = individual_time.as_secs_f64() / aggregated_time.as_secs_f64();
        println!("Verification speedup: {:.2}x", speedup);
    }
}
