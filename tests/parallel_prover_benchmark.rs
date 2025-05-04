#[cfg(test)]
mod parallel_prover_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::time::Instant;

    use wire_lib::gadgets::hash::hash_single;
    use wire_lib::utils::{
        generate_proofs_for_circuit, generate_proofs_in_parallel, verify_proofs_in_parallel,
        ParallelProverOptions,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn benchmark_parallel_vs_sequential_proof_generation() {
        // Skip this test in CI environments or when running with --test
        if std::env::var("CI").is_ok() || !std::env::args().any(|arg| arg == "--nocapture") {
            println!("Skipping parallel prover benchmark test in CI or non-verbose mode");
            println!(
                "Run with 'cargo test --test parallel_prover_benchmark -- --nocapture' to execute"
            );
            return;
        }

        println!("Benchmarking parallel vs sequential proof generation...");

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
        let circuit = builder.build::<C>();

        // Create multiple witnesses
        let batch_sizes = [1, 2, 4, 8, 16];

        for &batch_size in &batch_sizes {
            println!("\nTesting with batch size: {}", batch_size);

            let mut witnesses = Vec::with_capacity(batch_size);
            for i in 0..batch_size {
                let mut pw = PartialWitness::new();
                pw.set_target(input, F::from_canonical_u64(i as u64));
                witnesses.push(pw);
            }

            // Sequential proof generation
            let seq_start = Instant::now();
            let mut seq_proofs = Vec::with_capacity(batch_size);
            for witness in &witnesses {
                let proof = circuit.prove(witness.clone()).unwrap();
                seq_proofs.push(proof);
            }
            let seq_time = seq_start.elapsed();
            println!("Sequential proof generation time: {:?}", seq_time);

            // Parallel proof generation with 2 threads
            let par2_options = ParallelProverOptions {
                num_threads: Some(2),
                verbose: false,
            };
            let par2_start = Instant::now();
            let par2_proofs =
                generate_proofs_for_circuit(&circuit, witnesses.clone(), par2_options);
            let par2_time = par2_start.elapsed();
            println!(
                "Parallel proof generation time (2 threads): {:?}",
                par2_time
            );

            // Parallel proof generation with 4 threads
            let par4_options = ParallelProverOptions {
                num_threads: Some(4),
                verbose: false,
            };
            let par4_start = Instant::now();
            let par4_proofs =
                generate_proofs_for_circuit(&circuit, witnesses.clone(), par4_options);
            let par4_time = par4_start.elapsed();
            println!(
                "Parallel proof generation time (4 threads): {:?}",
                par4_time
            );

            // Parallel proof generation with auto threads
            let par_auto_options = ParallelProverOptions {
                num_threads: None,
                verbose: false,
            };
            let par_auto_start = Instant::now();
            let par_auto_proofs =
                generate_proofs_for_circuit(&circuit, witnesses, par_auto_options);
            let par_auto_time = par_auto_start.elapsed();
            println!(
                "Parallel proof generation time (auto threads): {:?}",
                par_auto_time
            );

            // Calculate speedup
            let speedup2 = seq_time.as_secs_f64() / par2_time.as_secs_f64();
            let speedup4 = seq_time.as_secs_f64() / par4_time.as_secs_f64();
            let speedup_auto = seq_time.as_secs_f64() / par_auto_time.as_secs_f64();

            println!("Speedup with 2 threads: {:.2}x", speedup2);
            println!("Speedup with 4 threads: {:.2}x", speedup4);
            println!("Speedup with auto threads: {:.2}x", speedup_auto);

            // Verify that all proofs are valid
            let circuit_refs = vec![&circuit; batch_size];
            let proof_refs: Vec<_> = seq_proofs.iter().collect();
            let verify_results = verify_proofs_in_parallel(
                circuit_refs,
                proof_refs,
                ParallelProverOptions::default(),
            );

            for result in verify_results {
                assert!(result.is_ok(), "Proof verification failed");
            }
        }
    }

    #[test]
    fn benchmark_parallel_verification() {
        // Skip this test in CI environments or when running with --test
        if std::env::var("CI").is_ok() || !std::env::args().any(|arg| arg == "--nocapture") {
            println!("Skipping parallel verification benchmark test in CI or non-verbose mode");
            println!(
                "Run with 'cargo test --test parallel_prover_benchmark -- --nocapture' to execute"
            );
            return;
        }

        println!("Benchmarking parallel vs sequential proof verification...");

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
        let circuit = builder.build::<C>();

        // Create multiple witnesses and generate proofs
        let batch_size = 8;
        let mut witnesses = Vec::with_capacity(batch_size);
        for i in 0..batch_size {
            let mut pw = PartialWitness::new();
            pw.set_target(input, F::from_canonical_u64(i as u64));
            witnesses.push(pw);
        }

        // Generate proofs in parallel
        let options = ParallelProverOptions {
            num_threads: None,
            verbose: false,
        };
        let proofs = generate_proofs_for_circuit(&circuit, witnesses, options);

        // Sequential verification
        let seq_start = Instant::now();
        for proof in &proofs {
            circuit.verify(proof).unwrap();
        }
        let seq_time = seq_start.elapsed();
        println!("Sequential verification time: {:?}", seq_time);

        // Parallel verification
        let circuit_refs = vec![&circuit; batch_size];
        let proof_refs: Vec<_> = proofs.iter().collect();

        // Parallel verification with 2 threads
        let par2_options = ParallelProverOptions {
            num_threads: Some(2),
            verbose: false,
        };
        let par2_start = Instant::now();
        let par2_results =
            verify_proofs_in_parallel(circuit_refs.clone(), proof_refs.clone(), par2_options);
        let par2_time = par2_start.elapsed();
        println!("Parallel verification time (2 threads): {:?}", par2_time);

        // Parallel verification with 4 threads
        let par4_options = ParallelProverOptions {
            num_threads: Some(4),
            verbose: false,
        };
        let par4_start = Instant::now();
        let par4_results =
            verify_proofs_in_parallel(circuit_refs.clone(), proof_refs.clone(), par4_options);
        let par4_time = par4_start.elapsed();
        println!("Parallel verification time (4 threads): {:?}", par4_time);

        // Parallel verification with auto threads
        let par_auto_options = ParallelProverOptions {
            num_threads: None,
            verbose: false,
        };
        let par_auto_start = Instant::now();
        let par_auto_results =
            verify_proofs_in_parallel(circuit_refs, proof_refs, par_auto_options);
        let par_auto_time = par_auto_start.elapsed();
        println!(
            "Parallel verification time (auto threads): {:?}",
            par_auto_time
        );

        // Calculate speedup
        let speedup2 = seq_time.as_secs_f64() / par2_time.as_secs_f64();
        let speedup4 = seq_time.as_secs_f64() / par4_time.as_secs_f64();
        let speedup_auto = seq_time.as_secs_f64() / par_auto_time.as_secs_f64();

        println!("Speedup with 2 threads: {:.2}x", speedup2);
        println!("Speedup with 4 threads: {:.2}x", speedup4);
        println!("Speedup with auto threads: {:.2}x", speedup_auto);

        // Verify that all results are successful
        for result in par_auto_results {
            assert!(result.is_ok(), "Proof verification failed");
        }
    }
}
