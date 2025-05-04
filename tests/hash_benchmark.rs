#[cfg(test)]
mod hash_benchmark_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::time::Instant;

    use wire_lib::core::UTXOTarget;
    use wire_lib::gadgets::hash::{
        hash_n, hash_single, hash_utxo_commitment, hash_utxo_target, optimized_hash,
        optimized_hash_pair, optimized_hash_single, optimized_hash_utxo,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn benchmark_hash_performance() {
        println!("Benchmarking hash function performance...");

        // Test single input hash
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a target to hash
        let input = builder.add_virtual_target();

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Perform the hash operation and connect it to the public input
        let hash_result = hash_single(&mut builder, input);
        builder.connect(hash_result, pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(input, F::from_canonical_u64(123));

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!("Single input hash performance:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }

    #[test]
    fn benchmark_optimized_hash_performance() {
        println!("Benchmarking optimized hash function performance...");

        // Test single input hash
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a target to hash
        let input = builder.add_virtual_target();

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Perform the hash operation and connect it to the public input
        let hash_result = optimized_hash_single(&mut builder, input);
        builder.connect(hash_result, pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(input, F::from_canonical_u64(123));

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!("Optimized single input hash performance:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }

    #[test]
    fn benchmark_utxo_hash_performance() {
        println!("Benchmarking UTXO hash performance...");

        // Test UTXO hash
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create virtual targets for the UTXO components
        let mut owner_pubkey_hash = Vec::with_capacity(4);
        for _ in 0..4 {
            owner_pubkey_hash.push(builder.add_virtual_target());
        }

        let mut asset_id = Vec::with_capacity(4);
        for _ in 0..4 {
            asset_id.push(builder.add_virtual_target());
        }

        let amount = builder.add_virtual_target();

        let mut salt = Vec::with_capacity(4);
        for _ in 0..4 {
            salt.push(builder.add_virtual_target());
        }

        // Create a UTXO target
        let utxo = UTXOTarget {
            owner_pubkey_hash_target: owner_pubkey_hash.clone(),
            asset_id_target: asset_id.clone(),
            amount_target: amount,
            salt_target: salt.clone(),
        };

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Perform the hash operation and connect it to the public input
        let hash_result = hash_utxo_target(&mut builder, &utxo);
        builder.connect(hash_result, pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        for i in 0..4 {
            pw.set_target(owner_pubkey_hash[i], F::from_canonical_u64(100 + i as u64));
            pw.set_target(asset_id[i], F::from_canonical_u64(200 + i as u64));
            pw.set_target(salt[i], F::from_canonical_u64(300 + i as u64));
        }
        pw.set_target(amount, F::from_canonical_u64(1000));

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!("UTXO hash performance:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }

    #[test]
    fn benchmark_optimized_utxo_hash_performance() {
        println!("Benchmarking optimized UTXO hash performance...");

        // Test optimized UTXO hash
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create virtual targets for the UTXO components
        let mut owner_pubkey_hash = Vec::with_capacity(4);
        for _ in 0..4 {
            owner_pubkey_hash.push(builder.add_virtual_target());
        }

        let mut asset_id = Vec::with_capacity(4);
        for _ in 0..4 {
            asset_id.push(builder.add_virtual_target());
        }

        let amount = builder.add_virtual_target();

        let mut salt = Vec::with_capacity(4);
        for _ in 0..4 {
            salt.push(builder.add_virtual_target());
        }

        // Create a UTXO target
        let utxo = UTXOTarget {
            owner_pubkey_hash_target: owner_pubkey_hash.clone(),
            asset_id_target: asset_id.clone(),
            amount_target: amount,
            salt_target: salt.clone(),
        };

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Perform the hash operation and connect it to the public input
        let hash_result = optimized_hash_utxo(&mut builder, &utxo);
        builder.connect(hash_result, pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        for i in 0..4 {
            pw.set_target(owner_pubkey_hash[i], F::from_canonical_u64(100 + i as u64));
            pw.set_target(asset_id[i], F::from_canonical_u64(200 + i as u64));
            pw.set_target(salt[i], F::from_canonical_u64(300 + i as u64));
        }
        pw.set_target(amount, F::from_canonical_u64(1000));

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!("Optimized UTXO hash performance:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }

    #[test]
    fn compare_hash_implementations() {
        println!("Comparing hash implementations with different input sizes...");

        // Test with different input sizes
        let input_sizes = [1, 2, 4, 8, 13];

        for &size in &input_sizes {
            println!("\nTesting with input size: {}", size);

            // Original implementation
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Create targets to hash
            let mut inputs = Vec::with_capacity(size);
            for _ in 0..size {
                inputs.push(builder.add_virtual_target());
            }

            // Add a public input
            let pub_input = builder.add_virtual_target();
            builder.register_public_input(pub_input);

            // Perform the hash operation
            let hash_result = hash_n(&mut builder, &inputs);
            builder.connect(hash_result, pub_input);

            // Build the circuit
            let start = Instant::now();
            let data = builder.build::<C>();
            let circuit_creation_time = start.elapsed();
            let gate_count = data.common.gates.len();

            println!("Original hash implementation:");
            println!("  Gate count: {}", gate_count);
            println!("  Circuit creation time: {:?}", circuit_creation_time);

            // Optimized implementation
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Create targets to hash
            let mut inputs = Vec::with_capacity(size);
            for _ in 0..size {
                inputs.push(builder.add_virtual_target());
            }

            // Add a public input
            let pub_input = builder.add_virtual_target();
            builder.register_public_input(pub_input);

            // Perform the hash operation
            let hash_result = optimized_hash(&mut builder, &inputs);
            builder.connect(hash_result, pub_input);

            // Build the circuit
            let start = Instant::now();
            let data = builder.build::<C>();
            let circuit_creation_time = start.elapsed();
            let gate_count = data.common.gates.len();

            println!("Optimized hash implementation:");
            println!("  Gate count: {}", gate_count);
            println!("  Circuit creation time: {:?}", circuit_creation_time);
        }
    }
}
