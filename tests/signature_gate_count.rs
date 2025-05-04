#[cfg(test)]
mod signature_gate_count_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::time::Instant;

    use wire_lib::gadgets::signature::{
        count_batch_signature_verification_gates, count_signature_verification_gates,
    };

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_signature_verification_gate_count() {
        println!("Measuring signature verification gate count...");

        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Count the gates for a single signature verification
        let gates = count_signature_verification_gates(&mut builder);

        println!("Single signature verification gate count: {:?}", gates);

        // Build the circuit to measure circuit creation time
        let start = Instant::now();
        let _data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        println!(
            "Signature verification circuit creation time: {:?}",
            circuit_creation_time
        );
    }

    #[test]
    fn test_batch_signature_verification_gate_count() {
        println!("Measuring batch signature verification gate counts...");

        // Test with different batch sizes
        let batch_sizes = [2, 4, 8, 16];

        for &batch_size in &batch_sizes {
            // Create a circuit
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            // Count the gates for batch signature verification
            let gates = count_batch_signature_verification_gates(&mut builder, batch_size);

            println!(
                "Batch signature verification gate count (size {}): {:?}",
                batch_size, gates
            );
            println!(
                "Average gates per signature in batch: {}",
                gates as f64 / batch_size as f64
            );

            // Only build the circuit for batch size 4 to save time
            if batch_size == 4 {
                // Build the circuit to measure circuit creation time
                let start = Instant::now();
                let _data = builder.build::<C>();
                let circuit_creation_time = start.elapsed();

                println!(
                    "Batch signature verification (size {}) circuit creation time: {:?}",
                    batch_size, circuit_creation_time
                );
            }
        }
    }

    #[test]
    fn test_signature_verification_performance() {
        println!("Benchmarking signature verification performance...");

        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Add a single signature verification
        count_signature_verification_gates(&mut builder);

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(pub_input, F::ONE);

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!("Signature verification performance results:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }

    #[test]
    fn test_batch_signature_verification_performance() {
        println!("Benchmarking batch signature verification performance...");

        // Use batch size 4 for performance testing
        let batch_size = 4;

        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Add batch signature verification
        count_batch_signature_verification_gates(&mut builder, batch_size);

        // Add a public input to make the circuit valid
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);

        // Build the circuit
        let start = Instant::now();
        let data = builder.build::<C>();
        let circuit_creation_time = start.elapsed();

        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(pub_input, F::ONE);

        // Generate a proof
        let start = Instant::now();
        let proof = data.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();

        // Verify the proof
        let start = Instant::now();
        data.verify(proof).unwrap();
        let verification_time = start.elapsed();

        println!(
            "Batch signature verification (size {}) performance results:",
            batch_size
        );
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }
}
