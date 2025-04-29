#[cfg(test)]
mod benchmark_tests {
    use std::time::Instant;
    
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::hash::poseidon::PoseidonHash;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget};
    use wire_lib::gadgets::hash;
    use wire_lib::gadgets::ed25519;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn benchmark_hash_gadget() {
        println!("Benchmarking hash gadget...");
        
        // Create a circuit with a hash operation
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a target to hash
        let target = builder.add_virtual_target();
        
        // Hash the target using our optimized hash function
        let hash_result = hash::hash_single(&mut builder, target);
        
        // Register the hash as a public input
        builder.register_public_input(hash_result);
        
        // Build the circuit
        let start = Instant::now();
        let circuit = builder.build::<C>();
        let circuit_creation_time = start.elapsed();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(target, F::from_canonical_u64(123));
        
        // Generate a proof
        let start = Instant::now();
        let proof = circuit.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();
        
        // Verify the proof
        let start = Instant::now();
        circuit.verify(proof).unwrap();
        let verification_time = start.elapsed();
        
        println!("Hash gadget benchmark results:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }
    
    #[test]
    fn benchmark_scalar_multiply() {
        println!("Benchmarking scalar multiplication...");
        
        // Create a circuit with a scalar multiplication operation
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a scalar and a point
        let scalar = builder.add_virtual_target();
        let point = PointTarget::add_virtual(&mut builder);
        
        // Perform scalar multiplication
        let result = ed25519::scalar_multiply(&mut builder, scalar, &point);
        
        // Register the result as a public input
        builder.register_public_input(result.x);
        builder.register_public_input(result.y);
        
        // Build the circuit
        let start = Instant::now();
        let circuit = builder.build::<C>();
        let circuit_creation_time = start.elapsed();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(scalar, F::from_canonical_u64(123));
        pw.set_target(point.x, F::from_canonical_u64(456));
        pw.set_target(point.y, F::from_canonical_u64(789));
        
        // Generate a proof
        let start = Instant::now();
        let proof = circuit.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();
        
        // Verify the proof
        let start = Instant::now();
        circuit.verify(proof).unwrap();
        let verification_time = start.elapsed();
        
        println!("Scalar multiplication benchmark results:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }
    
    #[test]
    fn benchmark_compare_optimizations() {
        // Run both benchmarks to compare their performance
        benchmark_hash_gadget();
        benchmark_scalar_multiply();
    }
}
