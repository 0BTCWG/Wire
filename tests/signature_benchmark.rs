#[cfg(test)]
mod signature_benchmark_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use std::time::Instant;
    
    use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget};
    use wire_lib::gadgets::signature::{verify_eddsa_signature, batch_verify_signatures};
    use wire_lib::gadgets::ed25519::is_on_curve;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn test_signature_verification_gates() {
        println!("Measuring signature verification gate count...");
        
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Store the initial gate count
        let initial_gates = builder.num_gates();
        
        // Create virtual targets for the signature components
        let r_x = builder.add_virtual_target();
        let r_y = builder.add_virtual_target();
        let s = builder.add_virtual_target();
        
        let r_point = PointTarget { x: r_x, y: r_y };
        
        // Add curve check for the points to ensure they're valid
        let is_r_on_curve = is_on_curve(&mut builder, &r_point);
        builder.assert_one(is_r_on_curve);
        
        // Create the signature with a clone of r_point
        let signature = SignatureTarget { 
            r_point: PointTarget { x: r_x, y: r_y }, 
            s_scalar: s 
        };
        
        // Create virtual targets for the public key
        let pk_x = builder.add_virtual_target();
        let pk_y = builder.add_virtual_target();
        let pk_point = PointTarget { x: pk_x, y: pk_y };
        
        // Add curve check for the public key
        let is_pk_on_curve = is_on_curve(&mut builder, &pk_point);
        builder.assert_one(is_pk_on_curve);
        
        // Create the public key with a clone of pk_point
        let public_key = PublicKeyTarget { 
            point: PointTarget { x: pk_x, y: pk_y } 
        };
        
        // Create a virtual target for the message hash
        let msg_hash = builder.add_virtual_target();
        
        // Verify the signature
        verify_eddsa_signature(&mut builder, &signature, msg_hash, &public_key);
        
        // Count the gates added
        let gates = builder.num_gates() - initial_gates;
        
        println!("Single signature verification gate count: {}", gates);
        
        // Build the circuit
        let start = Instant::now();
        let circuit = builder.build::<C>();
        let circuit_creation_time = start.elapsed();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Assign values to the virtual targets
        // Using valid curve points for Ed25519
        pw.set_target(r_x, F::from_canonical_u64(4));  // Example x-coordinate on curve
        pw.set_target(r_y, F::from_canonical_u64(5));  // Example y-coordinate on curve
        pw.set_target(s, F::from_canonical_u64(1));    // Example scalar
        pw.set_target(pk_x, F::from_canonical_u64(4)); // Example x-coordinate on curve
        pw.set_target(pk_y, F::from_canonical_u64(5)); // Example y-coordinate on curve
        pw.set_target(msg_hash, F::from_canonical_u64(123)); // Example message hash
        
        // Generate a proof
        let start = Instant::now();
        let proof = circuit.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();
        
        // Verify the proof
        let start = Instant::now();
        circuit.verify(proof).unwrap();
        let verification_time = start.elapsed();
        
        println!("Signature verification benchmark results:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }
    
    #[test]
    fn test_batch_signature_verification_gates() {
        // Test with different batch sizes
        let batch_sizes = [2, 4];
        
        for &batch_size in &batch_sizes {
            println!("Measuring batch signature verification gate count for batch size {}...", batch_size);
            
            // Create a circuit
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Store the initial gate count
            let initial_gates = builder.num_gates();
            
            // Create virtual targets for the signatures, message hashes, and public keys
            let mut signatures = Vec::with_capacity(batch_size);
            let mut message_hashes = Vec::with_capacity(batch_size);
            let mut public_keys = Vec::with_capacity(batch_size);
            
            // Keep track of targets for witness assignment
            let mut r_xs = Vec::with_capacity(batch_size);
            let mut r_ys = Vec::with_capacity(batch_size);
            let mut ss = Vec::with_capacity(batch_size);
            let mut pk_xs = Vec::with_capacity(batch_size);
            let mut pk_ys = Vec::with_capacity(batch_size);
            let mut msg_hashes_targets = Vec::with_capacity(batch_size);
            
            for _ in 0..batch_size {
                let r_x = builder.add_virtual_target();
                let r_y = builder.add_virtual_target();
                let s = builder.add_virtual_target();
                
                r_xs.push(r_x);
                r_ys.push(r_y);
                ss.push(s);
                
                let r_point = PointTarget { x: r_x, y: r_y };
                
                // Add curve check for the points to ensure they're valid
                let is_r_on_curve = is_on_curve(&mut builder, &r_point);
                builder.assert_one(is_r_on_curve);
                
                // Create signature with new point target
                let signature = SignatureTarget { 
                    r_point: PointTarget { x: r_x, y: r_y }, 
                    s_scalar: s 
                };
                signatures.push(signature);
                
                let pk_x = builder.add_virtual_target();
                let pk_y = builder.add_virtual_target();
                
                pk_xs.push(pk_x);
                pk_ys.push(pk_y);
                
                let pk_point = PointTarget { x: pk_x, y: pk_y };
                
                // Add curve check for the public key
                let is_pk_on_curve = is_on_curve(&mut builder, &pk_point);
                builder.assert_one(is_pk_on_curve);
                
                // Create public key with new point target
                let public_key = PublicKeyTarget { 
                    point: PointTarget { x: pk_x, y: pk_y } 
                };
                public_keys.push(public_key);
                
                let msg_hash = builder.add_virtual_target();
                msg_hashes_targets.push(msg_hash);
                message_hashes.push(msg_hash);
            }
            
            // Prepare message hashes as Vec<Vec<Target>> for batch verification
            let message_hash_vectors: Vec<Vec<Target>> = message_hashes.iter().map(|&hash| vec![hash]).collect();
            
            // Verify the batch of signatures
            batch_verify_signatures(&mut builder, &message_hash_vectors, &signatures, &public_keys);
            
            // Count the gates added
            let gates = builder.num_gates() - initial_gates;
            
            println!("Batch signature verification gate count (size {}): {}", batch_size, gates);
            println!("Average gates per signature in batch: {}", gates as f64 / batch_size as f64);
            
            if batch_size == 4 {
                // Only run the full benchmark for batch size 4 to save time
                // Build the circuit
                let start = Instant::now();
                let circuit = builder.build::<C>();
                let circuit_creation_time = start.elapsed();
                
                // Create a partial witness
                let mut pw = PartialWitness::new();
                
                // Assign values to the virtual targets
                for i in 0..batch_size {
                    // Using valid curve points for Ed25519
                    pw.set_target(r_xs[i], F::from_canonical_u64(4));  // Example x-coordinate on curve
                    pw.set_target(r_ys[i], F::from_canonical_u64(5));  // Example y-coordinate on curve
                    pw.set_target(ss[i], F::from_canonical_u64(1));    // Example scalar
                    pw.set_target(pk_xs[i], F::from_canonical_u64(4)); // Example x-coordinate on curve
                    pw.set_target(pk_ys[i], F::from_canonical_u64(5)); // Example y-coordinate on curve
                    pw.set_target(msg_hashes_targets[i], F::from_canonical_u64(100 + i as u64)); // Example message hash
                }
                
                // Generate a proof
                let start = Instant::now();
                let proof = circuit.prove(pw).unwrap();
                let proof_generation_time = start.elapsed();
                
                // Verify the proof
                let start = Instant::now();
                circuit.verify(proof).unwrap();
                let verification_time = start.elapsed();
                
                println!("Batch signature verification (size {}) benchmark results:", batch_size);
                println!("  Circuit creation time: {:?}", circuit_creation_time);
                println!("  Proof generation time: {:?}", proof_generation_time);
                println!("  Proof verification time: {:?}", verification_time);
            }
        }
    }
}
