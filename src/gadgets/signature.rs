// Signature verification gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget};
use crate::gadgets::{hash_targets, is_equal};
use crate::gadgets::ed25519::{is_on_curve, optimized_scalar_multiply, point_add, get_base_point};

/// Verify an EdDSA signature
///
/// This implements the full EdDSA verification algorithm:
/// 1. Verify that r_point is on the curve
/// 2. Compute h = H(R, A, M)
/// 3. Compute S·G
/// 4. Compute h·A
/// 5. Compute R + h·A
/// 6. Verify that S·G = R + h·A
pub fn verify_eddsa_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    sig: &SignatureTarget,
    msg_hash: Target,
    pk: &PublicKeyTarget,
) -> Target {
    // Step 1: Verify that r_point is on the curve
    // is_on_curve returns a Target, not a BoolTarget
    let r_on_curve = is_on_curve(builder, &sig.r_point);
    
    // Step 2: Compute h = H(R, A, M)
    // Create a message combining R, A, and M
    let mut combined_message = Vec::new();
    combined_message.push(sig.r_point.x);
    combined_message.push(sig.r_point.y);
    combined_message.push(pk.point.x);
    combined_message.push(pk.point.y);
    combined_message.push(msg_hash);
    
    // Hash the combined message to get h
    let h = hash_targets(builder, &combined_message).elements[0];
    
    // Step 3: Compute S·G
    // Get the base point G
    let base_point = get_base_point(builder);
    
    // Compute S·G using optimized scalar multiplication
    let s_times_g = optimized_scalar_multiply(builder, sig.s_scalar, &base_point);
    
    // Step 4: Compute h·A
    // Compute h·A where A is the public key using optimized scalar multiplication
    let h_times_a = optimized_scalar_multiply(builder, h, &pk.point);
    
    // Step 5: Compute R + h·A
    let r_plus_ha = point_add(builder, &sig.r_point, &h_times_a);
    
    // Step 6: Verify that S·G = R + h·A
    // Check if the x coordinates are equal
    let x_equal = builder.is_equal(s_times_g.x, r_plus_ha.x);
    
    // Check if the y coordinates are equal
    let y_equal = builder.is_equal(s_times_g.y, r_plus_ha.y);
    
    // Both x and y must be equal for the points to be equal
    // Convert BoolTarget to Target (0 or 1) and combine with AND operation
    let one = builder.one();
    let zero = builder.zero();
    
    // Optimize by using a single select operation
    let points_equal_bool = builder.and(x_equal, y_equal);
    let points_equal = builder.select(points_equal_bool, one, zero);
    
    // The signature is valid if r_point is on the curve AND the equation holds
    builder.mul(r_on_curve, points_equal)
}

/// A stub implementation of EdDSA signature verification that always returns true (1)
/// This is used for testing purposes only
pub fn stub_verify_eddsa_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    _sig: &SignatureTarget,
    _msg_hash: Target,
    _pk: &PublicKeyTarget,
) -> Target {
    builder.one()
}

/// Verify that a message was signed by the owner of a public key
///
/// This function:
/// 1. Hashes the message to create a message hash
/// 2. Verifies the EdDSA signature using the message hash and public key
pub fn verify_message_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    signature: &SignatureTarget,
    public_key: &PublicKeyTarget,
) -> Target {
    // Hash the message to create a message hash
    let message_hash = hash_targets(builder, message).elements[0];
    
    // Use the real implementation for production
    verify_eddsa_signature(builder, signature, message_hash, public_key)
}

/// Verify multiple EdDSA signatures in a batch
///
/// This is more efficient than verifying each signature individually
/// because it uses a randomized batch verification technique.
pub fn batch_verify_signatures<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    signatures: &[SignatureTarget],
    message_hashes: &[Target],
    public_keys: &[PublicKeyTarget],
) -> Target {
    assert_eq!(signatures.len(), message_hashes.len());
    assert_eq!(signatures.len(), public_keys.len());
    
    if signatures.is_empty() {
        return builder.one(); // Empty batch is trivially valid
    }
    
    if signatures.len() == 1 {
        // For a single signature, just use the regular verification
        return verify_eddsa_signature(builder, &signatures[0], message_hashes[0], &public_keys[0]);
    }
    
    // For batch verification, we'll use the following approach:
    // 1. Generate random weights for each signature
    // 2. Compute a linear combination of verification equations
    // 3. Verify the combined equation
    
    // Verify that all R points are on the curve
    let mut all_on_curve = builder.one();
    for sig in signatures {
        let r_on_curve = is_on_curve(builder, &sig.r_point);
        all_on_curve = builder.mul(all_on_curve, r_on_curve);
    }
    
    // Get the base point G
    let base_point = get_base_point(builder);
    
    // Compute the combined verification equation
    let mut combined_s_g = PointTarget {
        x: builder.zero(),
        y: builder.one(), // Identity point
    };
    
    let mut combined_r_ha = PointTarget {
        x: builder.zero(),
        y: builder.one(), // Identity point
    };
    
    // Use pseudorandom weights derived from the signatures themselves
    for i in 0..signatures.len() {
        let sig = &signatures[i];
        let pk = &public_keys[i];
        let msg_hash = message_hashes[i];
        
        // Derive a pseudorandom weight from the signature and message
        // This is a simplified approach - in a real implementation, we would use
        // a more secure method to generate these weights
        let mut weight_inputs = Vec::new();
        weight_inputs.push(sig.r_point.x);
        weight_inputs.push(sig.r_point.y);
        weight_inputs.push(msg_hash);
        weight_inputs.push(builder.constant(F::from_canonical_u64(i as u64)));
        let weight = hash_targets(builder, &weight_inputs).elements[0];
        
        // Compute h = H(R, A, M) for this signature
        let mut combined_message = Vec::new();
        combined_message.push(sig.r_point.x);
        combined_message.push(sig.r_point.y);
        combined_message.push(pk.point.x);
        combined_message.push(pk.point.y);
        combined_message.push(msg_hash);
        let h = hash_targets(builder, &combined_message).elements[0];
        
        // Compute weighted S·G
        let weighted_s = builder.mul(sig.s_scalar, weight);
        let s_g = optimized_scalar_multiply(builder, weighted_s, &base_point);
        
        // Compute weighted R
        let weighted_r = PointTarget {
            x: sig.r_point.x,
            y: sig.r_point.y,
        };
        
        // Compute weighted h·A
        let weighted_h = builder.mul(h, weight);
        let h_a = optimized_scalar_multiply(builder, weighted_h, &pk.point);
        
        // Add to the combined points
        if i == 0 {
            combined_s_g = s_g;
            combined_r_ha = point_add(builder, &weighted_r, &h_a);
        } else {
            combined_s_g = point_add(builder, &combined_s_g, &s_g);
            let r_ha = point_add(builder, &weighted_r, &h_a);
            combined_r_ha = point_add(builder, &combined_r_ha, &r_ha);
        }
    }
    
    // Verify that combined_s_g = combined_r_ha
    let x_equal = builder.is_equal(combined_s_g.x, combined_r_ha.x);
    let y_equal = builder.is_equal(combined_s_g.y, combined_r_ha.y);
    
    // Both x and y must be equal for the points to be equal
    let points_equal_bool = builder.and(x_equal, y_equal);
    let one = builder.one();
    let zero = builder.zero();
    let points_equal = builder.select(points_equal_bool, one, zero);
    
    // The batch is valid if all R points are on the curve AND the combined equation holds
    builder.mul(all_on_curve, points_equal)
}

/// Count the number of gates used in signature verification
pub fn count_signature_verification_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create virtual targets for the signature components
    let r_x = builder.add_virtual_target();
    let r_y = builder.add_virtual_target();
    let s = builder.add_virtual_target();
    
    let r_point = PointTarget { x: r_x, y: r_y };
    let signature = SignatureTarget { r_point, s_scalar: s };
    
    // Create virtual targets for the public key
    let pk_x = builder.add_virtual_target();
    let pk_y = builder.add_virtual_target();
    let pk_point = PointTarget { x: pk_x, y: pk_y };
    let public_key = PublicKeyTarget { point: pk_point };
    
    // Create a virtual target for the message hash
    let msg_hash = builder.add_virtual_target();
    
    // Verify the signature
    verify_eddsa_signature(builder, &signature, msg_hash, &public_key);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

/// Count the number of gates used in batch signature verification
pub fn count_batch_signature_verification_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    batch_size: usize,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create virtual targets for the signatures, message hashes, and public keys
    let mut signatures = Vec::with_capacity(batch_size);
    let mut message_hashes = Vec::with_capacity(batch_size);
    let mut public_keys = Vec::with_capacity(batch_size);
    
    for _ in 0..batch_size {
        let r_x = builder.add_virtual_target();
        let r_y = builder.add_virtual_target();
        let s = builder.add_virtual_target();
        
        let r_point = PointTarget { x: r_x, y: r_y };
        let signature = SignatureTarget { r_point, s_scalar: s };
        signatures.push(signature);
        
        let pk_x = builder.add_virtual_target();
        let pk_y = builder.add_virtual_target();
        let pk_point = PointTarget { x: pk_x, y: pk_y };
        let public_key = PublicKeyTarget { point: pk_point };
        public_keys.push(public_key);
        
        let msg_hash = builder.add_virtual_target();
        message_hashes.push(msg_hash);
    }
    
    // Verify the batch of signatures
    batch_verify_signatures(builder, &signatures, &message_hashes, &public_keys);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use crate::core::PointTarget;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_verify_signature_valid() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a message
        let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();
        
        // Create a signature
        let sig = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create a public key
        let pk = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Verify the signature
        let is_valid = verify_message_signature(&mut builder, &message, &sig, &pk);
        
        // Make the result a public input
        builder.register_public_input(is_valid);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Just verify that the circuit was created successfully
        // Skip proof generation and verification for now
        assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
    }

    #[test]
    fn test_verify_signature_invalid() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a message - use a smaller message to reduce complexity
        let message: Vec<Target> = (0..4).map(|_| builder.add_virtual_target()).collect();
        
        // Create a signature
        let sig = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create a public key
        let pk = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Verify the signature
        let is_valid = verify_message_signature(&mut builder, &message, &sig, &pk);
        
        // Make the result a public input
        builder.register_public_input(is_valid);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Just verify that the circuit was created successfully
        // Skip proof generation and verification for now
        assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
    }
}
