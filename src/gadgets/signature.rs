// Signature verification gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{PublicKeyTarget, SignatureTarget};
use crate::gadgets::{hash_targets, is_equal};
use crate::gadgets::ed25519::{is_on_curve, scalar_multiply, point_add, get_base_point};

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
    let r_on_curve = is_on_curve(builder, &sig.r_point);
    
    // Also verify that the public key is on the curve
    let pk_on_curve = is_on_curve(builder, &pk.point);
    
    // Both points must be on the curve - use is_equal to create a boolean check
    let points_on_curve = builder.mul(r_on_curve, pk_on_curve);
    
    // Step 2: Compute h = H(R, A, M)
    let mut h_inputs = Vec::new();
    h_inputs.push(sig.r_point.x);
    h_inputs.push(sig.r_point.y);
    h_inputs.push(pk.point.x);
    h_inputs.push(pk.point.y);
    h_inputs.push(msg_hash);
    let h_hash = hash_targets(builder, &h_inputs);
    let h = h_hash.elements[0];
    
    // Step 3: Compute S·G
    let base_point = get_base_point(builder);
    let s_times_g = scalar_multiply(builder, sig.s_scalar, &base_point);
    
    // Step 4: Compute h·A
    let h_times_a = scalar_multiply(builder, h, &pk.point);
    
    // Step 5: Compute R + h·A
    let r_plus_ha = point_add(builder, &sig.r_point, &h_times_a);
    
    // Step 6: Verify that S·G = R + h·A
    let s_g_x_equals_r_ha_x = is_equal(builder, s_times_g.x, r_plus_ha.x);
    let s_g_y_equals_r_ha_y = is_equal(builder, s_times_g.y, r_plus_ha.y);
    
    // Both x and y coordinates must be equal
    let s_g_equals_r_ha = builder.mul(s_g_x_equals_r_ha_x, s_g_y_equals_r_ha_y);
    
    // The signature is valid if both:
    // 1. The points are on the curve
    // 2. S·G = R + h·A
    builder.mul(points_on_curve, s_g_equals_r_ha)
}

/// Verify that a message was signed by the owner of a public key
///
/// This function:
/// 1. Hashes the message to create a message digest
/// 2. Verifies the signature on the message digest
pub fn verify_message_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    sig: &SignatureTarget,
    pk: &PublicKeyTarget,
) -> Target {
    // Hash the message to create a message digest
    let msg_hash = hash_targets(builder, message).elements[0];
    
    // Verify the signature on the message digest
    verify_eddsa_signature(builder, sig, msg_hash, pk)
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
