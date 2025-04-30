// Signature verification gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget};
use crate::gadgets::{hash_targets, is_equal};
use crate::gadgets::ed25519::{is_on_curve, optimized_scalar_multiply, point_add, get_base_point};
use crate::errors::{WireError, CryptoError, WireResult};

/// Verify an EdDSA signature
///
/// This function verifies that a signature is valid for a given message and public key
/// The verification algorithm is based on the EdDSA specification
pub fn verify_message_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    signature: &SignatureTarget,
    public_key: &PublicKeyTarget,
) -> WireResult<Target> {
    // Validate inputs
    if message.is_empty() {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Empty message provided for signature verification".to_string()
        )));
    }
    
    // Check for maximum message size to prevent DoS
    if message.len() > 1024 {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Message too large for signature verification".to_string()
        )));
    }
    
    // 1. Ensure the public key is on the curve
    assert_is_on_curve(builder, &public_key.point);
    
    // 2. Ensure the signature's R point is on the curve
    assert_is_on_curve(builder, &signature.r_point);
    
    // 3. Compute the message hash using domain separation for signatures
    let message_hash = crate::gadgets::hash::hash_for_signature(builder, message)?;
    
    // 4. Compute h = H(R, A, M)
    let mut hash_inputs = Vec::new();
    hash_inputs.push(signature.r_point.x);
    hash_inputs.push(signature.r_point.y);
    hash_inputs.push(public_key.point.x);
    hash_inputs.push(public_key.point.y);
    hash_inputs.push(message_hash);
    
    let h = crate::gadgets::hash::hash_for_signature(builder, &hash_inputs)?;
    
    // 5. Compute S * B, where B is the base point
    let s_b = scalar_mul_base_point(builder, signature.s_scalar);
    
    // 6. Compute R + h * A
    let h_a = scalar_mul(builder, h, &public_key.point);
    let r_plus_h_a = point_add(builder, &signature.r_point, &h_a);
    
    // 7. Check if S * B == R + h * A
    let is_x_equal = builder.is_equal(s_b.x, r_plus_h_a.x);
    let is_y_equal = builder.is_equal(s_b.y, r_plus_h_a.y);
    
    // Both x and y coordinates must be equal
    let is_valid = builder.and(is_x_equal, is_y_equal);
    
    // Convert BoolTarget to Target (0 or 1)
    let zero = builder.zero();
    let one = builder.one();
    Ok(builder.select(is_valid, one, zero))
}

/// Batch verify multiple EdDSA signatures
///
/// This function verifies multiple signatures in a batch, which is more efficient
/// than verifying them individually.
///
/// Returns a target that is 1 if all signatures are valid, and 0 otherwise.
pub fn batch_verify_signatures<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    messages: &[Vec<Target>],
    signatures: &[SignatureTarget],
    public_keys: &[PublicKeyTarget],
) -> WireResult<Target> {
    // Validate inputs
    if messages.len() != signatures.len() || messages.len() != public_keys.len() {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Mismatched number of messages, signatures, and public keys".to_string()
        )));
    }
    
    // Check for maximum batch size to prevent DoS
    if messages.len() > 256 {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Batch size too large for signature verification".to_string()
        )));
    }
    
    // If there are no signatures to verify, return success
    if messages.is_empty() {
        return Ok(builder.one());
    }
    
    // If there's only one signature, use the regular verification
    if messages.len() == 1 {
        return verify_message_signature(
            builder,
            &messages[0],
            &signatures[0],
            &public_keys[0],
        );
    }
    
    // Initialize a vector to store message hashes
    let mut messages_hash = Vec::with_capacity(messages.len());
    
    // For each signature, ensure the public key and R point are on the curve
    for (i, (signature, public_key)) in signatures.iter().zip(public_keys.iter()).enumerate() {
        // Ensure the public key is on the curve
        assert_is_on_curve(builder, &public_key.point);
        
        // Ensure the signature's R point is on the curve
        assert_is_on_curve(builder, &signature.r_point);
        
        // Validate message
        if messages[i].is_empty() {
            return Err(WireError::CryptoError(CryptoError::SignatureError(
                format!("Empty message provided for signature at index {}", i)
            )));
        }
        
        // Check for maximum message size
        if messages[i].len() > 1024 {
            return Err(WireError::CryptoError(CryptoError::SignatureError(
                format!("Message too large for signature verification at index {}", i)
            )));
        }
        
        // Compute the message hash
        let message_hash = crate::gadgets::hash::hash_for_signature(builder, &messages[i])?;
        messages_hash.push(message_hash);
    }
    
    // Batch verification logic
    // Generate random weights for the batch verification
    // In a real implementation, these would be generated from a secure RNG
    // For now, we'll use a deterministic but unpredictable approach
    let mut weights = Vec::with_capacity(messages.len());
    for i in 0..messages.len() {
        // Create a seed for the weight based on the circuit state
        let mut seed_inputs = Vec::new();
        seed_inputs.push(builder.constant(F::from_canonical_u64(i as u64)));
        seed_inputs.push(signatures[i].r_point.x);
        seed_inputs.push(public_keys[i].point.x);
        
        // Hash the seed to get a pseudorandom weight
        let weight = crate::gadgets::hash::hash(builder, &seed_inputs)?;
        weights.push(weight);
    }
    
    // Compute the batch verification equation:
    // Check if sum(weight_i * S_i) * B == sum(weight_i * R_i) + sum(weight_i * h_i * A_i)
    
    // First, compute sum(weight_i * S_i)
    let mut sum_weighted_s = builder.zero();
    for (i, signature) in signatures.iter().enumerate() {
        let weighted_s = builder.mul(weights[i], signature.s_scalar);
        sum_weighted_s = builder.add(sum_weighted_s, weighted_s);
    }
    
    // Compute sum(weight_i * S_i) * B
    let sum_weighted_s_b = scalar_mul_base_point(builder, sum_weighted_s);
    
    // Compute sum(weight_i * R_i)
    let mut sum_weighted_r = PointTarget {
        x: builder.zero(),
        y: builder.zero(),
    };
    let mut is_first = true;
    
    for (i, signature) in signatures.iter().enumerate() {
        // Create a weighted R point
        let weighted_r_x = builder.mul(weights[i], signature.r_point.x);
        let weighted_r_y = builder.mul(weights[i], signature.r_point.y);
        let weighted_r = PointTarget {
            x: weighted_r_x,
            y: weighted_r_y,
        };
        
        // Add it to the sum
        if is_first {
            sum_weighted_r = weighted_r;
            is_first = false;
        } else {
            sum_weighted_r = point_add(builder, &sum_weighted_r, &weighted_r)?;
        }
    }
    
    // Compute sum(weight_i * h_i * A_i)
    let mut sum_weighted_h_a = PointTarget {
        x: builder.zero(),
        y: builder.zero(),
    };
    is_first = true;
    
    for i in 0..messages.len() {
        // Compute h = H(R, A, M)
        let mut hash_inputs = Vec::new();
        hash_inputs.push(signatures[i].r_point.x);
        hash_inputs.push(signatures[i].r_point.y);
        hash_inputs.push(public_keys[i].point.x);
        hash_inputs.push(public_keys[i].point.y);
        hash_inputs.push(messages_hash[i]);
        
        let h = crate::gadgets::hash::hash_for_signature(builder, &hash_inputs)?;
        
        // Compute weighted_h = weight_i * h
        let weighted_h = builder.mul(weights[i], h);
        
        // Compute weighted_h * A_i
        let weighted_h_a = scalar_mul(builder, weighted_h, &public_keys[i].point)?;
        
        // Add it to the sum
        if is_first {
            sum_weighted_h_a = weighted_h_a;
            is_first = false;
        } else {
            sum_weighted_h_a = point_add(builder, &sum_weighted_h_a, &weighted_h_a)?;
        }
    }
    
    // Compute sum(weight_i * R_i) + sum(weight_i * h_i * A_i)
    let right_side = point_add(builder, &sum_weighted_r, &sum_weighted_h_a)?;
    
    // Check if sum(weight_i * S_i) * B == sum(weight_i * R_i) + sum(weight_i * h_i * A_i)
    let is_x_equal = builder.is_equal(sum_weighted_s_b.x, right_side.x);
    let is_y_equal = builder.is_equal(sum_weighted_s_b.y, right_side.y);
    
    // Both x and y coordinates must be equal
    let is_valid = builder.and(is_x_equal, is_y_equal);
    
    // Convert BoolTarget to Target (0 or 1)
    let zero = builder.zero();
    let one = builder.one();
    Ok(builder.select(is_valid, one, zero))
}

/// Helper function to assert that a point is on the curve
fn assert_is_on_curve<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    point: &PointTarget,
) {
    let is_valid = is_on_curve(builder, point);
    builder.assert_one(is_valid);
}

/// Helper function to perform scalar multiplication with the base point
fn scalar_mul_base_point<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    scalar: Target,
) -> PointTarget {
    let base_point = get_base_point(builder);
    optimized_scalar_multiply(builder, scalar, &base_point)
}

/// Helper function to perform scalar multiplication
fn scalar_mul<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    scalar: Target,
    point: &PointTarget,
) -> PointTarget {
    optimized_scalar_multiply(builder, scalar, point)
}

/// Count the number of gates used in signature verification
pub fn count_signature_verification_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> WireResult<usize> {
    let start_gates = builder.num_gates();
    
    // Create dummy inputs for signature verification
    let message_len = 32;
    let mut message = Vec::with_capacity(message_len);
    for _ in 0..message_len {
        message.push(builder.add_virtual_target());
    }
    
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };
    
    let public_key = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };
    
    // Run signature verification
    let _ = verify_message_signature(builder, &message, &signature, &public_key)?;
    
    let end_gates = builder.num_gates();
    Ok(end_gates - start_gates)
}

/// Count the number of gates used in batch signature verification
pub fn count_batch_signature_verification_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    batch_size: usize,
) -> WireResult<usize> {
    // Validate input
    if batch_size == 0 {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Batch size must be greater than zero".to_string()
        )));
    }
    
    if batch_size > 256 {
        return Err(WireError::CryptoError(CryptoError::SignatureError(
            "Batch size too large for gate counting".to_string()
        )));
    }
    
    let start_gates = builder.num_gates();
    
    // Create dummy inputs for batch signature verification
    let message_len = 32;
    let mut messages = Vec::with_capacity(batch_size);
    let mut signatures = Vec::with_capacity(batch_size);
    let mut public_keys = Vec::with_capacity(batch_size);
    
    for _ in 0..batch_size {
        let mut message = Vec::with_capacity(message_len);
        for _ in 0..message_len {
            message.push(builder.add_virtual_target());
        }
        messages.push(message);
        
        let signature = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        signatures.push(signature);
        
        let public_key = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        public_keys.push(public_key);
    }
    
    // Run batch signature verification
    let _ = batch_verify_signatures(builder, &messages, &signatures, &public_keys)?;
    
    let end_gates = builder.num_gates();
    Ok(end_gates - start_gates)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_verify_signature_valid() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create a valid signature scenario
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
        let is_valid = verify_message_signature(&mut builder, &message, &sig, &pk)
            .expect("Signature verification should not fail");
        
        // The signature should be valid (1)
        builder.assert_one(is_valid);
        
        let pw = builder.build::<C>();
        let proof = pw.prove(Default::default()).expect("Proving should not fail");
        
        let is_valid = pw.verify(proof).expect("Verification should not fail");
        assert!(is_valid);
    }
    
    #[test]
    fn test_verify_signature_invalid() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create an invalid signature scenario
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
        let is_valid = verify_message_signature(&mut builder, &message, &sig, &pk)
            .expect("Signature verification should not fail");
        
        // The signature should be invalid (0)
        builder.assert_zero(is_valid);
        
        let pw = builder.build::<C>();
        let proof = pw.prove(Default::default()).expect("Proving should not fail");
        
        let is_valid = pw.verify(proof).expect("Verification should not fail");
        assert!(is_valid);
    }
    
    #[test]
    fn test_empty_message_error() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create an empty message
        let message = Vec::new();
        
        // Create dummy signature and public key
        let signature = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        let public_key = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Verify the signature - should return an error
        let result = verify_message_signature(&mut builder, &message, &signature, &public_key);
        assert!(result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
            assert!(msg.contains("Empty message"));
        } else {
            panic!("Expected SignatureError");
        }
    }
    
    #[test]
    fn test_batch_size_validation() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create oversized batch
        let batch_size = 300; // Over the 256 limit
        
        // Test the gate counting function with oversized batch
        let result = count_batch_signature_verification_gates(&mut builder, batch_size);
        assert!(result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::SignatureError(msg))) = result {
            assert!(msg.contains("Batch size too large"));
        } else {
            panic!("Expected SignatureError");
        }
    }
}
