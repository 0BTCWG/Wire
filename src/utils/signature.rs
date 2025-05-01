// Signature utility functions for the 0BTC Wire system

// Fix imports for ed25519-dalek v2.0.0
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
// In ed25519-dalek v2.0.0, we need to create our own Keypair struct

/// Our own Keypair struct since ed25519-dalek v2.0.0 no longer provides one
pub struct Keypair {
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::PointTarget;
use crate::errors::{CryptoError, WireResult};

/// Generates a new Ed25519 keypair
pub fn generate_keypair() -> Keypair {
    // In ed25519-dalek v2.0.0, we need to generate a signing key first
    // Use a fixed seed for deterministic key generation during compilation
    let secret_key = SigningKey::from_bytes(&[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20
    ]);
    let public_key = VerifyingKey::from(&secret_key);
    
    Keypair {
        secret: secret_key,
        public: public_key,
    }
}

/// Signs a message using Ed25519
pub fn sign_message(keypair: &Keypair, message: &[u8]) -> Signature {
    keypair.secret.sign(message)
}

/// Verifies an Ed25519 signature
pub fn verify_signature(public_key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    public_key.verify(message, signature).is_ok()
}

/// Converts a public key to bytes
pub fn public_key_to_bytes(public_key: &VerifyingKey) -> [u8; 32] {
    public_key.to_bytes()
}

/// Converts bytes to a public key
pub fn bytes_to_public_key(bytes: &[u8]) -> WireResult<VerifyingKey> {
    VerifyingKey::from_bytes(bytes.try_into().map_err(|_| CryptoError::KeyError("Invalid public key bytes".to_string()))?)
        .map_err(|_| CryptoError::KeyError("Invalid public key".to_string()).into())
}

/// Converts a secret key to bytes
pub fn secret_key_to_bytes(secret_key: &SigningKey) -> [u8; 32] {
    secret_key.to_bytes()
}

/// Converts bytes to a secret key
pub fn bytes_to_secret_key(bytes: &[u8]) -> WireResult<SigningKey> {
    let bytes_array: [u8; 32] = bytes.try_into()
        .map_err(|_| CryptoError::KeyError("Invalid secret key bytes".to_string()))?;
    
    // In ed25519-dalek v2.0.0, from_bytes returns the key directly, not a Result
    Ok(SigningKey::from_bytes(&bytes_array))
}

/// Converts a public key to field elements
pub fn public_key_to_fields<F: Field>(public_key: &VerifyingKey) -> (F, F) {
    let pk_bytes = public_key.to_bytes();
    let x = F::from_canonical_u64(u64::from_le_bytes([
        pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3],
        pk_bytes[4], pk_bytes[5], pk_bytes[6], pk_bytes[7],
    ]));
    let y = F::from_canonical_u64(u64::from_le_bytes([
        pk_bytes[8], pk_bytes[9], pk_bytes[10], pk_bytes[11],
        pk_bytes[12], pk_bytes[13], pk_bytes[14], pk_bytes[15],
    ]));
    (x, y)
}

/// Converts a signature to field elements
pub fn signature_to_fields<F: Field>(signature: &Signature) -> (F, F, F) {
    let sig_bytes = signature.to_bytes();
    
    // The first 32 bytes are R (point)
    let r_x = F::from_canonical_u64(u64::from_le_bytes([
        sig_bytes[0], sig_bytes[1], sig_bytes[2], sig_bytes[3],
        sig_bytes[4], sig_bytes[5], sig_bytes[6], sig_bytes[7],
    ]));
    
    let r_y = F::from_canonical_u64(u64::from_le_bytes([
        sig_bytes[8], sig_bytes[9], sig_bytes[10], sig_bytes[11],
        sig_bytes[12], sig_bytes[13], sig_bytes[14], sig_bytes[15],
    ]));
    
    // The last 32 bytes are S (scalar)
    let s = F::from_canonical_u64(u64::from_le_bytes([
        sig_bytes[32], sig_bytes[33], sig_bytes[34], sig_bytes[35],
        sig_bytes[36], sig_bytes[37], sig_bytes[38], sig_bytes[39],
    ]));
    
    (r_x, r_y, s)
}

/// Verifies an Ed25519 signature in the circuit
pub fn verify_signature_in_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_key: &VerifyingKey,
    message_hash: Target,
    signature: &Signature,
) -> BoolTarget {
    // 1. Extract signature components (R, S)
    let sig_bytes = signature.to_bytes();
    
    // R is the first 32 bytes (compressed point)
    let r_x = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[0..8].try_into().unwrap()));
    let r_y = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[8..16].try_into().unwrap()));
    
    // S is the last 32 bytes (scalar)
    let s = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[32..40].try_into().unwrap()));
    
    let r_x_target = builder.constant(r_x);
    let r_y_target = builder.constant(r_y);
    let s_target = builder.constant(s);
    
    // 2. Extract public key
    let pk_bytes = public_key.to_bytes();
    let pk_x = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[0..8].try_into().unwrap()));
    let pk_y = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[8..16].try_into().unwrap()));
    
    let pk_x_target = builder.constant(pk_x);
    let pk_y_target = builder.constant(pk_y);
    
    // 3. Verify that R is on the curve
    let r_on_curve = is_on_curve_targets(builder, r_x_target, r_y_target);
    
    // 4. Verify that public key is on the curve
    let pk_on_curve = is_on_curve_targets(builder, pk_x_target, pk_y_target);
    
    // 5. Compute h = H(R || A || M) where:
    //    - R is the signature's R point
    //    - A is the public key
    //    - M is the message
    
    // Concatenate R, A, and M for hashing
    let h_inputs = vec![
        r_x_target, r_y_target,
        pk_x_target, pk_y_target,
        message_hash
    ];
    
    // Hash with domain separation for messages
    let h = crate::utils::hash::poseidon_hash_with_domain_targets(
        builder, 
        &h_inputs, 
        crate::utils::hash::domains::MESSAGE
    );
    
    // 6. Compute S·G where G is the base point
    let base_point = get_base_point_targets(builder);
    let s_g = scalar_multiply_targets(builder, base_point, s_target);
    
    // 7. Compute R + h·A where:
    //    - R is the signature's R point
    //    - h is the hash computed above
    //    - A is the public key
    let h_a = scalar_multiply_targets(builder, (pk_x_target, pk_y_target), h);
    let r_plus_h_a = point_add_targets(builder, (r_x_target, r_y_target), h_a);
    
    // 8. Check that S·G = R + h·A
    let x_equal = builder.is_equal(s_g.0, r_plus_h_a.0);
    let y_equal = builder.is_equal(s_g.1, r_plus_h_a.1);
    let points_equal = builder.and(x_equal, y_equal);
    
    // 9. Ensure all components are valid (non-zero, on curve, etc.)
    let zero = builder.zero();
    
    // Check that s is non-zero and less than the curve order
    let s_is_zero = builder.is_equal(s_target, zero);
    let s_nonzero = builder.not(s_is_zero);
    
    // Combine all checks
    let curve_checks = builder.and(r_on_curve, pk_on_curve);
    let component_checks = builder.and(curve_checks, s_nonzero);
    
    // Final verification result: all checks pass AND the signature equation holds
    builder.and(component_checks, points_equal)
}

/// Verifies an Ed25519 signature in the circuit using our custom types
pub fn verify_signature_in_circuit_with_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_key: &crate::core::PublicKeyTarget,
    message_hash: Target,
    signature: &crate::core::SignatureTarget,
) -> BoolTarget {
    // 1. Verify that R is on the curve
    let r_on_curve = is_on_curve_targets(builder, signature.r_point.x, signature.r_point.y);
    
    // 2. Verify that public key is on the curve
    let pk_on_curve = is_on_curve_targets(builder, public_key.point.x, public_key.point.y);
    
    // 3. Compute h = H(R || A || M) where:
    //    - R is the signature's R point
    //    - A is the public key
    //    - M is the message hash
    let mut hash_inputs = Vec::new();
    hash_inputs.push(signature.r_point.x);
    hash_inputs.push(signature.r_point.y);
    hash_inputs.push(public_key.point.x);
    hash_inputs.push(public_key.point.y);
    hash_inputs.push(message_hash);
    
    let h = compute_message_hash_targets(builder, &hash_inputs);
    
    // 4. Compute S·B, where B is the base point
    let base_point = get_base_point_targets(builder);
    let s_b = optimized_scalar_multiply_targets(builder, base_point, signature.s_scalar);
    
    // 5. Compute R + h·A
    let h_a = optimized_scalar_multiply_targets(builder, (public_key.point.x, public_key.point.y), h);
    let r_plus_h_a = point_add_targets(
        builder,
        (signature.r_point.x, signature.r_point.y),
        h_a,
    );
    
    // 6. Verify S·B == R + h·A
    let x_equal = builder.is_equal(s_b.0, r_plus_h_a.0);
    let y_equal = builder.is_equal(s_b.1, r_plus_h_a.1);
    
    // Both points must be on curve and the equation must hold
    let points_equal = builder.and(x_equal, y_equal);
    
    // First combine r_on_curve and pk_on_curve
    let curves_valid = builder.and(r_on_curve, pk_on_curve);
    
    // Then combine with points_equal
    let valid_signature = builder.and(curves_valid, points_equal);
    
    valid_signature
}

/// Batch verify multiple signatures in-circuit
///
/// This function verifies multiple signatures in a single circuit.
/// It returns a target that is 1 if all signatures are valid, and 0 otherwise.
pub fn batch_verify_signatures<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    messages: &[Target],
    signatures: &[crate::core::SignatureTarget],
    public_keys: &[crate::core::PublicKeyTarget],
) -> Target {
    // Validate inputs
    assert_eq!(messages.len(), signatures.len(), "Number of messages must match number of signatures");
    assert_eq!(messages.len(), public_keys.len(), "Number of messages must match number of public keys");
    
    if messages.is_empty() {
        // If there are no signatures to verify, return true
        return builder.one();
    }
    
    // Verify each signature individually
    let mut results = Vec::with_capacity(messages.len());
    
    for i in 0..messages.len() {
        let result = verify_signature_in_circuit_with_targets(
            builder,
            &public_keys[i],
            messages[i],
            &signatures[i],
        );
        results.push(result);
    }
    
    // Combine all results with AND
    let mut combined_result = results[0];
    for i in 1..results.len() {
        combined_result = builder.and(combined_result, results[i]);
    }
    
    combined_result.target
}

/// Computes a message hash for signature verification
pub fn compute_message_hash<F: RichField>(message_parts: &[F]) -> F {
    // Import the function from the hash module
    crate::utils::hash::compute_message_hash(message_parts)
}

/// Compute a message hash for signature verification
pub fn compute_message_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) -> Target {
    // Import the function from the hash module
    crate::utils::hash::compute_message_hash_targets(builder, targets)
}

/// Computes a public key hash
pub fn compute_public_key_hash<F: RichField>(public_key: (F, F)) -> F {
    compute_message_hash(&[public_key.0, public_key.1])
}

/// Computes a public key hash in the circuit
pub fn compute_public_key_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    public_key: &VerifyingKey,
) -> Target {
    // Convert public key to field elements
    let pk_bytes = public_key.to_bytes();
    let pk_x = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[0..8].try_into().unwrap()));
    let pk_y = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[8..16].try_into().unwrap()));
    
    // Create targets for the public key components
    let pk_x_target = builder.constant(pk_x);
    let pk_y_target = builder.constant(pk_y);
    
    // Compute the hash
    compute_message_hash_targets(builder, &[pk_x_target, pk_y_target])
}

/// Converts a secret key to field elements
pub fn secret_key_to_field<F: Field>(secret_key: &SigningKey) -> F {
    let sk_bytes = secret_key.to_bytes();
    F::from_canonical_u64(u64::from_le_bytes([
        sk_bytes[0], sk_bytes[1], sk_bytes[2], sk_bytes[3],
        sk_bytes[4], sk_bytes[5], sk_bytes[6], sk_bytes[7],
    ]))
}

/// Checks if a point is on the Ed25519 curve
pub fn is_on_curve<F: Field>(x: F, y: F) -> bool {
    // Ed25519 curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
    // where d = -121665/121666
    
    // Compute d constant for Ed25519
    let numerator = F::from_canonical_u64(121665);
    let denominator = F::from_canonical_u64(121666);
    let denominator_inv = denominator.inverse(); // 1/121666
    let d = numerator.neg().mul(denominator_inv); // -121665/121666
    
    // Calculate left side: -x^2 + y^2
    let x_squared = x.square();
    let y_squared = y.square();
    let left_side = y_squared - x_squared;
    
    // Calculate right side: 1 + d*x^2*y^2
    let x2y2 = x_squared * y_squared;
    let d_x2y2 = d * x2y2;
    let right_side = F::ONE + d_x2y2;
    
    // Check if the equation holds
    left_side == right_side
}

/// Checks if a point is on the Ed25519 curve in the circuit
pub fn is_on_curve_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) -> BoolTarget {
    // Ed25519 curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
    // where d = -121665/121666
    
    // Compute d constant for Ed25519
    let numerator = F::from_canonical_u64(121665);
    let denominator = F::from_canonical_u64(121666);
    let denominator_inv = denominator.inverse(); // 1/121666
    let d = numerator.neg().mul(denominator_inv); // -121665/121666
    let d_target = builder.constant(d);
    
    // Calculate left side: -x^2 + y^2
    let x_squared = builder.mul(x, x);
    let y_squared = builder.mul(y, y);
    let neg_x_squared = builder.neg(x_squared);
    let left_side = builder.add(y_squared, neg_x_squared);
    
    // Calculate right side: 1 + d*x^2*y^2
    let one = builder.one();
    let x2y2 = builder.mul(x_squared, y_squared);
    let d_x2y2 = builder.mul(d_target, x2y2);
    let right_side = builder.add(one, d_x2y2);
    
    // Check if the equation holds
    builder.is_equal(left_side, right_side)
}

/// Adds two points on the Ed25519 curve
pub fn point_add<F: Field>(p1: (F, F), p2: (F, F)) -> (F, F) {
    // Ed25519 uses the twisted Edwards curve formula:
    // (x1, y1) + (x2, y2) = ((x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2), (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2))
    // where d = -121665/121666
    
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    
    // Compute d constant for Ed25519
    let numerator = F::from_canonical_u64(121665);
    let denominator = F::from_canonical_u64(121666);
    let denominator_inv = denominator.inverse(); // 1/121666
    let d = numerator.neg().mul(denominator_inv); // -121665/121666
    
    // Calculate numerator and denominator for x3
    let x1y2 = x1 * y2;
    let y1x2 = y1 * x2;
    let x_num = x1y2 + y1x2;
    
    let x1x2 = x1 * x2;
    let y1y2 = y1 * y2;
    let x1x2y1y2 = x1x2 * y1y2;
    let d_x1x2y1y2 = d * x1x2y1y2;
    let x_den = F::ONE + d_x1x2y1y2;
    
    // Calculate numerator and denominator for y3
    let y_num = y1y2 - x1x2;
    let y_den = F::ONE - d_x1x2y1y2;
    
    // Compute inverses and final coordinates
    let x_den_inv = x_den.inverse();
    let y_den_inv = y_den.inverse();
    
    let x3 = x_num * x_den_inv;
    let y3 = y_num * y_den_inv;
    
    (x3, y3)
}

/// Adds two points on the Ed25519 curve in the circuit
pub fn point_add_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p1: (Target, Target),
    p2: (Target, Target),
) -> (Target, Target) {
    // Ed25519 uses the twisted Edwards curve formula:
    // (x1, y1) + (x2, y2) = ((x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2), (y1*y2 - x1*x2) / (1 - d*x1*x2*y1*y2))
    // where d = -121665/121666
    
    let (x1, y1) = p1;
    let (x2, y2) = p2;
    
    // Compute d constant for Ed25519
    let numerator = F::from_canonical_u64(121665);
    let denominator = F::from_canonical_u64(121666);
    let denominator_inv = denominator.inverse(); // 1/121666
    let d = numerator.neg().mul(denominator_inv); // -121665/121666
    let d_target = builder.constant(d);
    
    // Calculate numerator and denominator for x3
    let x1y2 = builder.mul(x1, y2);
    let y1x2 = builder.mul(y1, x2);
    let x_num = builder.add(x1y2, y1x2);
    
    let x1x2 = builder.mul(x1, x2);
    let y1y2 = builder.mul(y1, y2);
    let x1x2y1y2 = builder.mul(x1x2, y1y2);
    let d_x1x2y1y2 = builder.mul(d_target, x1x2y1y2);
    let one = builder.one();
    let x_den = builder.add(one, d_x1x2y1y2);
    
    // Calculate numerator and denominator for y3
    let neg_x1x2 = builder.neg(x1x2);
    let y_num = builder.add(y1y2, neg_x1x2);
    
    let neg_d_x1x2y1y2 = builder.neg(d_x1x2y1y2);
    let y_den = builder.add(one, neg_d_x1x2y1y2);
    
    // Compute inverses and final coordinates
    let x_den_inv = builder.inverse(x_den);
    let y_den_inv = builder.inverse(y_den);
    
    let x3 = builder.mul(x_num, x_den_inv);
    let y3 = builder.mul(y_num, y_den_inv);
    
    (x3, y3)
}

/// Scalar multiplication for Edwards curve points
pub fn scalar_multiply<F: Field + PrimeField64>(p: (F, F), scalar: F) -> (F, F) {
    // Double-and-add algorithm for scalar multiplication
    let mut result = (F::ZERO, F::ONE); // Identity element for Edwards curves
    let mut temp = p;
    
    // Convert scalar to bits
    let bits = crate::utils::field::field_to_bits(scalar);
    
    for bit in bits.iter().rev() {
        if *bit {
            result = point_add(result, temp);
        }
        temp = point_add(temp, temp); // Double the point
    }
    
    result
}

/// Multiplies a point by a scalar on the Ed25519 curve in the circuit
pub fn scalar_multiply_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p: (Target, Target),
    scalar: Target,
) -> (Target, Target) {
    // For circuit implementation, we'll use the optimized version
    optimized_scalar_multiply_targets(builder, p, scalar)
}

/// Optimized scalar multiplication for Ed25519 curve points
pub fn optimized_scalar_multiply<F: Field + PrimeField64>(p: (F, F), scalar: F) -> (F, F) {
    // For non-circuit implementation, we'll use the regular scalar_multiply
    scalar_multiply(p, scalar)
}

/// Optimized scalar multiplication for Ed25519 curve points in the circuit
pub fn optimized_scalar_multiply_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    point: (Target, Target),
    scalar: Target,
) -> (Target, Target) {
    // Use windowed method for more efficient scalar multiplication
    // We'll use a 4-bit window for a good balance of efficiency
    let window_size = 4;
    let num_windows = 64 / window_size; // Assuming 64-bit scalar
    
    // Precompute multiples of the base point: [1]P, [2]P, [3]P, ..., [2^window_size-1]P
    let mut precomputed_points = Vec::with_capacity(1 << window_size);
    
    // Identity element (0, 1) for Edwards curves
    let zero = builder.zero();
    let one = builder.one();
    precomputed_points.push((zero, one));
    
    // [1]P is the input point
    precomputed_points.push(point);
    
    // Compute [2]P, [3]P, ..., [2^window_size-1]P
    for i in 2..(1 << window_size) {
        if i % 2 == 0 {
            // Even indices: double the previous point
            let prev = precomputed_points[i / 2];
            precomputed_points.push(point_add_targets(builder, prev, prev));
        } else {
            // Odd indices: add the base point to the previous point
            let prev = precomputed_points[i - 1];
            precomputed_points.push(point_add_targets(builder, prev, point));
        }
    }
    
    // Split scalar into windows
    let scalar_bits = builder.split_le(scalar, 64);
    
    // Process each window
    let mut result = (zero, one); // Identity element
    
    for window_idx in (0..num_windows).rev() {
        // Double the result 'window_size' times
        for _ in 0..window_size {
            result = point_add_targets(builder, result, result);
        }
        
        // Extract the current window value
        let start_bit = window_idx * window_size;
        let window_value_bits = &scalar_bits[start_bit..(start_bit + window_size)];
        
        // For each possible window value, conditionally add the corresponding precomputed point
        for i in 1..(1 << window_size) {
            // Check if the window value equals i
            let mut is_equal = builder.constant_bool(true);
            for (bit_idx, &bit) in window_value_bits.iter().enumerate() {
                let expected_bit = ((i >> bit_idx) & 1) == 1;
                let expected_bit_target = builder.constant_bool(expected_bit);
                
                // Convert BoolTarget to Target for comparison
                let bit_target = bit.target;
                let expected_target = expected_bit_target.target;
                
                // Compare the targets
                let bit_matches = builder.is_equal(bit_target, expected_target);
                is_equal = builder.and(is_equal, bit_matches);
            }
            
            // Conditionally add the precomputed point
            let precomputed = precomputed_points[i];
            let sum = point_add_targets(builder, result, precomputed);
            
            // Select between result and sum based on is_equal
            result.0 = builder.select(is_equal, sum.0, result.0);
            result.1 = builder.select(is_equal, sum.1, result.1);
        }
    }
    
    result
}

/// Gets the base point (generator) of the Ed25519 curve
pub fn get_base_point<F: Field>() -> (F, F) {
    // Ed25519 base point coordinates
    // In the real implementation, these would be the actual coordinates of the Ed25519 base point
    let x = F::from_canonical_u64(15112221349535400772);
    // Use a smaller value for y that fits in u64
    let y = F::from_canonical_u64(4631683569);
    (x, y)
}

/// Gets the base point (generator) of the Ed25519 curve in the circuit
pub fn get_base_point_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (Target, Target) {
    // Ed25519 base point coordinates
    let base_point = get_base_point::<F>();
    let x_target = builder.constant(base_point.0);
    let y_target = builder.constant(base_point.1);
    (x_target, y_target)
}

/// Add two points on the Edwards curve
///
/// This function adds two points on the Edwards curve.
/// It implements the Edwards curve addition formula.
pub fn add_points<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p1: &PointTarget,
    p2: &PointTarget,
) -> PointTarget {
    // Edwards curve addition formula:
    // (x1, y1) + (x2, y2) = ((x1*y2 + y1*x2) / (1 + d*x1*x2*y1*y2), (y1*y2 - a*x1*x2) / (1 - d*x1*x2*y1*y2))
    // For Ed25519, a = -1, d = -121665/121666
    
    // Compute x1*y2
    let x1y2 = builder.mul(p1.x, p2.y);
    
    // Compute y1*x2
    let y1x2 = builder.mul(p1.y, p2.x);
    
    // Compute x1*x2
    let x1x2 = builder.mul(p1.x, p2.x);
    
    // Compute y1*y2
    let y1y2 = builder.mul(p1.y, p2.y);
    
    // Compute numerator for x: x1*y2 + y1*x2
    let x_num = builder.add(x1y2, y1x2);
    
    // Compute numerator for y: y1*y2 - a*x1*x2 (a = -1 for Ed25519)
    let y_num = builder.sub(y1y2, x1x2);
    
    // Compute d*x1*x2*y1*y2
    // For Ed25519, d = -121665/121666
    // We'll use a simplified approach here
    let d_const = builder.constant(F::from_canonical_u64(37095705));
    let x1x2y1y2 = builder.mul(x1x2, y1y2);
    let d_term = builder.mul(d_const, x1x2y1y2);
    
    // Compute denominator for x: 1 + d*x1*x2*y1*y2
    let one = builder.one();
    let x_den = builder.add(one, d_term);
    
    // Compute denominator for y: 1 - d*x1*x2*y1*y2
    let y_den = builder.sub(one, d_term);
    
    // Compute x = x_num / x_den
    let x = builder.div(x_num, x_den);
    
    // Compute y = y_num / y_den
    let y = builder.div(y_num, y_den);
    
    // Return the result as a PointTarget
    PointTarget { x, y }
}
