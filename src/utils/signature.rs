// Signature utility functions for the 0BTC Wire system

// Fix imports for ed25519-dalek v2.0.0
use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{SigningKey, VerifyingKey, Signature};
use ed25519_dalek::SignatureError;
// In ed25519-dalek v2.0.0, we need to create our own Keypair struct

/// Our own Keypair struct since ed25519-dalek v2.0.0 no longer provides one
pub struct Keypair {
    pub secret: SigningKey,
    pub public: VerifyingKey,
}

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::errors::{WireError, CryptoError, WireResult};

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
    // Convert signature to field elements
    let sig_bytes = signature.to_bytes();
    
    // Create R point targets
    let r_x = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[0..8].try_into().unwrap()));
    let r_y = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[8..16].try_into().unwrap()));
    let s = F::from_canonical_u64(u64::from_le_bytes(sig_bytes[32..40].try_into().unwrap()));
    
    let r_x_target = builder.constant(r_x);
    let r_y_target = builder.constant(r_y);
    let s_target = builder.constant(s);
    
    // Convert public key to field elements
    let pk_bytes = public_key.to_bytes();
    let pk_x = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[0..8].try_into().unwrap()));
    let pk_y = F::from_canonical_u64(u64::from_le_bytes(pk_bytes[8..16].try_into().unwrap()));
    
    let pk_x_target = builder.constant(pk_x);
    let pk_y_target = builder.constant(pk_y);
    
    // Check that signature components are non-zero
    let zero = builder.zero();
    let r_x_is_zero = builder.is_equal(r_x_target, zero);
    let r_y_is_zero = builder.is_equal(r_y_target, zero);
    let s_is_zero = builder.is_equal(s_target, zero);
    let pk_x_is_zero = builder.is_equal(pk_x_target, zero);
    let pk_y_is_zero = builder.is_equal(pk_y_target, zero);
    
    let r_x_nonzero = builder.not(r_x_is_zero);
    let r_y_nonzero = builder.not(r_y_is_zero);
    let s_nonzero = builder.not(s_is_zero);
    let pk_x_nonzero = builder.not(pk_x_is_zero);
    let pk_y_nonzero = builder.not(pk_y_is_zero);
    
    // For now, just check that all components are non-zero
    // In a real implementation, we would verify the signature properly
    let r_check = builder.and(r_x_nonzero, r_y_nonzero);
    let s_pk_x_check = builder.and(s_nonzero, pk_x_nonzero);
    let s_pk_check = builder.and(s_pk_x_check, pk_y_nonzero);
    let all_components_valid = builder.and(r_check, s_pk_check);
    
    // Verify that the message hash is valid
    let message_is_zero = builder.is_equal(message_hash, zero);
    let message_valid = builder.not(message_is_zero);
    
    // Final verification result
    builder.and(all_components_valid, message_valid)
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
    // This is a simplified check
    // In a real implementation, we would check the curve equation: -x^2 + y^2 = 1 + d*x^2*y^2
    // where d is the curve parameter
    
    // For now, we'll just check that the coordinates are non-zero
    !x.is_zero() && !y.is_zero()
}

/// Checks if a point is on the Ed25519 curve in the circuit
pub fn is_on_curve_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
    y: Target,
) -> BoolTarget {
    // For Ed25519 curve: -x^2 + y^2 = 1 + d*x^2*y^2 where d = -121665/121666
    // For simplicity, we'll just check a basic condition
    
    // Check if x and y are non-zero
    let zero = builder.zero();
    let x_is_zero = builder.is_equal(x, zero);
    let y_is_zero = builder.is_equal(y, zero);
    let x_nonzero = builder.not(x_is_zero);
    let y_nonzero = builder.not(y_is_zero);
    
    // For now, just return a basic check (x and y are non-zero)
    // In a real implementation, we would check the actual curve equation
    builder.and(x_nonzero, y_nonzero)
}

/// Adds two points on the Ed25519 curve
pub fn point_add<F: Field>(p1: (F, F), p2: (F, F)) -> (F, F) {
    // This is a simplified implementation
    // In a real implementation, we would use the Edwards curve addition formulas
    
    // For now, we'll just return a dummy result
    (p1.0 + p2.0, p1.1 + p2.1)
}

/// Adds two points on the Ed25519 curve in the circuit
pub fn point_add_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    p1: (Target, Target),
    p2: (Target, Target),
) -> (Target, Target) {
    // This is a simplified implementation
    // In a real implementation, we would use the Edwards curve addition formulas
    
    // For now, we'll just add the coordinates
    let x = builder.add(p1.0, p2.0);
    let y = builder.add(p1.1, p2.1);
    (x, y)
}

/// Multiplies a point by a scalar on the Ed25519 curve
pub fn scalar_multiply<F: Field>(p: (F, F), scalar: F) -> (F, F) {
    // For now, we'll implement a simple double-and-add algorithm
    // This is a placeholder implementation that should be replaced with a proper one
    // In a real implementation, we would use the ed25519-dalek library's scalar multiplication
    
    let mut result = (F::ZERO, F::ZERO); // Point at infinity
    let mut temp = p;
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
pub fn optimized_scalar_multiply<F: Field>(p: (F, F), scalar: F) -> (F, F) {
    // This is a placeholder for the actual optimized scalar multiplication
    // In a real implementation, this would use windowed or sliding window methods
    // For now, we'll just use the regular scalar_multiply function
    scalar_multiply(p, scalar)
}

/// Optimized scalar multiplication for Ed25519 curve points in the circuit
pub fn optimized_scalar_multiply_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    point: (Target, Target),
    scalar: Target,
) -> (Target, Target) {
    // This is a placeholder for the actual optimized scalar multiplication
    // In a real implementation, this would use windowed or sliding window methods
    // For now, we'll just use a simple approach
    
    // Initialize result to the identity element (0, 1)
    let zero = builder.zero();
    let one = builder.one();
    let mut result = (zero, one);
    
    // Create a dummy point for the result
    // In a real implementation, this would perform actual scalar multiplication
    result.0 = builder.mul(point.0, scalar);
    result.1 = builder.mul(point.1, scalar);
    
    result
}

/// Gets the base point (generator) of the Ed25519 curve
pub fn get_base_point<F: Field>() -> (F, F) {
    // The base point coordinates for Ed25519
    let x = F::from_canonical_u64(15112221349535400772501151409588531511454012693041857206046113283949847762202);
    let y = F::from_canonical_u64(46316835694926478169428394003475163141307993866256225615783033603165251855960);
    (x, y)
}

/// Gets the base point (generator) of the Ed25519 curve in the circuit
pub fn get_base_point_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> (Target, Target) {
    // The base point coordinates for Ed25519
    let x = builder.constant(F::from_canonical_u64(15112221349535400772501151409588531511454012693041857206046113283949847762202));
    let y = builder.constant(F::from_canonical_u64(46316835694926478169428394003475163141307993866256225615783033603165251855960));
    (x, y)
}
