// Nonce management gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::gadgets::hash_for_signature;
use crate::gadgets::comparison::is_less_than;

/// A nonce target for use in circuits
pub struct NonceTarget {
    /// The nonce value
    pub value: Target,
    /// The expiration timestamp (0 for no expiration)
    pub expiration: Target,
    /// The randomness used to generate the nonce
    pub randomness: Target,
}

/// Generate a secure nonce from randomness and a counter
///
/// This function creates a secure nonce by hashing randomness with a counter.
/// The randomness should be generated outside the circuit using a secure RNG.
pub fn generate_nonce<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    randomness: Target,
    counter: Target,
) -> Target {
    // Combine the randomness and counter
    let mut inputs = Vec::new();
    inputs.push(randomness);
    inputs.push(counter);
    
    // Hash with domain separation
    hash_for_signature(builder, &inputs)
}

/// Generate a nonce with expiration
///
/// This function creates a nonce that includes an expiration timestamp.
/// The nonce is only valid until the expiration time.
pub fn generate_nonce_with_expiration<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    randomness: Target,
    counter: Target,
    expiration: Target,
) -> NonceTarget {
    // Generate the nonce value
    let value = generate_nonce(builder, randomness, counter);
    
    // Create the nonce target with expiration
    NonceTarget {
        value,
        expiration,
        randomness,
    }
}

/// Verify that a nonce is valid and not expired
///
/// This function verifies that a nonce is valid and not expired.
/// The current_time should be provided as a public input.
pub fn verify_nonce_not_expired<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nonce: &NonceTarget,
    current_time: Target,
) -> BoolTarget {
    // If expiration is 0, the nonce never expires
    let zero = builder.zero();
    let is_never_expires = builder.is_equal(nonce.expiration, zero);
    
    // Check if the current time is less than the expiration time
    let is_not_expired = is_less_than(builder, current_time, nonce.expiration);
    
    // The nonce is valid if it never expires or if it's not expired
    builder.or(is_never_expires, is_not_expired)
}

/// Assert that a nonce is valid and not expired
///
/// This function asserts that a nonce is valid and not expired.
/// The current_time should be provided as a public input.
pub fn assert_nonce_not_expired<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nonce: &NonceTarget,
    current_time: Target,
) {
    let is_valid = verify_nonce_not_expired(builder, nonce, current_time);
    builder.assert_one(is_valid);
}

/// Verify that a nonce has sufficient randomness
///
/// This function verifies that a nonce has sufficient randomness.
/// The randomness should be at least min_randomness_bits bits.
pub fn verify_nonce_randomness<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nonce: &NonceTarget,
    min_randomness_bits: usize,
) -> BoolTarget {
    // Split the randomness into bits
    let randomness_bits = builder.split_le(nonce.randomness, min_randomness_bits);
    
    // Check if at least one bit is set in each byte
    let mut is_random_enough = builder.one_bool();
    
    // Check each byte (8 bits)
    for i in 0..(min_randomness_bits / 8) {
        let start = i * 8;
        let end = (i + 1) * 8;
        let byte_bits = &randomness_bits[start..end];
        
        // Check if at least one bit is set in this byte
        let mut byte_has_bit = builder.zero_bool();
        for bit in byte_bits {
            byte_has_bit = builder.or(byte_has_bit, *bit);
        }
        
        // All bytes must have at least one bit set
        is_random_enough = builder.and(is_random_enough, byte_has_bit);
    }
    
    is_random_enough
}

/// Assert that a nonce has sufficient randomness
///
/// This function asserts that a nonce has sufficient randomness.
/// The randomness should be at least min_randomness_bits bits.
pub fn assert_nonce_randomness<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nonce: &NonceTarget,
    min_randomness_bits: usize,
) {
    let is_random_enough = verify_nonce_randomness(builder, nonce, min_randomness_bits);
    builder.assert_one(is_random_enough);
}

/// Register a nonce as used
///
/// This function registers a nonce as used by adding it to the public inputs.
/// This allows external systems to track used nonces and prevent replay attacks.
pub fn register_used_nonce<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nonce: &NonceTarget,
) {
    // Register the nonce value as a public input
    builder.register_public_input(nonce.value);
    
    // Register the expiration as a public input
    builder.register_public_input(nonce.expiration);
}

/// Create a nonce registry for tracking used nonces
///
/// This struct provides a way to track used nonces and prevent replay attacks.
/// It should be used in conjunction with the register_used_nonce function.
#[derive(Default)]
pub struct NonceRegistry {
    /// The set of used nonces
    used_nonces: std::collections::HashSet<(u64, u64)>, // (value, expiration)
}

impl NonceRegistry {
    /// Create a new nonce registry
    pub fn new() -> Self {
        Self {
            used_nonces: std::collections::HashSet::new(),
        }
    }
    
    /// Check if a nonce is already used
    pub fn is_used(&self, value: u64, expiration: u64) -> bool {
        self.used_nonces.contains(&(value, expiration))
    }
    
    /// Mark a nonce as used
    pub fn mark_used(&mut self, value: u64, expiration: u64) {
        self.used_nonces.insert((value, expiration));
    }
    
    /// Clean up expired nonces
    pub fn clean_expired(&mut self, current_time: u64) {
        self.used_nonces.retain(|(_, expiration)| *expiration == 0 || *expiration > current_time);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_generate_nonce() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create inputs
        let randomness = builder.add_virtual_target();
        let counter = builder.add_virtual_target();
        
        // Generate a nonce
        let nonce = generate_nonce(&mut builder, randomness, counter);
        
        // Register the nonce as a public input
        builder.register_public_input(nonce);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set the values
        pw.set_target(randomness, F::from_canonical_u64(123));
        pw.set_target(counter, F::from_canonical_u64(1));
        
        // Generate the proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the nonce is non-zero
        assert_ne!(proof.public_inputs[0], F::ZERO);
    }
    
    #[test]
    fn test_nonce_expiration() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create inputs
        let randomness = builder.add_virtual_target();
        let counter = builder.add_virtual_target();
        let expiration = builder.add_virtual_target();
        let current_time = builder.add_virtual_target();
        
        // Generate a nonce with expiration
        let nonce = generate_nonce_with_expiration(
            &mut builder,
            randomness,
            counter,
            expiration,
        );
        
        // Verify that the nonce is not expired
        let is_valid = verify_nonce_not_expired(&mut builder, &nonce, current_time);
        
        // Register the result as a public input
        builder.register_public_input(nonce.value);
        builder.register_public_input(nonce.expiration);
        builder.register_public_input(current_time);
        
        // Convert the boolean to a field element
        let zero = builder.zero();
        let one = builder.one();
        let is_valid_field = builder.select(is_valid, one, zero);
        builder.register_public_input(is_valid_field);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Test case 1: Nonce is not expired
        let mut pw = PartialWitness::new();
        pw.set_target(randomness, F::from_canonical_u64(123));
        pw.set_target(counter, F::from_canonical_u64(1));
        pw.set_target(expiration, F::from_canonical_u64(1000));
        pw.set_target(current_time, F::from_canonical_u64(500));
        
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the nonce is valid
        assert_eq!(proof.public_inputs[3], F::ONE);
        
        // Test case 2: Nonce is expired
        let mut pw = PartialWitness::new();
        pw.set_target(randomness, F::from_canonical_u64(123));
        pw.set_target(counter, F::from_canonical_u64(1));
        pw.set_target(expiration, F::from_canonical_u64(1000));
        pw.set_target(current_time, F::from_canonical_u64(1500));
        
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the nonce is invalid
        assert_eq!(proof.public_inputs[3], F::ZERO);
        
        // Test case 3: Nonce never expires
        let mut pw = PartialWitness::new();
        pw.set_target(randomness, F::from_canonical_u64(123));
        pw.set_target(counter, F::from_canonical_u64(1));
        pw.set_target(expiration, F::from_canonical_u64(0));
        pw.set_target(current_time, F::from_canonical_u64(9999));
        
        let proof = circuit.prove(pw).unwrap();
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the nonce is valid
        assert_eq!(proof.public_inputs[3], F::ONE);
    }
    
    #[test]
    fn test_nonce_registry() {
        let mut registry = NonceRegistry::new();
        
        // Check that a nonce is not used initially
        assert!(!registry.is_used(123, 1000));
        
        // Mark the nonce as used
        registry.mark_used(123, 1000);
        
        // Check that the nonce is now used
        assert!(registry.is_used(123, 1000));
        
        // Clean up expired nonces
        registry.clean_expired(1500);
        
        // Check that the expired nonce is no longer tracked
        assert!(!registry.is_used(123, 1000));
        
        // Add a nonce that never expires
        registry.mark_used(456, 0);
        
        // Clean up expired nonces
        registry.clean_expired(9999);
        
        // Check that the never-expiring nonce is still tracked
        assert!(registry.is_used(456, 0));
    }
}
