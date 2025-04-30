// Field utility functions for the 0BTC Wire system

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Converts a field element to its binary representation
pub fn field_to_bits<F: Field>(value: F) -> Vec<bool> {
    let bit_length = 64; // Default to 64 bits for u64 representation
    let mut result = Vec::with_capacity(bit_length);
    let mut val = value.to_canonical_u64();
    
    for _ in 0..bit_length {
        result.push(val & 1 == 1);
        val >>= 1;
    }
    
    result
}

/// Converts a field element to its binary representation with specified bit length
pub fn field_to_bits_with_length<F: Field>(value: F, bit_length: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(bit_length);
    let mut val = value.to_canonical_u64();
    
    for _ in 0..bit_length {
        result.push(val & 1 == 1);
        val >>= 1;
    }
    
    result
}

/// Converts a binary representation to a field element
pub fn bits_to_field<F: Field>(bits: &[bool]) -> F {
    let mut result = F::ZERO;
    let mut power = F::ONE;
    
    for &bit in bits {
        if bit {
            result += power;
        }
        power = power.double();
    }
    
    result
}

/// Adds field element targets in the circuit
pub fn add_field_targets<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.add(a, b)
}

/// Multiplies field element targets in the circuit
pub fn mul_field_targets<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.mul(a, b)
}

/// Computes the inverse of a field element target in the circuit
pub fn inverse_field_target<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    builder.inverse(a)
}

/// Converts a u64 to a field element
pub fn u64_to_field<F: Field>(value: u64) -> F {
    F::from_canonical_u64(value)
}

/// Converts a field element to a u64
pub fn field_to_u64<F: Field>(value: F) -> u64 {
    value.to_canonical_u64()
}

/// Computes the square of a field element target in the circuit
pub fn square_field_target<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    builder.mul(a, a)
}

/// Computes the cube of a field element target in the circuit
pub fn cube_field_target<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    let a_squared = builder.mul(a, a);
    builder.mul(a_squared, a)
}

/// Computes a^n for a field element target in the circuit
pub fn pow_field_target<F: Field, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    n: u64,
) -> Target {
    if n == 0 {
        return builder.one();
    }
    
    if n == 1 {
        return a;
    }
    
    let mut result = builder.one();
    let mut base = a;
    let mut exp = n;
    
    while exp > 0 {
        if exp & 1 == 1 {
            result = builder.mul(result, base);
        }
        base = builder.mul(base, base);
        exp >>= 1;
    }
    
    result
}

/// Returns the Goldilocks field modulus
pub fn goldilocks_modulus() -> u64 {
    GoldilocksField::ORDER
}

/// Checks if a u64 value is within the Goldilocks field range
pub fn is_in_goldilocks_field_range(value: u64) -> bool {
    value < GoldilocksField::ORDER
}

/// Reduces a u64 value modulo the Goldilocks field modulus
pub fn reduce_to_goldilocks_field_range(value: u64) -> u64 {
    value % GoldilocksField::ORDER
}
