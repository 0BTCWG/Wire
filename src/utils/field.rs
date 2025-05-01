// Field utility functions for the 0BTC Wire system

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_field::types::Field64;

/// Converts a field element to its binary representation
pub fn field_to_bits<F: Field + PrimeField64>(value: F) -> Vec<bool> {
    let mut result = Vec::new();
    let mut val = value.to_canonical_u64();
    
    while val > 0u64 {
        result.push((val & 1u64) == 1u64);
        val >>= 1;
    }
    
    result.reverse();
    result
}

/// Converts a field element to its binary representation with a fixed length
pub fn field_to_bits_with_length<F: Field + PrimeField64>(value: F, bit_length: usize) -> Vec<bool> {
    let mut result = Vec::with_capacity(bit_length);
    let mut val = value.to_canonical_u64();
    
    for _ in 0..bit_length {
        result.push((val & 1u64) != 0u64);
        val >>= 1;
    }
    
    result.reverse();
    result
}

/// Converts a field element target to its binary representation in the circuit
pub fn field_to_bits_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    bit_length: usize,
) -> Vec<BoolTarget> {
    builder.split_le(value, bit_length)
}

/// Adds two field element targets in the circuit
pub fn add_field_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.add(a, b)
}

/// Multiplies two field element targets in the circuit
pub fn mul_field_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.mul(a, b)
}

/// Computes the inverse of a field element target in the circuit
pub fn inverse_field_target<F: RichField + Extendable<D>, const D: usize>(
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
pub fn field_to_u64<F: Field + PrimeField64>(value: F) -> u64 {
    value.to_canonical_u64()
}

/// Computes the square of a field element target in the circuit
pub fn square_field_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    builder.mul(a, a)
}

/// Computes the cube of a field element target in the circuit
pub fn cube_field_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
) -> Target {
    let a_squared = builder.mul(a, a);
    builder.mul(a_squared, a)
}

/// Computes a^n for a field element target in the circuit
pub fn pow_field_target<F: RichField + Extendable<D>, const D: usize>(
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

/// Converts a bit array to a field element
pub fn bits_to_field<F: Field>(bits: &[bool]) -> F {
    let mut result = F::ZERO;
    for &bit in bits {
        result = result + result;
        if bit {
            result = result + F::ONE;
        }
    }
    result
}

/// Converts a bit array target to a field element target in the circuit
pub fn bits_to_field_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bits: &[BoolTarget],
) -> Target {
    let mut result = builder.zero();
    let two = builder.two();
    
    for &bit in bits {
        // First compute result * 2
        let result_times_two = builder.mul(result, two);
        
        // Then add the bit
        result = builder.add(result_times_two, bit.target);
    }
    
    result
}

/// Checks if a u64 is less than the field order
pub fn is_valid_field_element(value: u64) -> bool {
    value < GoldilocksField::ORDER
}

/// Reduces a u64 modulo the field order
pub fn reduce_to_field_element(value: u64) -> u64 {
    value % GoldilocksField::ORDER
}

/// Converts a field element to a little-endian bit array target in the circuit
pub fn field_to_bits_le_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    bit_length: usize,
) -> Vec<BoolTarget> {
    builder.split_le(value, bit_length)
}
