use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Compare two vectors of Targets and return a BoolTarget that is true if they are equal.
/// This is a utility function used across different circuit modules.
pub fn compare_vectors<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &[Target],
    b: &[Target],
) -> BoolTarget {
    // If vectors have different lengths, return false
    if a.len() != b.len() {
        return builder.constant_bool(false);
    }

    // Compare each element and AND the results
    if a.is_empty() {
        return builder.constant_bool(true); // Empty vectors are equal
    }

    let mut equal_bits = Vec::with_capacity(a.len());
    for (a_bit, b_bit) in a.iter().zip(b.iter()) {
        let bit_eq = builder.is_equal(*a_bit, *b_bit);
        equal_bits.push(bit_eq);
    }

    // Combine all equality checks with AND operations
    let mut result = equal_bits[0];
    for bit_eq in equal_bits.iter().skip(1) {
        result = builder.and(result, *bit_eq);
    }

    result
}
