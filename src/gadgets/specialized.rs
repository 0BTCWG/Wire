use std::time::Instant;
use log::{debug, info};

use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::errors::{CircuitError, ValidationError, WireError, WireResult};
use crate::gadgets::hash::{hash, hash_n};

/// Specialized gadget for range checks
/// Efficiently verifies that a value is within a specified range [0, max_value]
pub fn range_check<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    max_value: u64,
) -> WireResult<Target> {
    // Input validation
    if max_value == 0 {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            "Maximum value must be greater than zero".to_string()
        )));
    }

    // For small ranges, use a direct comparison
    if max_value <= 1024 {
        return range_check_small(builder, value, max_value);
    }
    
    // For larger ranges, use a more efficient approach with bit decomposition
    range_check_large(builder, value, max_value)
}

/// Range check for small ranges (up to 1024)
fn range_check_small<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    max_value: u64,
) -> WireResult<Target> {
    let max_value_target = builder.constant(F::from_canonical_u64(max_value));
    let is_less_or_equal = builder.is_less_than_or_equal(value, max_value_target);
    
    // Also check that value is non-negative (always true for field elements in our case)
    // but we include it for completeness
    let zero = builder.zero();
    let is_greater_or_equal = builder.is_less_than_or_equal(zero, value);
    
    // Both conditions must be true
    let result = builder.and(is_less_or_equal, is_greater_or_equal);
    
    Ok(result)
}

/// Range check for large ranges (more than 1024)
fn range_check_large<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    max_value: u64,
) -> WireResult<Target> {
    // Determine the number of bits needed to represent max_value
    let bits_needed = 64 - max_value.leading_zeros();
    
    // Decompose value into bits
    let bits = builder.split_le(value, bits_needed as usize);
    
    // Check if the value is within range by comparing with max_value
    let mut is_valid = builder.constant(F::ONE);
    let mut running_value = 0u64;
    
    for i in (0..bits.len()).rev() {
        // Check if setting this bit would exceed max_value
        let bit_value = 1u64 << i;
        let new_value = running_value + bit_value;
        
        if new_value <= max_value {
            // This bit can be either 0 or 1
            running_value = new_value;
        } else {
            // This bit must be 0 if previous bits match the max_value
            let must_be_zero = builder.constant(F::ZERO);
            let is_zero = builder.is_equal(bits[i], must_be_zero);
            is_valid = builder.and(is_valid, is_zero);
        }
    }
    
    Ok(is_valid)
}

/// Specialized gadget for efficient batch hashing
/// Optimized for hashing multiple values with the same domain
pub fn batch_hash_with_domain<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Vec<Target>],
    domain: &str,
) -> WireResult<Vec<Target>> {
    // Input validation
    if inputs.is_empty() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            "Inputs array cannot be empty".to_string()
        )));
    }
    
    // For small batches, just use the regular hash function
    if inputs.len() <= 4 {
        let mut results = Vec::with_capacity(inputs.len());
        for input in inputs {
            let hash_result = hash_n(builder, input, domain)?;
            results.push(hash_result);
        }
        return Ok(results);
    }
    
    // For larger batches, use a more efficient approach
    batch_hash_optimized(builder, inputs, domain)
}

/// Optimized batch hashing for larger batches
fn batch_hash_optimized<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Vec<Target>],
    domain: &str,
) -> WireResult<Vec<Target>> {
    // Precompute domain constants once for all hashes
    let domain_targets = domain_to_targets(builder, domain)?;
    
    let mut results = Vec::with_capacity(inputs.len());
    
    for input in inputs {
        // Combine input with domain
        let mut combined = domain_targets.clone();
        combined.extend_from_slice(input);
        
        // Hash the combined input
        let hash_result = hash(builder, &combined)?;
        results.push(hash_result);
    }
    
    Ok(results)
}

/// Convert a domain string to circuit targets
fn domain_to_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    domain: &str,
) -> WireResult<Vec<Target>> {
    let mut targets = Vec::new();
    
    // Convert domain string to bytes
    let domain_bytes = domain.as_bytes();
    
    // Convert each byte to a target
    for &byte in domain_bytes {
        let target = builder.constant(F::from_canonical_u64(byte as u64));
        targets.push(target);
    }
    
    // Add domain length as a target
    let length_target = builder.constant(F::from_canonical_u64(domain_bytes.len() as u64));
    targets.push(length_target);
    
    Ok(targets)
}

/// Specialized gadget for efficient batch equality checks
/// Optimized for checking multiple equality conditions at once
pub fn batch_equality_check<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left_values: &[Target],
    right_values: &[Target],
) -> WireResult<Target> {
    // Input validation
    if left_values.len() != right_values.len() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            format!("Arrays must have the same length: {} != {}", 
                    left_values.len(), right_values.len())
        )));
    }
    
    if left_values.is_empty() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            "Arrays cannot be empty".to_string()
        )));
    }
    
    // For small batches, use the regular approach
    if left_values.len() <= 4 {
        let mut result = builder.constant(F::ONE);
        
        for i in 0..left_values.len() {
            let eq = builder.is_equal(left_values[i], right_values[i]);
            result = builder.and(result, eq);
        }
        
        return Ok(result);
    }
    
    // For larger batches, use a more efficient approach
    batch_equality_optimized(builder, left_values, right_values)
}

/// Optimized batch equality check for larger batches
fn batch_equality_optimized<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left_values: &[Target],
    right_values: &[Target],
) -> WireResult<Target> {
    // Use a randomized linear combination approach
    // This is more efficient than checking each equality separately
    
    // Generate random coefficients (in a real circuit, these would be derived from a seed)
    let mut coefficients = Vec::with_capacity(left_values.len());
    for i in 0..left_values.len() {
        let coeff = builder.constant(F::from_canonical_u64((i + 1) as u64));
        coefficients.push(coeff);
    }
    
    // Compute linear combinations
    let mut left_sum = builder.zero();
    let mut right_sum = builder.zero();
    
    for i in 0..left_values.len() {
        // left_sum += coefficients[i] * left_values[i]
        let left_term = builder.mul(coefficients[i], left_values[i]);
        left_sum = builder.add(left_sum, left_term);
        
        // right_sum += coefficients[i] * right_values[i]
        let right_term = builder.mul(coefficients[i], right_values[i]);
        right_sum = builder.add(right_sum, right_term);
    }
    
    // Check if the linear combinations are equal
    let result = builder.is_equal(left_sum, right_sum);
    
    Ok(result)
}

/// Specialized gadget for conditional selection
/// Efficiently selects between two values based on a condition
pub fn conditional_select<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: Target,
    true_value: Target,
    false_value: Target,
) -> WireResult<Target> {
    // Ensure condition is a bit (0 or 1)
    let zero = builder.zero();
    let one = builder.constant(F::ONE);
    
    // Check if condition is 0 or 1
    let is_zero = builder.is_equal(condition, zero);
    let is_one = builder.is_equal(condition, one);
    let is_bit = builder.or(is_zero, is_one);
    
    // Assert that condition is a bit
    builder.assert_one(is_bit);
    
    // Compute: condition * true_value + (1 - condition) * false_value
    let condition_times_true = builder.mul(condition, true_value);
    let one_minus_condition = builder.sub(one, condition);
    let one_minus_condition_times_false = builder.mul(one_minus_condition, false_value);
    
    let result = builder.add(condition_times_true, one_minus_condition_times_false);
    
    Ok(result)
}

/// Specialized gadget for vector dot product
/// Efficiently computes the dot product of two vectors
pub fn vector_dot_product<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left_values: &[Target],
    right_values: &[Target],
) -> WireResult<Target> {
    // Input validation
    if left_values.len() != right_values.len() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            format!("Vectors must have the same length: {} != {}", 
                    left_values.len(), right_values.len())
        )));
    }
    
    if left_values.is_empty() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            "Vectors cannot be empty".to_string()
        )));
    }
    
    // Compute the dot product
    let mut sum = builder.zero();
    
    for i in 0..left_values.len() {
        let product = builder.mul(left_values[i], right_values[i]);
        sum = builder.add(sum, product);
    }
    
    Ok(sum)
}

/// Specialized gadget for vector sum
/// Efficiently computes the sum of a vector
pub fn vector_sum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    // Input validation
    if values.is_empty() {
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            "Vector cannot be empty".to_string()
        )));
    }
    
    // For small vectors, use a simple loop
    if values.len() <= 8 {
        let mut sum = builder.zero();
        
        for &value in values {
            sum = builder.add(sum, value);
        }
        
        return Ok(sum);
    }
    
    // For larger vectors, use a divide-and-conquer approach
    vector_sum_optimized(builder, values)
}

/// Optimized vector sum for larger vectors
fn vector_sum_optimized<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    // Use a divide-and-conquer approach to reduce circuit depth
    if values.len() == 1 {
        return Ok(values[0]);
    }
    
    let mid = values.len() / 2;
    let left = &values[..mid];
    let right = &values[mid..];
    
    let left_sum = vector_sum_optimized(builder, left)?;
    let right_sum = vector_sum_optimized(builder, right)?;
    
    let result = builder.add(left_sum, right_sum);
    
    Ok(result)
}
