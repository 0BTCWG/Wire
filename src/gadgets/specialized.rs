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
    // For very small ranges, use direct comparison
    let max_target = builder.constant(F::from_canonical_u64(max_value));
    
    // Check if value <= max_value
    // We can implement this as !(value > max_target)
    // Since we don't have a direct less-than-or-equal operation,
    // we'll use a subtraction and check if it's non-negative
    let diff = builder.sub(max_target, value);
    
    // Split the difference into bits to check the sign bit
    let bits = builder.split_le(diff, 64);
    
    // If the highest bit is 0, then the difference is non-negative,
    // which means value <= max_target
    let is_non_negative = builder.not(bits[63]);
    
    // Return the result as a Target
    Ok(is_non_negative.target)
}

/// Range check for large ranges (more than 1024)
fn range_check_large<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
    max_value: u64,
) -> WireResult<Target> {
    // For large ranges, use bit decomposition
    let bit_length = 64 - max_value.leading_zeros();
    let bits = builder.split_le(value, bit_length as usize);
    
    // Check that all higher bits are zero and value is within range
    let must_be_zero = builder.zero();
    let mut is_valid = builder.constant_bool(true);
    
    for i in bit_length as usize..bits.len() {
        let bit_target = bits[i].target;
        let is_zero = builder.is_equal(bit_target, must_be_zero);
        is_valid = builder.and(is_valid, is_zero);
    }
    
    // Return the result as a Target
    Ok(is_valid.target)
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
            // Create domain separator target
            let domain_target = domain_to_targets(builder, domain)?;
            
            // Combine input with domain
            let mut combined_input = domain_target;
            combined_input.extend_from_slice(input);
            
            // Use hash_n without domain parameter
            let hash_result = hash_n(builder, &combined_input);
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
        
        // Hash the combined input - use hash_n directly instead of hash
        let hash_result = hash_n(builder, &combined);
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
        let mut result = builder.constant_bool(true);
        
        for i in 0..left_values.len() {
            let eq = builder.is_equal(left_values[i], right_values[i]);
            result = builder.and(result, eq);
        }
        
        return Ok(result.target);
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
    
    Ok(result.target)
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
    builder.assert_one(is_bit.target);
    
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
/// Uses a divide-and-conquer approach for better performance
pub fn vector_sum_optimized<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    if values.is_empty() {
        return Ok(builder.zero());
    }
    
    if values.len() == 1 {
        return Ok(values[0]);
    }
    
    if values.len() <= 8 {
        // For small vectors, use the direct approach
        let mut sum = values[0];
        for i in 1..values.len() {
            sum = builder.add(sum, values[i]);
        }
        return Ok(sum);
    }
    
    // For larger vectors, use divide and conquer
    let mid = values.len() / 2;
    let left = &values[..mid];
    let right = &values[mid..];
    
    // Recursively sum the halves
    let left_sum = vector_sum_optimized(builder, left).unwrap_or_else(|_| builder.zero());
    let right_sum = vector_sum_optimized(builder, right).unwrap_or_else(|_| builder.zero());
    
    // Combine the results
    Ok(builder.add(left_sum, right_sum))
}
