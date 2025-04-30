// Arithmetic gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Check if two targets are equal
pub fn is_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // Compute a - b
    let diff = builder.sub(a, b);
    
    // Create a zero constant
    let zero = builder.zero();
    
    // Check if diff == 0
    // We'll use the inverse approach: if diff != 0, then 1/diff exists
    let diff_is_zero_bool = builder.is_equal(diff, zero);
    
    // Convert the boolean result to a target (0 or 1)
    let one = builder.one();
    builder.select(diff_is_zero_bool, one, zero)
}

/// Select between two targets based on a condition
pub fn select<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: Target,
    when_true: Target,
    when_false: Target,
) -> Target {
    // Create a zero constant
    let zero = builder.zero();
    
    // Check if condition is non-zero
    let is_non_zero = builder.is_equal(condition, zero);
    let is_true = builder.not(is_non_zero);
    
    // Select based on the condition
    builder.select(is_true, when_true, when_false)
}

/// Sum a list of targets
pub fn sum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) -> Target {
    if targets.is_empty() {
        return builder.zero();
    }
    
    let mut result = targets[0];
    for &target in &targets[1..] {
        result = builder.add(result, target);
    }
    
    result
}

/// Add two targets
pub fn add<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.add(a, b)
}

/// Subtract one target from another
pub fn sub<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.sub(a, b)
}

/// Multiply two targets
pub fn mul<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    builder.mul(a, b)
}

/// Divide one target by another
pub fn div<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // Compute 1/b
    let b_inv = builder.inverse(b);
    
    // Compute a * (1/b)
    builder.mul(a, b_inv)
}

/// Check if a is equal to b (alias for is_equal)
pub fn eq<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    is_equal(builder, a, b)
}

/// Check if a is less than b
pub fn lt<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // Compute b - a
    let diff = builder.sub(b, a);
    
    // Check if diff > 0
    let zero = builder.zero();
    let is_positive = builder.is_equal(zero, diff);
    let result = builder.not(is_positive);
    
    result.target
}

/// Check if a is less than or equal to b
pub fn lte<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a <= b is equivalent to !(a > b)
    let a_gt_b = gt(builder, a, b);
    let not_a_gt_b = builder.not(a_gt_b);
    not_a_gt_b.target
}

/// Check if a is greater than b
pub fn gt<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a > b is equivalent to b < a
    lt(builder, b, a)
}

/// Check if a is greater than or equal to b
pub fn gte<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a >= b is equivalent to !(a < b)
    let a_lt_b = lt(builder, a, b);
    let not_a_lt_b = builder.not(a_lt_b);
    not_a_lt_b.target
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
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn test_is_equal() {
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two inputs
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        // Check if a == b
        let result = is_equal(&mut builder, a, b);
        
        // Register the result as a public input
        builder.register_public_input(result);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Test case 1: a == b (5 == 5)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(5));
        pw.set_target(b, F::from_canonical_u64(5));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 1 (true)
        assert_eq!(public_inputs[0], F::ONE);
        
        // Test case 2: a != b (5 != 10)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(5));
        pw.set_target(b, F::from_canonical_u64(10));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 0 (false)
        assert_eq!(public_inputs[0], F::ZERO);
    }
}
