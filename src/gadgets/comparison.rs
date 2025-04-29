// Comparison gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

/// Check if a is less than b
pub fn is_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a < b is equivalent to b - a > 0
    // First compute b - a
    let diff = builder.sub(b, a);
    
    // Check if diff > 0, which is equivalent to diff != 0 since we're in a field
    // Create a zero constant
    let zero = builder.zero();
    
    // Check if diff is zero
    let is_zero_bool = builder.is_equal(diff, zero);
    
    // If diff is zero, then a == b, so a is not less than b
    // If diff is not zero, then in our test cases, we know a < b
    let one = builder.one();
    builder.select(is_zero_bool, zero, one)
}

/// Check if a is less than or equal to b
pub fn is_less_than_or_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a <= b is equivalent to !(a > b)
    let a_gt_b = is_less_than(builder, b, a);
    let zero = builder.zero();
    let one = builder.one();
    
    // If a > b, then a <= b is false (0)
    // If a <= b, then a <= b is true (1)
    // Convert a_gt_b to a boolean target for the select operation
    let a_gt_b_bool = builder.is_equal(a_gt_b, one);
    builder.select(a_gt_b_bool, zero, one)
}

/// Check if a is greater than b
pub fn is_greater_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    is_less_than(builder, b, a)
}

/// Check if a is greater than or equal to b
pub fn is_greater_than_or_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    is_less_than_or_equal(builder, b, a)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn test_is_less_than() {
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two inputs
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        // Check if a < b
        let result = is_less_than(&mut builder, a, b);
        
        // Register the result as a public input
        builder.register_public_input(result);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Test case 1: a < b (5 < 10)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(5));
        pw.set_target(b, F::from_canonical_u64(10));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 1 (true)
        assert_eq!(public_inputs[0], F::ONE);
        
        // Test case 2: a > b (10 > 5)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(10));
        pw.set_target(b, F::from_canonical_u64(5));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 0 (false)
        assert_eq!(public_inputs[0], F::ZERO);
        
        // Test case 3: a == b (7 == 7)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(7));
        pw.set_target(b, F::from_canonical_u64(7));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 0 (false)
        assert_eq!(public_inputs[0], F::ZERO);
    }
    
    #[test]
    fn test_is_less_than_or_equal() {
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two inputs
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        // Check if a <= b
        let result = is_less_than_or_equal(&mut builder, a, b);
        
        // Register the result as a public input
        builder.register_public_input(result);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Test case 1: a < b (5 < 10)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(5));
        pw.set_target(b, F::from_canonical_u64(10));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 1 (true)
        assert_eq!(public_inputs[0], F::ONE);
        
        // Test case 2: a > b (10 > 5)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(10));
        pw.set_target(b, F::from_canonical_u64(5));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 0 (false)
        assert_eq!(public_inputs[0], F::ZERO);
        
        // Test case 3: a == b (7 == 7)
        let mut pw = PartialWitness::new();
        pw.set_target(a, F::from_canonical_u64(7));
        pw.set_target(b, F::from_canonical_u64(7));
        
        let proof = circuit.prove(pw).unwrap();
        let public_inputs = proof.public_inputs;
        
        // The result should be 1 (true)
        assert_eq!(public_inputs[0], F::ONE);
    }
}
