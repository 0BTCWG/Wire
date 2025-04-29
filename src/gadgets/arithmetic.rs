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
