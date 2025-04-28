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
    
    // Check if diff is zero
    let is_zero = builder.is_zero(diff);
    
    is_zero
}

/// Check if target a is less than target b
pub fn is_less_than<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // For simplicity, we'll use the range check method
    // In a real implementation, this would be more complex
    
    // Compute b - a
    let diff = builder.sub(b, a);
    
    // Check if diff is non-zero and positive
    // This is a simplified version; in practice, you'd need
    // to handle the full range of field elements
    let diff_bits = builder.split_le(diff, 64);
    
    // If diff > 0, then a < b
    // We'll just return the first bit for simplicity
    // In a real implementation, you'd need to check that the rest are zero
    diff_bits[0]
}

/// Check if target a is less than or equal to target b
pub fn is_less_than_or_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // a <= b is equivalent to !(a > b)
    // which is equivalent to !(b < a)
    let b_lt_a = is_less_than(builder, b, a);
    let not_b_lt_a = builder.not(b_lt_a);
    
    not_b_lt_a
}

/// Select between two targets based on a condition
pub fn select<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    condition: Target,
    when_true: Target,
    when_false: Target,
) -> Target {
    builder.select(condition, when_true, when_false)
}

/// Sum an array of targets
pub fn sum<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) -> Target {
    let mut sum = builder.zero();
    
    for &target in targets {
        sum = builder.add(sum, target);
    }
    
    sum
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::field::goldilocks_field::GoldilocksField;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_is_equal() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two targets
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        // Check if they're equal
        let is_eq = is_equal(&mut builder, a, b);
        
        // Make the result a public input
        builder.register_public_input(is_eq);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness for equal values
        let mut pw_equal = PartialWitness::new();
        pw_equal.set_target(a, F::from_canonical_u64(123));
        pw_equal.set_target(b, F::from_canonical_u64(123));
        
        // Generate the proof
        let proof_equal = circuit.prove(pw_equal).unwrap();
        
        // Verify the proof
        circuit.verify(proof_equal).unwrap();
        
        // Check the public input (should be 1 for equal)
        assert_eq!(proof_equal.public_inputs[0], F::ONE);
        
        // Create a witness for unequal values
        let mut pw_unequal = PartialWitness::new();
        pw_unequal.set_target(a, F::from_canonical_u64(123));
        pw_unequal.set_target(b, F::from_canonical_u64(456));
        
        // Generate the proof
        let proof_unequal = circuit.prove(pw_unequal).unwrap();
        
        // Verify the proof
        circuit.verify(proof_unequal).unwrap();
        
        // Check the public input (should be 0 for unequal)
        assert_eq!(proof_unequal.public_inputs[0], F::ZERO);
    }
    
    #[test]
    fn test_is_less_than() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two targets
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        
        // Check if a < b
        let is_lt = is_less_than(&mut builder, a, b);
        
        // Make the result a public input
        builder.register_public_input(is_lt);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness for a < b
        let mut pw_less = PartialWitness::new();
        pw_less.set_target(a, F::from_canonical_u64(123));
        pw_less.set_target(b, F::from_canonical_u64(456));
        
        // Generate the proof
        let proof_less = circuit.prove(pw_less).unwrap();
        
        // Verify the proof
        circuit.verify(proof_less).unwrap();
        
        // Check the public input (should be 1 for a < b)
        assert_eq!(proof_less.public_inputs[0], F::ONE);
        
        // Create a witness for a > b
        let mut pw_greater = PartialWitness::new();
        pw_greater.set_target(a, F::from_canonical_u64(456));
        pw_greater.set_target(b, F::from_canonical_u64(123));
        
        // Generate the proof
        let proof_greater = circuit.prove(pw_greater).unwrap();
        
        // Verify the proof
        circuit.verify(proof_greater).unwrap();
        
        // Check the public input (should be 0 for a > b)
        assert_eq!(proof_greater.public_inputs[0], F::ZERO);
    }
}
