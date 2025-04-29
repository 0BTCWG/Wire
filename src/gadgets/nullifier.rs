// Nullifier gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::gadgets::hash_targets;

/// Calculate a nullifier for a UTXO
///
/// This prevents double-spending by creating a unique nullifier
/// based on salt and owner's secret key.
pub fn calculate_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    owner_sk: Target,
) -> Target {
    // Combine the salt and owner's secret key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(salt);
    inputs.push(owner_sk);
    
    // Hash the combined inputs to create the nullifier
    let nullifier_hash = hash_targets(builder, &inputs);
    
    // Use the first element of the hash as the nullifier
    nullifier_hash.elements[0]
}

/// Calculate and register a nullifier for a UTXO
///
/// This prevents double-spending by creating a unique nullifier
/// that is registered as a public input.
pub fn calculate_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    owner_sk: Target,
) -> Target {
    // Calculate the nullifier
    let nullifier = calculate_nullifier(builder, salt, owner_sk);
    
    // Register the nullifier as a public input
    builder.register_public_input(nullifier);
    
    nullifier
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
    fn test_nullifier_calculation() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create inputs
        let salt = builder.add_virtual_target();
        let owner_sk = builder.add_virtual_target();
        
        // Calculate the nullifier
        let _nullifier = calculate_and_register_nullifier(&mut builder, &[salt], owner_sk);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set the salt values
        pw.set_target(salt, F::from_canonical_u64(0));
        
        // Set the owner secret key
        pw.set_target(owner_sk, F::from_canonical_u64(42));
        
        // Generate the proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the nullifier is in the public inputs
        assert_ne!(proof.public_inputs[0], F::ZERO);
    }
}
