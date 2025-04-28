// Nullifier gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::gadgets::hash_targets;

/// Calculate a nullifier for a UTXO
///
/// A nullifier is a unique identifier for a spent UTXO that prevents double-spending.
/// It's calculated as hash(utxo_salt, user_sk) where user_sk is the user's secret key.
pub fn calculate_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo_salt: &[Target],
    user_sk: Target,
) -> Target {
    // Combine salt and secret key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(utxo_salt);
    inputs.push(user_sk);
    
    // Hash the combined inputs
    hash_targets(builder, &inputs)
}

/// Calculate and register a nullifier as a public input
pub fn calculate_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo_salt: &[Target],
    user_sk: Target,
) -> Target {
    // Calculate the nullifier
    let nullifier = calculate_nullifier(builder, utxo_salt, user_sk);
    
    // Register it as a public input
    builder.register_public_input(nullifier);
    
    nullifier
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use crate::core::HASH_SIZE;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_nullifier_calculation() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a salt and secret key
        let salt: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        let sk = builder.add_virtual_target();
        
        // Calculate the nullifier
        let nullifier = calculate_nullifier(&mut builder, &salt, sk);
        
        // Make the nullifier a public input
        builder.register_public_input(nullifier);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        // Set salt values
        for (i, s) in salt.iter().enumerate() {
            pw.set_target(*s, F::from_canonical_u64(i as u64));
        }
        // Set secret key
        pw.set_target(sk, F::from_canonical_u64(123456));
        
        // Generate the proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof).unwrap();
    }
}
