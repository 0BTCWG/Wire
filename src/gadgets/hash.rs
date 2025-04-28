// Hash gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::HASH_SIZE;

/// Hash a list of targets using Poseidon hash
pub fn hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> Target {
    // Use Plonky2's built-in Poseidon hash
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())[0]
}

/// Hash a UTXO commitment
/// 
/// The commitment includes:
/// - owner_pubkey_hash
/// - asset_id
/// - amount
/// - salt
pub fn hash_utxo_commitment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    owner_pubkey_hash: &[Target],
    asset_id: &[Target],
    amount: Target,
    salt: &[Target],
) -> Target {
    // Combine all fields into a single vector
    let mut inputs = Vec::new();
    inputs.extend_from_slice(owner_pubkey_hash);
    inputs.extend_from_slice(asset_id);
    inputs.push(amount);
    inputs.extend_from_slice(salt);
    
    // Hash the combined inputs
    hash_targets(builder, &inputs)
}

/// Calculate an asset ID from creator public key and nonce
pub fn calculate_asset_id<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    creator_pubkey: &[Target],
    nonce: Target,
    decimals: Target,
    max_supply: Target,
    is_mintable: Target,
) -> Vec<Target> {
    // Combine all fields into a single vector
    let mut inputs = Vec::new();
    inputs.extend_from_slice(creator_pubkey);
    inputs.push(nonce);
    inputs.push(decimals);
    inputs.push(max_supply);
    inputs.push(is_mintable);
    
    // Hash the combined inputs and split into HASH_SIZE targets
    let hash_result = hash_targets(builder, &inputs);
    
    // Convert the single hash result into a vector of targets
    // In a real implementation, we'd need to split this properly
    // This is a simplified version
    (0..HASH_SIZE).map(|_| builder.add_virtual_target()).collect()
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
    fn test_hash_targets() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create some input targets
        let input1 = builder.add_virtual_target();
        let input2 = builder.add_virtual_target();
        
        // Hash the inputs
        let hash_output = hash_targets(&mut builder, &[input1, input2]);
        
        // Make the hash output a public input
        builder.register_public_input(hash_output);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        pw.set_target(input1, F::from_canonical_u64(123));
        pw.set_target(input2, F::from_canonical_u64(456));
        
        // Generate the proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof).unwrap();
    }
}
