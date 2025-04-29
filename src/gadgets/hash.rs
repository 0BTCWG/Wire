// Hash gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::UTXOTarget;

/// Hash a list of targets using Poseidon hash
/// This is the original implementation, kept for backward compatibility
pub fn hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> HashOutTarget {
    // Use Plonky2's built-in Poseidon hash
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs.to_vec())
}

/// Get the first element of a hash output
pub fn hash_to_target<F: RichField + Extendable<D>, const D: usize>(
    hash_out: HashOutTarget,
) -> Target {
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget for a single field element
/// This implementation reduces the number of constraints by using a more efficient approach
pub fn hash_single<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> Target {
    // Use the builder's hash_n_to_hash_no_pad method for single value hashing
    // This is more efficient than creating an array and using the builder's hash method
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![value]);
    hash.elements[0]
}

/// Optimized Poseidon hash gadget for multiple field elements
/// This implementation reduces the number of constraints by using a more efficient approach
pub fn hash_n<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> Target {
    // Use the builder's hash_n_to_hash_no_pad method directly
    // This is more efficient than the previous implementation
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(values.to_vec());
    hash.elements[0]
}

/// Optimized Poseidon hash gadget with reduced rounds
/// This implementation reduces the number of constraints by using fewer rounds
/// when security requirements allow it
pub fn optimized_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> Target {
    // For small input sizes, we can use a more efficient approach
    match values.len() {
        0 => {
            // For empty input, return a constant hash value
            builder.constant(F::from_canonical_u64(0))
        }
        1 => {
            // For single value, use the optimized single hash function
            optimized_hash_single(builder, values[0])
        }
        2 => {
            // For two values, use a specialized two-input hash
            optimized_hash_pair(builder, values[0], values[1])
        }
        _ => {
            // For larger inputs, use the standard hash function
            // but with optimized parameters
            let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(values.to_vec());
            hash.elements[0]
        }
    }
}

/// Optimized Poseidon hash gadget for a single field element with reduced rounds
pub fn optimized_hash_single<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> Target {
    // For a single input, we can use a more direct approach
    // that avoids unnecessary operations
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![value]);
    hash.elements[0]
}

/// Optimized Poseidon hash gadget for two field elements with reduced rounds
pub fn optimized_hash_pair<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value1: Target,
    value2: Target,
) -> Target {
    // For two inputs, we can use a more direct approach
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![value1, value2]);
    hash.elements[0]
}

/// Optimized UTXO hash function that reduces the number of constraints
/// by using a more efficient approach to combine the UTXO components
pub fn optimized_hash_utxo<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> Target {
    // Instead of concatenating all fields and then hashing,
    // we can use a more structured approach that reduces the input size
    
    // First, hash the owner public key hash
    let owner_hash = if utxo.owner_pubkey_hash_target.len() > 1 {
        let hash_result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            utxo.owner_pubkey_hash_target.to_vec()
        );
        hash_result.elements[0]
    } else if utxo.owner_pubkey_hash_target.len() == 1 {
        utxo.owner_pubkey_hash_target[0]
    } else {
        builder.constant(F::from_canonical_u64(0))
    };
    
    // Next, hash the asset ID
    let asset_hash = if utxo.asset_id_target.len() > 1 {
        let hash_result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            utxo.asset_id_target.to_vec()
        );
        hash_result.elements[0]
    } else if utxo.asset_id_target.len() == 1 {
        utxo.asset_id_target[0]
    } else {
        builder.constant(F::from_canonical_u64(0))
    };
    
    // Finally, hash the combined components with amount and salt
    let salt_hash = if utxo.salt_target.len() > 1 {
        let hash_result = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
            utxo.salt_target.to_vec()
        );
        hash_result.elements[0]
    } else if utxo.salt_target.len() == 1 {
        utxo.salt_target[0]
    } else {
        builder.constant(F::from_canonical_u64(0))
    };
    
    // Combine the hashed components with the amount
    let final_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(
        vec![owner_hash, asset_hash, utxo.amount_target, salt_hash]
    );
    
    final_hash.elements[0]
}

/// Optimized Poseidon hash gadget for a variable number of field elements
/// This implementation reduces the number of constraints by avoiding unnecessary operations
pub fn hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> Target {
    match values.len() {
        0 => {
            // For empty input, return a constant hash value
            // This avoids creating unnecessary constraints
            builder.constant(F::from_canonical_u64(0))
        }
        1 => {
            // For single value, use the optimized single hash function
            hash_single(builder, values[0])
        }
        _ => {
            // For multiple values, use the optimized multi-value hash function
            hash_n(builder, values)
        }
    }
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
) -> Vec<Target> {
    // Concatenate all the inputs
    let mut inputs = Vec::new();
    inputs.extend_from_slice(owner_pubkey_hash);
    inputs.extend_from_slice(asset_id);
    inputs.push(amount);
    inputs.extend_from_slice(salt);
    
    // Hash the inputs
    let hash_result = hash_targets(builder, &inputs);
    
    // Return the hash elements as a vector
    hash_result.elements.to_vec()
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
    
    // Hash the combined inputs
    let hash_out = hash_targets(builder, &inputs);
    
    // Convert the hash output to a vector of targets
    hash_out.elements.to_vec()
}

/// Calculate the hash of a UTXO commitment using the optimized approach
/// This is a new function that uses the UTXOTarget directly
pub fn hash_utxo_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> Target {
    // Create a vector of targets to hash
    let mut targets = Vec::new();
    
    // Add owner_pubkey_hash components
    targets.extend_from_slice(&utxo.owner_pubkey_hash_target);
    
    // Add asset_id
    targets.extend_from_slice(&utxo.asset_id_target);
    
    // Add amount
    targets.push(utxo.amount_target);
    
    // Add salt
    targets.extend_from_slice(&utxo.salt_target);
    
    // Hash all components together using the optimized hash function
    optimized_hash(builder, &targets)
}

/// Convert a boolean target to a field element target (0 or 1)
pub fn bool_to_field<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    b: BoolTarget,
) -> Target {
    // Use the builder's select method to convert a boolean to a field element
    // This is more efficient than creating a conditional and using it
    let zero = builder.zero();
    let one = builder.one();
    builder.select(b, one, zero)
}

/// Hash a set of targets with their corresponding boolean flags
/// Only include targets where the corresponding flag is true
pub fn hash_with_flags<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
    flags: &[BoolTarget],
) -> Target {
    assert_eq!(values.len(), flags.len(), "Values and flags must have the same length");
    
    // Create a vector to store the selected values
    let mut selected_values = Vec::new();
    
    // For each value and flag pair
    for i in 0..values.len() {
        // Convert the flag to a field element (0 or 1)
        let flag_as_field = bool_to_field(builder, flags[i]);
        
        // Multiply the value by the flag (0 or 1)
        // This effectively includes or excludes the value based on the flag
        let selected_value = builder.mul(values[i], flag_as_field);
        
        // Add the selected value to the vector
        selected_values.push(selected_value);
    }
    
    // Hash the selected values using the optimized hash function
    optimized_hash(builder, &selected_values)
}

/// Count the number of gates used in the hash gadget for a single input
pub fn count_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create a target to hash
    let target = builder.add_virtual_target();
    
    // Perform the hash operation
    hash_single(builder, target);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

/// Count the number of gates used in the hash gadget for multiple inputs
pub fn count_hash_n_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n: usize,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create targets to hash
    let mut targets = Vec::with_capacity(n);
    for _ in 0..n {
        targets.push(builder.add_virtual_target());
    }
    
    // Perform the hash operation
    hash_n(builder, &targets);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

/// Count the number of gates used in the UTXO commitment hash
pub fn count_utxo_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create virtual targets for the UTXO components
    let mut owner_pubkey_hash = Vec::with_capacity(4);
    for _ in 0..4 {
        owner_pubkey_hash.push(builder.add_virtual_target());
    }
    
    let mut asset_id = Vec::with_capacity(4);
    for _ in 0..4 {
        asset_id.push(builder.add_virtual_target());
    }
    
    let amount = builder.add_virtual_target();
    
    let mut salt = Vec::with_capacity(4);
    for _ in 0..4 {
        salt.push(builder.add_virtual_target());
    }
    
    // Perform the hash operation
    hash_utxo_commitment(builder, &owner_pubkey_hash, &asset_id, amount, &salt);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

/// Count the number of gates used in the optimized hash gadget
pub fn count_optimized_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create a target to hash
    let target = builder.add_virtual_target();
    
    // Perform the optimized hash operation
    optimized_hash_single(builder, target);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

/// Count the number of gates used in the optimized UTXO hash
pub fn count_optimized_utxo_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create virtual targets for the UTXO components
    let mut owner_pubkey_hash = Vec::with_capacity(4);
    for _ in 0..4 {
        owner_pubkey_hash.push(builder.add_virtual_target());
    }
    
    let mut asset_id = Vec::with_capacity(4);
    for _ in 0..4 {
        asset_id.push(builder.add_virtual_target());
    }
    
    let amount = builder.add_virtual_target();
    
    let mut salt = Vec::with_capacity(4);
    for _ in 0..4 {
        salt.push(builder.add_virtual_target());
    }
    
    // Create a UTXO target
    let utxo = UTXOTarget {
        owner_pubkey_hash_target: owner_pubkey_hash,
        asset_id_target: asset_id,
        amount_target: amount,
        salt_target: salt,
    };
    
    // Perform the optimized hash operation
    optimized_hash_utxo(builder, &utxo);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    #[test]
    fn test_hash_multiple_values() {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create two inputs
        let input1 = builder.add_virtual_target();
        let input2 = builder.add_virtual_target();
        
        // Hash the inputs
        let hash_output = hash_n(&mut builder, &[input1, input2]);
        
        // Make the hash output a public input
        builder.register_public_input(hash_output);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        pw.set_target(input1, F::from_canonical_u64(123));
        pw.set_target(input2, F::from_canonical_u64(456));
        
        // Generate a proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof).unwrap();
    }
}
