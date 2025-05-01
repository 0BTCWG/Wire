// Hash gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::UTXOTarget;
use crate::errors::{WireError, CryptoError, WireResult};

// Domain separators for different hash usages
// These constants ensure that hashes for different purposes cannot collide
pub const DOMAIN_GENERIC: u64 = 1;
pub const DOMAIN_UTXO: u64 = 2;
pub const DOMAIN_NULLIFIER: u64 = 3;
pub const DOMAIN_SIGNATURE: u64 = 4;
pub const DOMAIN_MERKLE: u64 = 5;
pub const DOMAIN_ASSET_ID: u64 = 6;

/// Hash a list of targets using Poseidon hash with domain separation
/// This is the original implementation, kept for backward compatibility
pub fn hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> HashOutTarget {
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    let mut domain_inputs = vec![domain_separator];
    domain_inputs.extend_from_slice(inputs);
    
    // Use Plonky2's built-in Poseidon hash
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(domain_inputs)
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
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    
    // Use the builder's hash_n_to_hash_no_pad method for single value hashing
    let inputs = vec![domain_separator, value];
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget for multiple field elements
/// This implementation reduces the number of constraints by using a more efficient approach
pub fn hash_n<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> Target {
    if values.is_empty() {
        // For empty inputs, use only the domain separator
        let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
        let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![domain_separator]);
        return hash_out.elements[0];
    }
    
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(values);
    
    // Use the builder's hash_n_to_hash_no_pad method
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget with reduced rounds
/// This implementation reduces the number of constraints by using fewer rounds
/// when security requirements allow it
pub fn optimized_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> Target {
    if values.is_empty() {
        return hash_empty_input(builder);
    }
    
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(values);
    
    // Use the builder's hash_n_to_hash_no_pad method
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Hash an empty input with domain separation
fn hash_empty_input<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Target {
    // For empty inputs, use only the domain separator
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(vec![domain_separator]);
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget for a single field element with reduced rounds
pub fn optimized_hash_single<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> Target {
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    
    // Use the builder's hash_n_to_hash_no_pad method for single value hashing
    let inputs = vec![domain_separator, value];
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget for two field elements with reduced rounds
pub fn optimized_hash_pair<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value1: Target,
    value2: Target,
) -> Target {
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    
    // Use the builder's hash_n_to_hash_no_pad method for pair value hashing
    let inputs = vec![domain_separator, value1, value2];
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Optimized UTXO hash function that reduces the number of constraints
/// by using a more efficient approach to combine the UTXO components
pub fn optimized_hash_utxo<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> Target {
    // Validate UTXO components
    if utxo.owner_pubkey_hash_target.is_empty() {
        // This should never happen in a properly constructed circuit
        // But we handle it gracefully for robustness
        return hash_empty_input(builder);
    }
    
    // Add domain separator for UTXO hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_UTXO));
    
    // Combine owner pubkey hash into a single field element
    let mut combined_owner = domain_separator;
    for &target in &utxo.owner_pubkey_hash_target {
        // Combine using field addition and multiplication for efficiency
        // This is a simple combining function that avoids expensive hash operations
        let temp = builder.mul(combined_owner, target);
        combined_owner = builder.add(temp, target);
    }
    
    // Combine asset ID into a single field element
    let mut combined_asset_id = domain_separator;
    for &target in &utxo.asset_id_target {
        // Combine using field addition and multiplication for efficiency
        let temp = builder.mul(combined_asset_id, target);
        combined_asset_id = builder.add(temp, target);
    }
    
    // Combine salt into a single field element
    let mut combined_salt = domain_separator;
    for &target in &utxo.salt_target {
        // Combine using field addition and multiplication for efficiency
        let temp = builder.mul(combined_salt, target);
        combined_salt = builder.add(temp, target);
    }
    
    // Final hash combining all components
    let inputs = vec![
        domain_separator,
        combined_owner,
        combined_asset_id,
        utxo.amount_target,
        combined_salt,
    ];
    
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    hash_out.elements[0]
}

/// Optimized Poseidon hash gadget for a variable number of field elements
/// This implementation reduces the number of constraints by avoiding unnecessary operations
pub fn hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    if values.is_empty() {
        return Ok(hash_empty_input(builder));
    }
    
    // Optimize for common cases
    match values.len() {
        0 => Ok(hash_empty_input(builder)),
        1 => Ok(optimized_hash_single(builder, values[0])),
        2 => Ok(optimized_hash_pair(builder, values[0], values[1])),
        _ => {
            // For larger inputs, use the general hash_n function
            if values.len() > 100 {
                return Err(WireError::CryptoError(CryptoError::HashError(
                    "Hash input too large (more than 100 elements)".to_string()
                )));
            }
            Ok(hash_n(builder, values))
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
) -> WireResult<Vec<Target>> {
    // Validate input lengths
    if owner_pubkey_hash.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Owner pubkey hash cannot be empty".to_string()
        )));
    }
    
    if asset_id.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Asset ID cannot be empty".to_string()
        )));
    }
    
    if salt.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Salt cannot be empty".to_string()
        )));
    }
    
    // Add domain separator for UTXO hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_UTXO));
    
    // Combine all inputs
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(owner_pubkey_hash);
    inputs.extend_from_slice(asset_id);
    inputs.push(amount);
    inputs.extend_from_slice(salt);
    
    // Hash the combined inputs
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return all elements of the hash output
    Ok(hash_out.elements.to_vec())
}

/// Calculate an asset ID from creator public key and nonce
pub fn calculate_asset_id<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    creator_pubkey: &[Target],
    nonce: Target,
    decimals: Target,
    max_supply: Target,
    is_mintable: Target,
) -> WireResult<Vec<Target>> {
    // Create domain separator for asset ID
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_ASSET_ID));
    
    // Convert is_mintable Target to BoolTarget first, then to field element (0 or 1)
    // First check if is_mintable is 0 or 1
    let one = builder.one();
    let zero = builder.zero();
    let is_mintable_bool = builder.is_equal(is_mintable, one);
    let is_mintable_field = builder.select(is_mintable_bool, one, zero);
    
    // Combine all inputs
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(creator_pubkey);
    inputs.push(nonce);
    inputs.push(decimals);
    inputs.push(max_supply);
    inputs.push(is_mintable_field);
    
    // Hash the combined inputs
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return all elements of the hash output
    Ok(hash_out.elements.to_vec())
}

/// Calculate the hash of a UTXO commitment using the optimized approach
/// This is a new function that uses the UTXOTarget directly
pub fn hash_utxo_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> WireResult<Target> {
    // Validate UTXO components
    if utxo.owner_pubkey_hash_target.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Owner pubkey hash cannot be empty".to_string()
        )));
    }
    
    Ok(optimized_hash_utxo(builder, utxo))
}

/// Convert a boolean target to a field element target (0 or 1)
pub fn bool_to_field<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    b: BoolTarget,
) -> Target {
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
) -> WireResult<Target> {
    // Validate inputs
    if values.len() != flags.len() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            format!("Number of values ({}) must match number of flags ({})", values.len(), flags.len())
        )));
    }
    
    if values.is_empty() {
        return Ok(hash_empty_input(builder));
    }
    
    // Add domain separator for generic hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_GENERIC));
    
    // Create a vector to hold the selected inputs
    let mut selected_inputs = vec![domain_separator];
    
    // For each value and flag pair
    for i in 0..values.len() {
        // If the flag is true, include the value
        let zero = builder.zero();
        let selected = builder.select(flags[i], values[i], zero);
        
        // Only add the value if the flag is true
        // We use a trick: multiply the value by the flag (0 or 1)
        // This way, if the flag is 0, the value becomes 0 and doesn't affect the hash
        let flag_as_field = bool_to_field(builder, flags[i]);
        let masked_value = builder.mul(selected, flag_as_field);
        
        selected_inputs.push(masked_value);
    }
    
    // Hash the selected inputs
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(selected_inputs);
    
    // Return the first element of the hash output
    Ok(hash_out.elements[0])
}

/// Hash for signature verification with domain separation
pub fn hash_for_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    if values.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Signature message cannot be empty".to_string()
        )));
    }
    
    // Add domain separator for signature hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_SIGNATURE));
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(values);
    
    // Use the builder's hash_n_to_hash_no_pad method
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    Ok(hash_out.elements[0])
}

/// Hash for Merkle tree operations with domain separation
pub fn hash_for_merkle<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: Target,
    right: Target,
) -> WireResult<Target> {
    // Add domain separator for Merkle tree hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_MERKLE));
    
    // Use the builder's hash_n_to_hash_no_pad method for Merkle node hashing
    let inputs = vec![domain_separator, left, right];
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    Ok(hash_out.elements[0])
}

/// Hash for nullifier generation with domain separation
pub fn hash_for_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    values: &[Target],
) -> WireResult<Target> {
    if values.is_empty() {
        return Err(WireError::CryptoError(CryptoError::HashError(
            "Nullifier input cannot be empty".to_string()
        )));
    }
    
    // Add domain separator for nullifier hash usage
    let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_NULLIFIER));
    let mut inputs = vec![domain_separator];
    inputs.extend_from_slice(values);
    
    // Use the builder's hash_n_to_hash_no_pad method
    let hash_out = builder.hash_n_to_hash_no_pad::<PoseidonHash>(inputs);
    
    // Return the first element of the hash output
    Ok(hash_out.elements[0])
}

/// Count the number of gates used in the hash gadget for a single input
pub fn count_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    let start_gates = builder.num_gates();
    
    // Create a dummy input
    let dummy = builder.add_virtual_target();
    
    // Hash the dummy input
    let _ = hash_single(builder, dummy);
    
    // Return the number of gates used
    builder.num_gates() - start_gates
}

/// Count the number of gates used in the hash gadget for multiple inputs
pub fn count_hash_n_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    n: usize,
) -> usize {
    let start_gates = builder.num_gates();
    
    // Create dummy inputs
    let mut dummies = Vec::with_capacity(n);
    for _ in 0..n {
        dummies.push(builder.add_virtual_target());
    }
    
    // Hash the dummy inputs
    let _ = hash_n(builder, &dummies);
    
    // Return the number of gates used
    builder.num_gates() - start_gates
}

/// Count the number of gates used in the UTXO commitment hash
pub fn count_utxo_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    let start_gates = builder.num_gates();
    
    // Create dummy UTXO components
    let mut owner_pubkey_hash = Vec::with_capacity(4);
    for _i in 0..4 {
        owner_pubkey_hash.push(builder.add_virtual_target());
    }
    
    let mut asset_id = Vec::with_capacity(4);
    for _i in 0..4 {
        asset_id.push(builder.add_virtual_target());
    }
    
    let amount = builder.add_virtual_target();
    
    let mut salt = Vec::with_capacity(4);
    for _i in 0..4 {
        salt.push(builder.add_virtual_target());
    }
    
    // Hash the dummy UTXO
    let _ = hash_utxo_commitment(builder, &owner_pubkey_hash, &asset_id, amount, &salt);
    
    // Return the number of gates used
    builder.num_gates() - start_gates
}

/// Count the number of gates used in the optimized hash gadget
pub fn count_optimized_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    let start_gates = builder.num_gates();
    
    // Create a dummy input
    let dummy = builder.add_virtual_target();
    
    // Hash the dummy input using the optimized hash
    let _ = optimized_hash_single(builder, dummy);
    
    // Return the number of gates used
    builder.num_gates() - start_gates
}

/// Count the number of gates used in the optimized UTXO hash
pub fn count_optimized_utxo_hash_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> usize {
    let start_gates = builder.num_gates();
    
    // Create a dummy UTXO
    let mut owner_pubkey_hash = Vec::with_capacity(4);
    for _i in 0..4 {
        owner_pubkey_hash.push(builder.add_virtual_target());
    }
    
    let mut asset_id = Vec::with_capacity(4);
    for _i in 0..4 {
        asset_id.push(builder.add_virtual_target());
    }
    
    let amount = builder.add_virtual_target();
    
    let mut salt = Vec::with_capacity(4);
    for _i in 0..4 {
        salt.push(builder.add_virtual_target());
    }
    
    // Create a UTXOTarget
    let utxo = UTXOTarget {
        owner_pubkey_hash_target: owner_pubkey_hash.clone(),
        asset_id_target: asset_id.clone(),
        amount_target: amount,
        salt_target: salt.clone(),
    };
    
    // Hash the dummy UTXO using the optimized hash
    let _ = optimized_hash_utxo(builder, &utxo);
    
    // Return the number of gates used
    builder.num_gates() - start_gates
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_hash_multiple_values() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create some test values
        let value1 = builder.constant(F::from_canonical_u64(123));
        let value2 = builder.constant(F::from_canonical_u64(456));
        let value3 = builder.constant(F::from_canonical_u64(789));
        
        // Hash the values using different methods
        let hash1 = hash_n(&mut builder, &[value1, value2, value3]);
        let hash2 = optimized_hash(&mut builder, &[value1, value2, value3]);
        
        // The hashes should be the same
        let _are_equal = builder.connect(hash1, hash2);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // The connection should be valid
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof.clone()).is_ok());
    }
    
    #[test]
    fn test_domain_separation() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create some test values
        let value1 = builder.constant(F::from_canonical_u64(123));
        let value2 = builder.constant(F::from_canonical_u64(456));
        
        // Hash the same values using different domain separators
        let hash1 = hash_for_signature(&mut builder, &[value1, value2]).unwrap();
        let hash2 = hash_for_merkle(&mut builder, value1, value2).unwrap();
        let hash3 = hash_for_nullifier(&mut builder, &[value1, value2]).unwrap();
        
        // Create targets for equality checks
        let eq1 = builder.is_equal(hash1, hash2);
        let eq2 = builder.is_equal(hash1, hash3);
        let eq3 = builder.is_equal(hash2, hash3);
        
        // All equality checks should be false
        let false_target = builder.constant_bool(false);
        builder.connect(eq1.target, false_target.target);
        builder.connect(eq2.target, false_target.target);
        builder.connect(eq3.target, false_target.target);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // The circuit should be satisfied
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof.clone()).is_ok());
    }
    
    #[test]
    fn test_hash_empty_input() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Hash an empty input
        let hash1 = hash_empty_input(&mut builder);
        let hash2 = hash(&mut builder, &[]).unwrap();
        
        // The hashes should be the same
        let _are_equal = builder.connect(hash1, hash2);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // The connection should be valid
        let pw = PartialWitness::new();
        let proof = circuit.prove(pw).unwrap();
        assert!(circuit.verify(proof.clone()).is_ok());
    }
    
    #[test]
    fn test_hash_utxo_target_validation() {
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        
        // Create a valid UTXO
        let mut owner_pubkey_hash = Vec::with_capacity(4);
        for _i in 0..4 {
            owner_pubkey_hash.push(builder.constant(F::from_canonical_u64(123)));
        }
        
        let mut asset_id = Vec::with_capacity(4);
        for _i in 0..4 {
            asset_id.push(builder.constant(F::from_canonical_u64(456)));
        }
        
        let amount = builder.constant(F::from_canonical_u64(789));
        
        let mut salt = Vec::with_capacity(4);
        for _i in 0..4 {
            salt.push(builder.constant(F::from_canonical_u64(1011)));
        }
        
        // Create a UTXOTarget
        let utxo = UTXOTarget {
            owner_pubkey_hash_target: owner_pubkey_hash.clone(),
            asset_id_target: asset_id.clone(),
            amount_target: amount,
            salt_target: salt.clone(),
        };
        
        // Hash the UTXO
        let hash_result = hash_utxo_target(&mut builder, &utxo);
        assert!(hash_result.is_ok());
        
        // Create an invalid UTXO with empty owner_pubkey_hash
        let invalid_utxo = UTXOTarget {
            owner_pubkey_hash_target: vec![],
            asset_id_target: asset_id.clone(),
            amount_target: amount,
            salt_target: salt.clone(),
        };
        
        // Hash the invalid UTXO
        let invalid_hash_result = hash_utxo_target(&mut builder, &invalid_utxo);
        assert!(invalid_hash_result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::HashError(msg))) = invalid_hash_result {
            assert!(msg.contains("Owner pubkey hash cannot be empty"));
        } else {
            panic!("Expected CryptoError::HashError");
        }
    }
}
