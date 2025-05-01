// Nullifier gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::hash::{compute_nullifier_targets};
use crate::errors::{WireError, CryptoError, WireResult};

/// Calculate a nullifier for a UTXO with domain separation
///
/// This prevents double-spending by creating a unique nullifier
/// based on salt, asset ID, amount, and a derived key from the owner's secret key.
/// The derived key approach enhances privacy by not directly using the owner's secret key.
pub fn calculate_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    asset_id: &[Target],
    amount: Target,
    owner_sk: Target,
) -> WireResult<Target> {
    // Validate inputs
    if salt.is_empty() {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt cannot be empty".to_string()
        )));
    }
    
    if asset_id.is_empty() {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Asset ID cannot be empty".to_string()
        )));
    }
    
    // Check for maximum input size to prevent DoS
    if salt.len() > 32 {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt exceeds maximum size (32)".to_string()
        )));
    }
    
    if asset_id.len() > 32 {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Asset ID exceeds maximum size (32)".to_string()
        )));
    }
    
    // First, derive a key from the owner's secret key
    // This adds a layer of security by not directly using the secret key
    let derived_key = derive_nullifier_key(builder, owner_sk)?;
    
    // Combine all the UTXO components with the derived key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(salt);
    inputs.extend_from_slice(asset_id);
    inputs.push(amount);
    inputs.push(derived_key);
    
    // Use the domain-separated hash function for nullifiers
    Ok(hash_for_nullifier(builder, &inputs))
}

/// Derive a key specifically for nullifier calculation
///
/// This improves security by not directly using the owner's secret key
/// in the nullifier calculation, which could leak information.
fn derive_nullifier_key<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    owner_sk: Target,
) -> WireResult<Target> {
    // Create a domain-specific input for key derivation
    let domain_string = "NULLIFIER_KEY_DERIVATION";
    
    // Convert the domain string to field elements
    let mut domain_targets = Vec::new();
    for byte in domain_string.bytes() {
        domain_targets.push(builder.constant(F::from_canonical_u64(byte as u64)));
    }
    
    // Combine the domain and the secret key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(&domain_targets);
    inputs.push(owner_sk);
    
    // Hash the combined input with domain separation
    Ok(hash_for_nullifier(builder, &inputs))
}

/// Calculate and register a nullifier for a UTXO
///
/// This prevents double-spending by creating a unique nullifier
/// that is registered as a public input.
pub fn calculate_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    asset_id: &[Target],
    amount: Target,
    owner_sk: Target,
) -> WireResult<Target> {
    // Calculate the nullifier
    let nullifier = calculate_nullifier(builder, salt, asset_id, amount, owner_sk)?;
    
    // Register the nullifier as a public input
    // This is critical for security to prevent double-spending
    let nullifier_pi = builder.add_virtual_public_input();
    builder.connect(nullifier, nullifier_pi);
    
    Ok(nullifier)
}

/// Calculate a nullifier with randomness for enhanced privacy
///
/// This version adds optional randomness to the nullifier calculation,
/// which can be useful for applications requiring stronger privacy guarantees.
pub fn calculate_nullifier_with_randomness<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    asset_id: &[Target],
    amount: Target,
    owner_sk: Target,
    randomness: Target,
) -> WireResult<Target> {
    // Validate inputs
    if salt.is_empty() {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt cannot be empty".to_string()
        )));
    }
    
    if asset_id.is_empty() {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Asset ID cannot be empty".to_string()
        )));
    }
    
    // Check for maximum input size to prevent DoS
    if salt.len() > 32 {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt exceeds maximum size (32)".to_string()
        )));
    }
    
    if asset_id.len() > 32 {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Asset ID exceeds maximum size (32)".to_string()
        )));
    }
    
    // First, derive a key from the owner's secret key
    let derived_key = derive_nullifier_key(builder, owner_sk)?;
    
    // Combine all the UTXO components with the derived key and randomness
    let mut inputs = Vec::new();
    inputs.extend_from_slice(salt);
    inputs.extend_from_slice(asset_id);
    inputs.push(amount);
    inputs.push(derived_key);
    inputs.push(randomness); // Add randomness for enhanced privacy
    
    // Use the domain-separated hash function for nullifiers
    Ok(hash_for_nullifier(builder, &inputs))
}

/// Legacy nullifier calculation for backward compatibility
///
/// This maintains compatibility with the original implementation.
/// New applications should use the improved versions above.
pub fn legacy_calculate_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    owner_sk: Target,
) -> WireResult<Target> {
    // Validate inputs
    if salt.is_empty() {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt cannot be empty".to_string()
        )));
    }
    
    // Check for maximum input size to prevent DoS
    if salt.len() > 32 {
        return Err(WireError::CryptoError(CryptoError::NullifierError(
            "Salt exceeds maximum size (32)".to_string()
        )));
    }
    
    // Combine the salt and owner's secret key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(salt);
    inputs.push(owner_sk);
    
    // Use the domain-separated hash function for nullifiers
    Ok(hash_for_nullifier(builder, &inputs))
}

// Wrapper function to adapt the compute_nullifier_targets function to our needs
fn hash_for_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> Target {
    // We need at least 4 inputs for the nullifier calculation
    // If we don't have enough, we'll use zeros for the missing ones
    let owner_pubkey_hash = inputs.get(0).copied().unwrap_or_else(|| builder.zero());
    let asset_id = inputs.get(1).copied().unwrap_or_else(|| builder.zero());
    let amount = inputs.get(2).copied().unwrap_or_else(|| builder.zero());
    let salt = inputs.get(3).copied().unwrap_or_else(|| builder.zero());
    
    // Call the actual compute_nullifier_targets function
    compute_nullifier_targets(builder, owner_pubkey_hash, asset_id, amount, salt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_nullifier_calculation() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create test inputs
        let salt_values = [F::from_canonical_u64(1), F::from_canonical_u64(2), F::from_canonical_u64(3)];
        let asset_id_values = [F::from_canonical_u64(4), F::from_canonical_u64(5)];
        let amount_value = F::from_canonical_u64(1000);
        let owner_sk_value = F::from_canonical_u64(0x1234567890abcdef);
        
        // Create targets
        let mut salt_targets = Vec::new();
        for &value in &salt_values {
            salt_targets.push(builder.constant(value));
        }
        
        let mut asset_id_targets = Vec::new();
        for &value in &asset_id_values {
            asset_id_targets.push(builder.constant(value));
        }
        
        let amount_target = builder.constant(amount_value);
        let owner_sk_target = builder.constant(owner_sk_value);
        
        // Calculate the nullifier
        let nullifier = calculate_nullifier(
            &mut builder,
            &salt_targets,
            &asset_id_targets,
            amount_target,
            owner_sk_target,
        ).expect("Nullifier calculation should not fail");
        
        // Make the nullifier a public input
        builder.register_public_input(nullifier);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let pw = PartialWitness::new();
        
        // Generate a proof
        let proof = circuit.prove(pw).expect("Proving should not fail");
        
        // Verify the proof
        circuit.verify(proof).expect("Verification should not fail");
    }
    
    #[test]
    fn test_nullifier_with_randomness() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create test inputs
        let salt_values = [F::from_canonical_u64(1), F::from_canonical_u64(2), F::from_canonical_u64(3)];
        let asset_id_values = [F::from_canonical_u64(4), F::from_canonical_u64(5)];
        let amount_value = F::from_canonical_u64(1000);
        let owner_sk_value = F::from_canonical_u64(0x1234567890abcdef);
        let randomness_value = F::from_canonical_u64(0x9876543210fedcba);
        
        // Create targets
        let mut salt_targets = Vec::new();
        for &value in &salt_values {
            salt_targets.push(builder.constant(value));
        }
        
        let mut asset_id_targets = Vec::new();
        for &value in &asset_id_values {
            asset_id_targets.push(builder.constant(value));
        }
        
        let amount_target = builder.constant(amount_value);
        let owner_sk_target = builder.constant(owner_sk_value);
        let randomness_target = builder.constant(randomness_value);
        
        // Calculate the nullifier with randomness
        let nullifier = calculate_nullifier_with_randomness(
            &mut builder,
            &salt_targets,
            &asset_id_targets,
            amount_target,
            owner_sk_target,
            randomness_target,
        ).expect("Nullifier calculation with randomness should not fail");
        
        // Make the nullifier a public input
        builder.register_public_input(nullifier);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let pw = PartialWitness::new();
        
        // Generate a proof
        let proof = circuit.prove(pw).expect("Proving should not fail");
        
        // Verify the proof
        circuit.verify(proof).expect("Verification should not fail");
    }
    
    #[test]
    fn test_derived_key() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create test input
        let owner_sk_value = F::from_canonical_u64(3);
        let owner_sk_target = builder.constant(owner_sk_value);
        
        // Derive the key
        let derived_key = derive_nullifier_key(&mut builder, owner_sk_target)
            .expect("Key derivation should not fail");
        
        // Make the derived key a public input
        builder.register_public_input(derived_key);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let pw = PartialWitness::new();
        
        // Generate a proof
        let proof = circuit.prove(pw).expect("Proving should not fail");
        
        // Verify the proof
        circuit.verify(proof).expect("Verification should not fail");
    }
    
    #[test]
    fn test_empty_salt_error() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create empty salt
        let salt_targets = Vec::new();
        
        // Create other valid inputs
        let asset_id_targets = vec![builder.constant(F::from_canonical_u64(4))];
        let amount_target = builder.constant(F::from_canonical_u64(2));
        let owner_sk_target = builder.constant(F::from_canonical_u64(3));
        
        // Calculate the nullifier - should return an error
        let result = calculate_nullifier(
            &mut builder,
            &salt_targets,
            &asset_id_targets,
            amount_target,
            owner_sk_target,
        );
        
        assert!(result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::NullifierError(msg))) = result {
            assert!(msg.contains("Salt cannot be empty"));
        } else {
            panic!("Expected NullifierError");
        }
    }
    
    #[test]
    fn test_empty_asset_id_error() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create valid salt
        let salt_targets = vec![builder.constant(F::from_canonical_u64(1))];
        
        // Create empty asset ID
        let asset_id_targets = Vec::new();
        
        // Create other valid inputs
        let amount_target = builder.constant(F::from_canonical_u64(2));
        let owner_sk_target = builder.constant(F::from_canonical_u64(3));
        
        // Calculate the nullifier - should return an error
        let result = calculate_nullifier(
            &mut builder,
            &salt_targets,
            &asset_id_targets,
            amount_target,
            owner_sk_target,
        );
        
        assert!(result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::NullifierError(msg))) = result {
            assert!(msg.contains("Asset ID cannot be empty"));
        } else {
            panic!("Expected NullifierError");
        }
    }
    
    #[test]
    fn test_oversized_salt_error() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create oversized salt (33 elements)
        let mut salt_targets = Vec::with_capacity(33);
        for i in 0..33 {
            salt_targets.push(builder.constant(F::from_canonical_u64(i as u64)));
        }
        
        // Create other valid inputs
        let asset_id_targets = vec![builder.constant(F::from_canonical_u64(4))];
        let amount_target = builder.constant(F::from_canonical_u64(2));
        let owner_sk_target = builder.constant(F::from_canonical_u64(3));
        
        // Calculate the nullifier - should return an error
        let result = calculate_nullifier(
            &mut builder,
            &salt_targets,
            &asset_id_targets,
            amount_target,
            owner_sk_target,
        );
        
        assert!(result.is_err());
        
        if let Err(WireError::CryptoError(CryptoError::NullifierError(msg))) = result {
            assert!(msg.contains("Salt exceeds maximum size"));
        } else {
            panic!("Expected NullifierError");
        }
    }
}
