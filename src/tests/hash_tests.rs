// Unit tests for hash utility functions

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::hash::*;

#[test]
fn test_poseidon_hash() {
    let a = GoldilocksField::from_canonical_u64(123);
    let b = GoldilocksField::from_canonical_u64(456);
    
    // Hash two values
    let hash = poseidon_hash(&[a, b]);
    
    // Hash should be non-zero
    assert!(!hash.is_zero());
    
    // Hash of the same values should be the same
    let hash2 = poseidon_hash(&[a, b]);
    assert_eq!(hash, hash2);
    
    // Hash of different values should be different
    let c = GoldilocksField::from_canonical_u64(789);
    let hash3 = poseidon_hash(&[a, c]);
    assert_ne!(hash, hash3);
}

#[test]
fn test_poseidon_hash_with_domain() {
    let a = GoldilocksField::from_canonical_u64(123);
    let b = GoldilocksField::from_canonical_u64(456);
    
    // Hash with domain separation
    let hash1 = poseidon_hash_with_domain(&[a, b], domains::NULLIFIER);
    let hash2 = poseidon_hash_with_domain(&[a, b], domains::MESSAGE);
    
    // Same inputs with different domains should produce different hashes
    assert_ne!(hash1, hash2);
    
    // Same inputs and domain should produce the same hash
    let hash3 = poseidon_hash_with_domain(&[a, b], domains::NULLIFIER);
    assert_eq!(hash1, hash3);
}

#[test]
fn test_poseidon_hash_convenience_functions() {
    let a = GoldilocksField::from_canonical_u64(123);
    let b = GoldilocksField::from_canonical_u64(456);
    let c = GoldilocksField::from_canonical_u64(789);
    let d = GoldilocksField::from_canonical_u64(101112);
    
    // Test the convenience functions
    let hash_two = poseidon_hash_two(a, b);
    let hash_three = poseidon_hash_three(a, b, c);
    let hash_four = poseidon_hash_four(a, b, c, d);
    
    // Compare with the general function
    assert_eq!(hash_two, poseidon_hash(&[a, b]));
    assert_eq!(hash_three, poseidon_hash(&[a, b, c]));
    assert_eq!(hash_four, poseidon_hash(&[a, b, c, d]));
}

#[test]
fn test_compute_nullifier() {
    let owner_pubkey_hash = GoldilocksField::from_canonical_u64(123);
    let asset_id = GoldilocksField::from_canonical_u64(456);
    let amount = GoldilocksField::from_canonical_u64(789);
    let salt = GoldilocksField::from_canonical_u64(101112);
    
    // Compute nullifier
    let nullifier = compute_nullifier(owner_pubkey_hash, asset_id, amount, salt);
    
    // Nullifier should be non-zero
    assert!(!nullifier.is_zero());
    
    // Same inputs should produce the same nullifier
    let nullifier2 = compute_nullifier(owner_pubkey_hash, asset_id, amount, salt);
    assert_eq!(nullifier, nullifier2);
    
    // Different inputs should produce different nullifiers
    let different_amount = GoldilocksField::from_canonical_u64(999);
    let nullifier3 = compute_nullifier(owner_pubkey_hash, asset_id, different_amount, salt);
    assert_ne!(nullifier, nullifier3);
}

#[test]
fn test_compute_utxo_commitment() {
    let owner_pubkey_hash = GoldilocksField::from_canonical_u64(123);
    let asset_id = GoldilocksField::from_canonical_u64(456);
    let amount = GoldilocksField::from_canonical_u64(789);
    let salt = GoldilocksField::from_canonical_u64(101112);
    
    // Compute UTXO commitment
    let commitment = compute_utxo_commitment(owner_pubkey_hash, asset_id, amount, salt);
    
    // Commitment should be non-zero
    assert!(!commitment.is_zero());
    
    // Same inputs should produce the same commitment
    let commitment2 = compute_utxo_commitment(owner_pubkey_hash, asset_id, amount, salt);
    assert_eq!(commitment, commitment2);
    
    // Different inputs should produce different commitments
    let different_amount = GoldilocksField::from_canonical_u64(999);
    let commitment3 = compute_utxo_commitment(owner_pubkey_hash, asset_id, different_amount, salt);
    assert_ne!(commitment, commitment3);
}

#[test]
fn test_compute_asset_id() {
    let creator_pubkey_hash = GoldilocksField::from_canonical_u64(123);
    let asset_nonce = GoldilocksField::from_canonical_u64(456);
    let decimals = GoldilocksField::from_canonical_u64(18);
    let max_supply = GoldilocksField::from_canonical_u64(1000000);
    let is_mintable = GoldilocksField::from_canonical_u64(1);
    
    // Compute asset ID
    let asset_id = compute_asset_id(creator_pubkey_hash, asset_nonce, decimals, max_supply, is_mintable);
    
    // Asset ID should be non-zero
    assert!(!asset_id.is_zero());
    
    // Same inputs should produce the same asset ID
    let asset_id2 = compute_asset_id(creator_pubkey_hash, asset_nonce, decimals, max_supply, is_mintable);
    assert_eq!(asset_id, asset_id2);
    
    // Different inputs should produce different asset IDs
    let different_nonce = GoldilocksField::from_canonical_u64(789);
    let asset_id3 = compute_asset_id(creator_pubkey_hash, different_nonce, decimals, max_supply, is_mintable);
    assert_ne!(asset_id, asset_id3);
}

#[test]
fn test_compute_message_hash() {
    let a = GoldilocksField::from_canonical_u64(123);
    let b = GoldilocksField::from_canonical_u64(456);
    
    // Compute message hash
    let hash = compute_message_hash(&[a, b]);
    
    // Hash should be non-zero
    assert!(!hash.is_zero());
    
    // Same inputs should produce the same hash
    let hash2 = compute_message_hash(&[a, b]);
    assert_eq!(hash, hash2);
    
    // Different inputs should produce different hashes
    let c = GoldilocksField::from_canonical_u64(789);
    let hash3 = compute_message_hash(&[a, c]);
    assert_ne!(hash, hash3);
    
    // Verify that compute_message_hash uses the MESSAGE domain
    let direct_hash = poseidon_hash_with_domain(&[a, b], domains::MESSAGE);
    assert_eq!(hash, direct_hash);
}

#[test]
fn test_compute_merkle_node_hash() {
    let left = GoldilocksField::from_canonical_u64(123);
    let right = GoldilocksField::from_canonical_u64(456);
    
    // Compute Merkle node hash
    let hash = compute_merkle_node_hash(left, right);
    
    // Hash should be non-zero
    assert!(!hash.is_zero());
    
    // Same inputs should produce the same hash
    let hash2 = compute_merkle_node_hash(left, right);
    assert_eq!(hash, hash2);
    
    // Different inputs should produce different hashes
    let different_right = GoldilocksField::from_canonical_u64(789);
    let hash3 = compute_merkle_node_hash(left, different_right);
    assert_ne!(hash, hash3);
    
    // Order matters for Merkle node hashes
    let hash4 = compute_merkle_node_hash(right, left);
    assert_ne!(hash, hash4);
    
    // Verify that compute_merkle_node_hash uses the MERKLE_TREE domain
    let direct_hash = poseidon_hash_with_domain(&[left, right], domains::MERKLE_TREE);
    assert_eq!(hash, direct_hash);
}

#[test]
fn test_hash_targets_in_circuit() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create two targets
    let a = builder.constant(GoldilocksField::from_canonical_u64(123));
    let b = builder.constant(GoldilocksField::from_canonical_u64(456));
    
    // Hash them
    let hash = poseidon_hash_two_targets(&mut builder, a, b);
    
    // Make the hash a public input
    builder.register_public_input(hash);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check that the hash matches the non-circuit version
    let expected_hash = poseidon_hash_two(
        GoldilocksField::from_canonical_u64(123),
        GoldilocksField::from_canonical_u64(456)
    );
    assert_eq!(pw.public_inputs[0], expected_hash);
}

#[test]
fn test_domain_separated_hash_targets_in_circuit() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create two targets
    let a = builder.constant(GoldilocksField::from_canonical_u64(123));
    let b = builder.constant(GoldilocksField::from_canonical_u64(456));
    
    // Hash them with domain separation
    let hash1 = poseidon_hash_with_domain_targets(&mut builder, &[a, b], domains::NULLIFIER);
    let hash2 = poseidon_hash_with_domain_targets(&mut builder, &[a, b], domains::MESSAGE);
    
    // Check that the hashes are different
    let hashes_equal = builder.is_equal(hash1, hash2);
    let hashes_different = builder.not(hashes_equal);
    
    // Make the result a public input
    builder.register_public_input(hashes_different.target);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check that the hashes are indeed different
    assert_eq!(pw.public_inputs[0], GoldilocksField::ONE);
}

#[test]
fn test_nullifier_targets_in_circuit() {
    // Create a circuit builder
    let mut builder = CircuitBuilder::<GoldilocksField, 2>::new();
    
    // Create targets for UTXO components
    let owner_pubkey_hash = builder.constant(GoldilocksField::from_canonical_u64(123));
    let asset_id = builder.constant(GoldilocksField::from_canonical_u64(456));
    let amount = builder.constant(GoldilocksField::from_canonical_u64(789));
    let salt = builder.constant(GoldilocksField::from_canonical_u64(101112));
    
    // Compute nullifier
    let nullifier = compute_nullifier_targets(&mut builder, owner_pubkey_hash, asset_id, amount, salt);
    
    // Make the nullifier a public input
    builder.register_public_input(nullifier);
    
    // Build the circuit
    let circuit = builder.build();
    
    // Create a proof with public inputs
    let pw = circuit.prove(vec![]).unwrap();
    
    // Verify the proof
    assert!(circuit.verify(pw.clone()).is_ok());
    
    // Check that the nullifier matches the non-circuit version
    let expected_nullifier = compute_nullifier(
        GoldilocksField::from_canonical_u64(123),
        GoldilocksField::from_canonical_u64(456),
        GoldilocksField::from_canonical_u64(789),
        GoldilocksField::from_canonical_u64(101112)
    );
    assert_eq!(pw.public_inputs[0], expected_nullifier);
}
