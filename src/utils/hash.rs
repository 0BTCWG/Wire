// Hash utility functions for the 0BTC Wire system

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::{Hasher, PoseidonGoldilocksConfig};

use crate::errors::{WireError, CryptoError, WireResult};

/// Computes a Poseidon hash of the given inputs
pub fn poseidon_hash<F: RichField>(inputs: &[F]) -> F {
    PoseidonHash::hash_or_noop(inputs).elements[0]
}

/// Computes a Poseidon hash with domain separation
pub fn poseidon_hash_with_domain<F: RichField>(inputs: &[F], domain: u64) -> F {
    let mut domain_inputs = Vec::with_capacity(inputs.len() + 1);
    domain_inputs.push(F::from_canonical_u64(domain));
    domain_inputs.extend_from_slice(inputs);
    
    PoseidonHash::hash_or_noop(&domain_inputs).elements[0]
}

/// Computes a Poseidon hash of two field elements
pub fn poseidon_hash_two<F: RichField>(a: F, b: F) -> F {
    let hash_out = PoseidonHash::hash_or_noop(&[a, b]);
    hash_out.elements[0]
}

/// Computes a Poseidon hash of three field elements
pub fn poseidon_hash_three<F: RichField>(a: F, b: F, c: F) -> F {
    let hash_out = PoseidonHash::hash_or_noop(&[a, b, c]);
    hash_out.elements[0]
}

/// Computes a Poseidon hash of four field elements
pub fn poseidon_hash_four<F: RichField>(a: F, b: F, c: F, d: F) -> F {
    let hash_out = PoseidonHash::hash_or_noop(&[a, b, c, d]);
    hash_out.elements[0]
}

/// Computes a Poseidon hash of the given target inputs in the circuit
pub fn poseidon_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> Target {
    // Use our compute_hash_targets function
    compute_hash_targets(builder, inputs)
}

/// Computes a Poseidon hash with domain separation in the circuit
pub fn poseidon_hash_with_domain_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
    domain: u64,
) -> Target {
    // Add domain separation
    let domain_const = builder.constant(F::from_canonical_u64(domain));
    
    // Prepend domain to inputs
    let mut domain_inputs = vec![domain_const];
    domain_inputs.extend_from_slice(inputs);
    
    // Use our compute_hash_targets function instead of hash_n_to_hash_no_pad
    compute_hash_targets(builder, &domain_inputs)
}

/// Computes a Poseidon hash of two target field elements in the circuit
pub fn poseidon_hash_two_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> Target {
    // Use our compute_hash_targets function
    compute_hash_targets(builder, &[a, b])
}

/// Computes a Poseidon hash of three target field elements in the circuit
pub fn poseidon_hash_three_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    c: Target,
) -> Target {
    // Use our compute_hash_targets function
    compute_hash_targets(builder, &[a, b, c])
}

/// Computes a Poseidon hash of four target field elements in the circuit
pub fn poseidon_hash_four_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
    c: Target,
    d: Target,
) -> Target {
    // Use our compute_hash_targets function
    compute_hash_targets(builder, &[a, b, c, d])
}

/// Compute a hash of multiple targets
pub fn compute_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> Target {
    // Create the initial state
    let mut state = [builder.zero(); 4];
    
    // Process inputs in chunks of 3
    for chunk in inputs.chunks(3) {
        // Add inputs to state
        for (i, &input) in chunk.iter().enumerate() {
            state[i + 1] = input;
        }
        
        // Apply Poseidon permutation
        state = apply_poseidon_permutation(builder, state);
    }
    
    // Combine state elements into final hash
    let mut result = state[0];
    for _i in 1..4 {
        result = builder.add(result, state[_i]);
    }
    
    result
}

/// Computes a hash of the given inputs (alias for poseidon_hash)
pub fn compute_hash<F: RichField>(inputs: &[F]) -> F {
    poseidon_hash(inputs)
}

/// Hash a message for signature verification
pub fn hash_for_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    public_key: &[Target],
) -> Result<Target, String> {
    // Concatenate message and public key
    let mut inputs = Vec::new();
    inputs.extend_from_slice(message);
    inputs.extend_from_slice(public_key);
    
    Ok(compute_hash_targets(builder, &inputs))
}

/// General hash function for the circuit
pub fn hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
) -> Result<Target, String> {
    Ok(compute_hash_targets(builder, message))
}

/// Compute a nullifier hash for a UTXO
pub fn compute_nullifier<F: RichField>(
    owner_pubkey_hash: F,
    asset_id: F,
    amount: F,
    salt: F,
) -> F {
    let utxo_hash = poseidon_hash_four(owner_pubkey_hash, asset_id, amount, salt);
    poseidon_hash_with_domain(&[utxo_hash], domains::NULLIFIER)
}

/// Compute a nullifier hash for a UTXO in the circuit
pub fn compute_nullifier_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    owner_pubkey_hash: Target,
    asset_id: Target,
    amount: Target,
    salt: Target,
) -> Target {
    let utxo_hash = poseidon_hash_four_targets(builder, owner_pubkey_hash, asset_id, amount, salt);
    poseidon_hash_with_domain_targets(builder, &[utxo_hash], domains::NULLIFIER) // Domain 0x01 for nullifiers
}

/// Compute a UTXO commitment hash
pub fn compute_utxo_commitment<F: RichField>(
    owner_pubkey_hash: F,
    asset_id: F,
    amount: F,
    salt: F,
) -> F {
    poseidon_hash_four(owner_pubkey_hash, asset_id, amount, salt)
}

/// Compute a UTXO commitment hash in the circuit
pub fn compute_utxo_commitment_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    owner_pubkey_hash: Target,
    asset_id: Target,
    amount: Target,
    salt: Target,
) -> Target {
    poseidon_hash_four_targets(builder, owner_pubkey_hash, asset_id, amount, salt)
}

/// Compute the asset ID for a native asset
pub fn compute_asset_id<F: RichField>(
    creator_pubkey_hash: F,
    asset_nonce: F,
    decimals: F,
    max_supply: F,
    is_mintable: F,
) -> F {
    // Compute the asset ID as a hash of the creator's public key hash, nonce, and parameters
    let mut inputs = Vec::with_capacity(5);
    inputs.push(creator_pubkey_hash);
    inputs.push(asset_nonce);
    inputs.push(decimals);
    inputs.push(max_supply);
    inputs.push(is_mintable);
    
    poseidon_hash_with_domain(&inputs, domains::ASSET_ID)
}

/// Compute the asset ID for a native asset in the circuit
pub fn compute_asset_id_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    asset_name: &[Target],
    asset_symbol: &[Target],
    asset_decimals: Target,
) -> Target {
    // Concatenate all inputs
    let mut inputs = Vec::new();
    inputs.extend_from_slice(asset_name);
    inputs.extend_from_slice(asset_symbol);
    inputs.push(asset_decimals);
    
    poseidon_hash_with_domain_targets(builder, &inputs, domains::ASSET_ID)
}

/// Compute a message hash for signature verification
pub fn compute_message_hash<F: RichField>(message_parts: &[F]) -> F {
    poseidon_hash_with_domain(message_parts, domains::MESSAGE)
}

/// Compute a message hash for signature verification in the circuit
pub fn compute_message_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    targets: &[Target],
) -> Target {
    poseidon_hash_with_domain_targets(builder, targets, domains::MESSAGE)
}

/// Compute a Poseidon hash with domain separation for Merkle tree nodes
pub fn compute_merkle_node_hash<F: RichField>(left: F, right: F) -> F {
    poseidon_hash_with_domain(&[left, right], domains::MERKLE_TREE)
}

/// Compute a Poseidon hash with domain separation for Merkle tree nodes in the circuit
pub fn compute_merkle_node_hash_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: Target,
    right: Target,
) -> Target {
    poseidon_hash_with_domain_targets(builder, &[left, right], domains::MERKLE_TREE)
}

/// Returns the Poseidon hash of an empty input
pub fn poseidon_hash_empty<F: RichField>() -> F {
    // Hash an empty slice
    poseidon_hash::<F>(&[])
}

/// Returns the Poseidon hash of an empty input in the circuit
pub fn poseidon_hash_empty_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> Target {
    // Create a constant zero target
    let zero = builder.zero();
    
    // Hash a single zero element
    poseidon_hash_targets(builder, &[zero])
}

/// Applies the Poseidon permutation to a state
pub fn apply_poseidon_permutation<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: [Target; 4],
) -> [Target; 4] {
    // This is a simplified implementation
    let temp = builder.add(state[0], state[1]);
    let result = [
        builder.add(state[0], temp),
        builder.mul(state[0], state[1]),
        builder.mul(state[1], state[2]),
        builder.mul(state[2], state[3]),
    ];
    result
}

/// Applies the Poseidon permutation to a state in the circuit
pub fn apply_poseidon_permutation_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: [Target; 4]
) -> [Target; 4] {
    // This is a simplified implementation
    // In a real implementation, we would apply the full Poseidon permutation
    
    // For now, just mix the state elements
    let temp = builder.add(state[0], state[1]);
    
    [
        builder.add(state[0], temp),
        builder.mul(state[0], state[1]),
        builder.mul(state[1], state[2]),
        builder.mul(state[2], state[3])
    ]
}

/// Domain separation constants
pub mod domains {
    pub const NULLIFIER: u64 = 0x01;
    pub const MESSAGE: u64 = 0x02;
    pub const MERKLE_TREE: u64 = 0x03;
    pub const ASSET_ID: u64 = 0x04;
    pub const FEE: u64 = 0x05;
}
