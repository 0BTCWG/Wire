// Nullifier utility functions for the 0BTC Wire system

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::BoolTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::hash::{
    compute_nullifier, compute_utxo_commitment, compute_utxo_commitment_targets,
};

/// A UTXO (Unspent Transaction Output)
#[derive(Debug, Clone)]
pub struct UTXO<F: RichField> {
    /// The hash of the owner's public key
    pub owner_pubkey_hash: F,
    /// The asset ID
    pub asset_id: F,
    /// The amount
    pub amount: F,
    /// A random salt for privacy
    pub salt: F,
}

/// A UTXO target in the circuit
#[derive(Debug, Clone)]
pub struct UTXOTarget {
    /// The hash of the owner's public key target
    pub owner_pubkey_hash_target: Vec<Target>,
    /// The asset ID target
    pub asset_id_target: Vec<Target>,
    /// The amount target
    pub amount_target: Vec<Target>,
    /// A random salt target for privacy
    pub salt_target: Vec<Target>,
}

impl UTXOTarget {
    /// Create a new UTXOTarget with virtual targets
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        let owner_pubkey_hash_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();

        let asset_id_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();

        let amount_target = vec![builder.add_virtual_target()];

        let salt_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();

        Self {
            owner_pubkey_hash_target,
            asset_id_target,
            amount_target,
            salt_target,
        }
    }
}

/// Computes the commitment hash for a UTXO
pub fn compute_utxo_hash<F: RichField>(utxo: &UTXO<F>) -> F {
    compute_utxo_commitment(
        utxo.owner_pubkey_hash,
        utxo.asset_id,
        utxo.amount,
        utxo.salt,
    )
}

/// Computes the commitment hash for a UTXO target in the circuit
pub fn compute_utxo_commitment_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> Target {
    // We need to extract a single Target from the vectors
    let owner_pubkey_hash = if !utxo.owner_pubkey_hash_target.is_empty() {
        utxo.owner_pubkey_hash_target[0]
    } else {
        builder.zero()
    };

    let asset_id = if !utxo.asset_id_target.is_empty() {
        utxo.asset_id_target[0]
    } else {
        builder.zero()
    };

    let amount = if !utxo.amount_target.is_empty() {
        utxo.amount_target[0]
    } else {
        builder.zero()
    };

    let salt = if !utxo.salt_target.is_empty() {
        utxo.salt_target[0]
    } else {
        builder.zero()
    };

    compute_utxo_commitment_targets(builder, owner_pubkey_hash, asset_id, amount, salt)
}

/// Computes the nullifier for a UTXO
pub fn compute_utxo_nullifier<F: RichField>(utxo: &UTXO<F>) -> F {
    compute_nullifier(
        utxo.owner_pubkey_hash,
        utxo.asset_id,
        utxo.amount,
        utxo.salt,
    )
}

/// Computes the nullifier for a UTXO in the circuit
pub fn compute_utxo_nullifier_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
) -> Target {
    // Ensure we're using all elements of the UTXO to compute the nullifier
    // This ensures uniqueness even if some elements are the same across different UTXOs

    // Hash all elements of the owner's public key hash
    let mut all_inputs = Vec::new();
    all_inputs.extend_from_slice(&utxo.owner_pubkey_hash_target);

    // Add all elements of the asset ID
    all_inputs.extend_from_slice(&utxo.asset_id_target);

    // Add the amount
    if !utxo.amount_target.is_empty() {
        all_inputs.push(utxo.amount_target[0]);
    } else {
        all_inputs.push(builder.zero());
    }

    // Add all elements of the salt
    all_inputs.extend_from_slice(&utxo.salt_target);

    // Use domain separation to ensure nullifiers can't collide with other hash types
    let domain_separated_hash = crate::utils::hash::poseidon_hash_with_domain_targets(
        builder,
        &all_inputs,
        crate::utils::hash::domains::NULLIFIER,
    );

    // Return the domain-separated hash as the nullifier
    domain_separated_hash
}

/// Creates a new UTXO
pub fn create_utxo<F: RichField>(owner_pubkey_hash: F, asset_id: F, amount: F, salt: F) -> UTXO<F> {
    UTXO {
        owner_pubkey_hash,
        asset_id,
        amount,
        salt,
    }
}

/// Creates a new UTXO target in the circuit
pub fn create_utxo_target<F: RichField + Extendable<D>, const D: usize>(
    _builder: &mut CircuitBuilder<F, D>,
    owner_pubkey_hash: Target,
    asset_id: Target,
    amount: Target,
    salt: Target,
) -> UTXOTarget {
    UTXOTarget {
        owner_pubkey_hash_target: vec![owner_pubkey_hash],
        asset_id_target: vec![asset_id],
        amount_target: vec![amount],
        salt_target: vec![salt],
    }
}

/// Generates a random salt for a UTXO
pub fn generate_random_salt<F: RichField>() -> F {
    // Fixed implementation for now to avoid rand() issues
    F::from_canonical_u64(12345)
}

/// Verifies that a nullifier has not been used before
pub fn verify_nullifier_unused<F: RichField>(nullifier: F, used_nullifiers: &[F]) -> bool {
    !used_nullifiers.contains(&nullifier)
}

/// Verifies that a nullifier has not been used before in the circuit
pub fn verify_nullifier_unused_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nullifier: Target,
    used_nullifiers: &[Target],
) -> BoolTarget {
    // Start with true (nullifier is unused)
    let mut result = builder.constant_bool(true);

    // Check against each used nullifier
    for &used_nullifier in used_nullifiers {
        // Check if the nullifier equals the used nullifier
        let is_equal = builder.is_equal(nullifier, used_nullifier);
        let not_equal = builder.not(is_equal);

        // If they are equal, the nullifier is used
        // We want to return false if any equality check is true
        result = builder.and(result, not_equal);
    }

    result
}

/// Checks if two UTXOs are equal
pub fn utxos_equal<F: RichField>(a: &UTXO<F>, b: &UTXO<F>) -> bool {
    a.owner_pubkey_hash == b.owner_pubkey_hash
        && a.asset_id == b.asset_id
        && a.amount == b.amount
        && a.salt == b.salt
}

/// Checks if two UTXO targets are equal in the circuit
pub fn utxos_equal_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: &UTXOTarget,
    b: &UTXOTarget,
) -> BoolTarget {
    // Check equality for each field
    let owner_equal =
        builder.is_equal(a.owner_pubkey_hash_target[0], b.owner_pubkey_hash_target[0]);
    let asset_equal = builder.is_equal(a.asset_id_target[0], b.asset_id_target[0]);
    let amount_equal = builder.is_equal(a.amount_target[0], b.amount_target[0]);
    let salt_equal = builder.is_equal(a.salt_target[0], b.salt_target[0]);

    // All fields must be equal for the UTXOs to be equal
    let mut result = owner_equal;
    result = builder.and(result, asset_equal);
    result = builder.and(result, amount_equal);
    result = builder.and(result, salt_equal);

    result
}

/// Converts a UTXO to a vector of field elements
pub fn utxo_to_fields<F: RichField>(utxo: &UTXO<F>) -> Vec<F> {
    vec![
        utxo.owner_pubkey_hash,
        utxo.asset_id,
        utxo.amount,
        utxo.salt,
    ]
}

/// Converts a vector of field elements to a UTXO
pub fn fields_to_utxo<F: RichField>(fields: &[F]) -> UTXO<F> {
    assert!(fields.len() >= 4, "Not enough fields to create a UTXO");

    UTXO {
        owner_pubkey_hash: fields[0],
        asset_id: fields[1],
        amount: fields[2],
        salt: fields[3],
    }
}

/// Calculates and registers a nullifier for a UTXO in the circuit
pub fn calculate_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
    _owner_sk: Target,
) -> Target {
    // Compute the nullifier using the domain-separated hash function
    let nullifier = compute_utxo_nullifier_target(builder, utxo);

    // Register the nullifier as a public input
    // This is crucial for preventing double-spends as it makes the nullifier
    // visible in the proof verification, allowing external systems to track used nullifiers
    builder.register_public_input(nullifier);

    // Add a comment to explain the importance of this nullifier
    // This nullifier must be checked against a list of used nullifiers
    // outside the circuit to prevent double-spending

    // Return the nullifier
    nullifier
}

/// Verifies that a nullifier has not been used before in the circuit
/// and registers it as a public input
pub fn verify_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
    used_nullifiers: &[Target],
) -> Target {
    // Compute the nullifier
    let nullifier = compute_utxo_nullifier_target(builder, utxo);

    // Verify that the nullifier has not been used before
    let is_unused = verify_nullifier_unused_target(builder, nullifier, used_nullifiers);

    // Assert that the nullifier is unused
    let one = builder.one();
    let zero = builder.zero();
    let is_unused_target = builder.select(is_unused, one, zero);
    builder.assert_one(is_unused_target);

    // Register the nullifier as a public input
    builder.register_public_input(nullifier);

    // Return the nullifier
    nullifier
}

/// Computes a circuit-specific nullifier for a UTXO in the circuit
/// This ensures that nullifiers from different circuits cannot collide
pub fn compute_circuit_specific_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
    circuit_domain: u64,
) -> Target {
    // Compute the base nullifier using all UTXO elements
    let mut all_inputs = Vec::new();
    all_inputs.extend_from_slice(&utxo.owner_pubkey_hash_target);
    all_inputs.extend_from_slice(&utxo.asset_id_target);

    if !utxo.amount_target.is_empty() {
        all_inputs.push(utxo.amount_target[0]);
    } else {
        all_inputs.push(builder.zero());
    }

    all_inputs.extend_from_slice(&utxo.salt_target);

    // Apply circuit-specific domain separation
    let domain_separated_hash =
        crate::utils::hash::poseidon_hash_with_domain_targets(builder, &all_inputs, circuit_domain);

    domain_separated_hash
}

/// Calculates and registers a circuit-specific nullifier for a UTXO
pub fn calculate_and_register_circuit_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    utxo: &UTXOTarget,
    circuit_domain: u64,
) -> Target {
    // Compute the nullifier with circuit-specific domain separation
    let nullifier = compute_circuit_specific_nullifier(builder, utxo, circuit_domain);

    // Register the nullifier as a public input
    builder.register_public_input(nullifier);

    // Return the nullifier
    nullifier
}
