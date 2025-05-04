//! Tests for the nullifier logic

use plonky2::field::types::Field;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::utils::hash::domains;
use crate::utils::nullifier::{
    calculate_and_register_circuit_nullifier, compute_circuit_specific_nullifier,
    compute_utxo_nullifier, compute_utxo_nullifier_target, UTXOTarget, UTXO,
};

#[test]
fn test_nullifier_uniqueness() {
    // Create a test UTXO
    let owner_pubkey_hash = 1u64.into();
    let asset_id = 2u64.into();
    let amount = 100u64.into();
    let salt = 42u64.into();

    let utxo = UTXO {
        owner_pubkey_hash,
        asset_id,
        amount,
        salt,
    };

    // Compute the nullifier using the native function
    let nullifier = compute_utxo_nullifier(&utxo);

    // Create a different UTXO with just one field changed
    let utxo2 = UTXO {
        owner_pubkey_hash,
        asset_id,
        amount: 101u64.into(), // Different amount
        salt,
    };

    // Compute the nullifier for the second UTXO
    let nullifier2 = compute_utxo_nullifier(&utxo2);

    // Ensure the nullifiers are different
    assert_ne!(
        nullifier, nullifier2,
        "Nullifiers should be different for different UTXOs"
    );
}

#[test]
fn test_circuit_specific_nullifiers() {
    // Use the smallest circuit configuration that works
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a UTXO target
    let hash_size = 4; // Small hash size for testing
    let utxo_target = UTXOTarget::add_virtual(&mut builder, hash_size);

    // Compute nullifiers with different circuit domains
    let transfer_nullifier = compute_circuit_specific_nullifier(
        &mut builder,
        &utxo_target,
        domains::nullifiers::TRANSFER,
    );

    let swap_nullifier =
        compute_circuit_specific_nullifier(&mut builder, &utxo_target, domains::nullifiers::SWAP);

    let add_liquidity_nullifier = compute_circuit_specific_nullifier(
        &mut builder,
        &utxo_target,
        domains::nullifiers::ADD_LIQUIDITY,
    );

    let remove_liquidity_nullifier = compute_circuit_specific_nullifier(
        &mut builder,
        &utxo_target,
        domains::nullifiers::REMOVE_LIQUIDITY,
    );

    // Assert that all nullifiers are different (by adding constraints that check inequality)
    let transfer_eq_swap = builder.is_equal(transfer_nullifier, swap_nullifier);
    let not_transfer_eq_swap = builder.not(transfer_eq_swap);
    builder.assert_one(not_transfer_eq_swap.target);

    let transfer_eq_add = builder.is_equal(transfer_nullifier, add_liquidity_nullifier);
    let not_transfer_eq_add = builder.not(transfer_eq_add);
    builder.assert_one(not_transfer_eq_add.target);

    let transfer_eq_remove = builder.is_equal(transfer_nullifier, remove_liquidity_nullifier);
    let not_transfer_eq_remove = builder.not(transfer_eq_remove);
    builder.assert_one(not_transfer_eq_remove.target);

    let swap_eq_add = builder.is_equal(swap_nullifier, add_liquidity_nullifier);
    let not_swap_eq_add = builder.not(swap_eq_add);
    builder.assert_one(not_swap_eq_add.target);

    let swap_eq_remove = builder.is_equal(swap_nullifier, remove_liquidity_nullifier);
    let not_swap_eq_remove = builder.not(swap_eq_remove);
    builder.assert_one(not_swap_eq_remove.target);

    let add_eq_remove = builder.is_equal(add_liquidity_nullifier, remove_liquidity_nullifier);
    let not_add_eq_remove = builder.not(add_eq_remove);
    builder.assert_one(not_add_eq_remove.target);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set values for the UTXO target
    for i in 0..hash_size {
        pw.set_target(
            utxo_target.owner_pubkey_hash_target[i],
            F::from_canonical_u64(i as u64 + 1),
        );
        pw.set_target(
            utxo_target.asset_id_target[i],
            F::from_canonical_u64(i as u64 + 10),
        );
    }

    pw.set_target(utxo_target.amount_target[0], F::from_canonical_u64(100));

    for i in 0..hash_size {
        pw.set_target(
            utxo_target.salt_target[i],
            F::from_canonical_u64(i as u64 + 20),
        );
    }

    // Generate the proof - this should succeed if all constraints are satisfied
    let proof = circuit.prove(pw).expect("Failed to generate proof");

    // Verify the proof
    circuit.verify(proof).expect("Failed to verify proof");
}

#[test]
fn test_register_nullifier() {
    // Use the smallest circuit configuration that works
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a UTXO target
    let hash_size = 4; // Small hash size for testing
    let utxo_target = UTXOTarget::add_virtual(&mut builder, hash_size);

    // Register a nullifier as a public input
    let nullifier = calculate_and_register_circuit_nullifier(
        &mut builder,
        &utxo_target,
        domains::nullifiers::TRANSFER,
    );

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set values for the UTXO target
    for i in 0..hash_size {
        pw.set_target(
            utxo_target.owner_pubkey_hash_target[i],
            F::from_canonical_u64(i as u64 + 1),
        );
        pw.set_target(
            utxo_target.asset_id_target[i],
            F::from_canonical_u64(i as u64 + 10),
        );
    }

    pw.set_target(utxo_target.amount_target[0], F::from_canonical_u64(100));

    for i in 0..hash_size {
        pw.set_target(
            utxo_target.salt_target[i],
            F::from_canonical_u64(i as u64 + 20),
        );
    }

    // Generate the proof
    let proof = circuit.prove(pw).expect("Failed to generate proof");

    // Verify the proof
    circuit.verify(proof).expect("Failed to verify proof");

    // Check that the nullifier is included in the public inputs
    assert!(
        circuit.public_inputs.contains(&nullifier),
        "Nullifier should be included in the public inputs"
    );
}
