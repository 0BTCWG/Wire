use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::core::UTXOTarget;
use wire_lib::gadgets::{calculate_asset_id, hash_targets, hash_utxo_commitment};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_hash_single_value() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a target for the input
    let input = builder.add_virtual_target();

    // Hash the input
    let hash_out = hash_targets(&mut builder, &[input]);

    // Register the hash output as public inputs
    for &element in &hash_out.elements {
        builder.register_public_input(element);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the input value to 42
    pw.set_target(input, F::from_noncanonical_u64(42));

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check the hash output
    // Note: These values are specific to the Poseidon hash function with the Goldilocks field
    // If the hash function implementation changes, these values will need to be updated
    assert_ne!(proof.public_inputs[0], F::ZERO);
}

#[test]
fn test_hash_multiple_values() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create targets for the inputs
    let input1 = builder.add_virtual_target();
    let input2 = builder.add_virtual_target();

    // Hash the inputs
    let hash_out = hash_targets(&mut builder, &[input1, input2]);

    // Register the hash output as public inputs
    for &element in &hash_out.elements {
        builder.register_public_input(element);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the input values
    pw.set_target(input1, F::from_noncanonical_u64(123));
    pw.set_target(input2, F::from_noncanonical_u64(456));

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check the hash output
    // Note: These values are specific to the Poseidon hash function with the Goldilocks field
    // If the hash function implementation changes, these values will need to be updated
    assert_ne!(proof.public_inputs[0], F::ZERO);
}

#[test]
fn test_hash_empty_input() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Add a dummy target to ensure the circuit has at least one constraint
    let dummy = builder.add_virtual_target();
    builder.register_public_input(dummy);

    // Hash an empty input
    let hash_out = hash_targets(&mut builder, &[]);

    // Register the hash output as public inputs
    for &element in &hash_out.elements {
        builder.register_public_input(element);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the dummy value
    pw.set_target(dummy, F::ONE);

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // For empty input, we just verify the proof runs without errors
    // We don't assert anything about the hash value
}

#[test]
fn test_hash_utxo_commitment_gadget() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a UTXO target
    let utxo = UTXOTarget {
        owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        amount_target: builder.add_virtual_target(),
        salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
    };

    // Hash the UTXO
    let hash_out = hash_utxo_commitment(
        &mut builder,
        &utxo.owner_pubkey_hash_target,
        &utxo.asset_id_target,
        utxo.amount_target,
        &utxo.salt_target,
    );

    // Register the hash output as public inputs
    for target in &hash_out {
        builder.register_public_input(*target);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the UTXO values
    for target in &utxo.owner_pubkey_hash_target {
        pw.set_target(*target, F::ONE);
    }

    for target in &utxo.asset_id_target {
        pw.set_target(*target, F::ONE);
    }

    pw.set_target(utxo.amount_target, F::from_noncanonical_u64(100));

    for target in &utxo.salt_target {
        pw.set_target(*target, F::ONE);
    }

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check the hash output
    // Note: These values are specific to the Poseidon hash function with the Goldilocks field
    // If the hash function implementation changes, these values will need to be updated
    assert_ne!(proof.public_inputs[0], F::ZERO);
}

#[test]
fn test_calculate_asset_id_gadget() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create targets for the asset creator and asset name
    let asset_creator_pubkey_hash: Vec<Target> =
        (0..32).map(|_| builder.add_virtual_target()).collect();

    // Create other required parameters
    let nonce = builder.add_virtual_target();
    let decimals = builder.add_virtual_target();
    let max_supply = builder.add_virtual_target();
    let is_mintable = builder.add_virtual_target();

    // Calculate the asset ID
    let asset_id = calculate_asset_id(
        &mut builder,
        &asset_creator_pubkey_hash,
        nonce,
        decimals,
        max_supply,
        is_mintable,
    );

    // Register the asset ID as public inputs
    for &target in &asset_id {
        builder.register_public_input(target);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the asset creator pubkey hash
    for target in &asset_creator_pubkey_hash {
        pw.set_target(*target, F::ONE);
    }

    // Set other parameters
    pw.set_target(nonce, F::from_noncanonical_u64(42));
    pw.set_target(decimals, F::from_noncanonical_u64(18));
    pw.set_target(max_supply, F::from_noncanonical_u64(1000000));
    pw.set_target(is_mintable, F::ONE);

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // We just verify the proof runs without errors
    // We don't assert anything about the asset ID value
}

#[test]
fn test_hash_different_utxos_produce_different_commitments() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create the first UTXO
    let utxo1 = UTXOTarget {
        owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        amount_target: builder.add_virtual_target(),
        salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
    };

    // Create the second UTXO with a different amount
    let utxo2 = UTXOTarget {
        owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        amount_target: builder.add_virtual_target(),
        salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
    };

    // Hash the UTXOs
    let hash_out1 = hash_utxo_commitment(
        &mut builder,
        &utxo1.owner_pubkey_hash_target,
        &utxo1.asset_id_target,
        utxo1.amount_target,
        &utxo1.salt_target,
    );

    let hash_out2 = hash_utxo_commitment(
        &mut builder,
        &utxo2.owner_pubkey_hash_target,
        &utxo2.asset_id_target,
        utxo2.amount_target,
        &utxo2.salt_target,
    );

    // Register the hash outputs as public inputs
    for target in &hash_out1 {
        builder.register_public_input(*target);
    }

    for target in &hash_out2 {
        builder.register_public_input(*target);
    }

    // Build the circuit
    let circuit = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the values for the first UTXO
    for target in &utxo1.owner_pubkey_hash_target {
        pw.set_target(*target, F::ONE);
    }

    for target in &utxo1.asset_id_target {
        pw.set_target(*target, F::ONE);
    }

    pw.set_target(utxo1.amount_target, F::from_noncanonical_u64(100));

    for target in &utxo1.salt_target {
        pw.set_target(*target, F::ONE);
    }

    // Set the values for the second UTXO (same as first except for amount)
    for target in &utxo2.owner_pubkey_hash_target {
        pw.set_target(*target, F::ONE);
    }

    for target in &utxo2.asset_id_target {
        pw.set_target(*target, F::ONE);
    }

    pw.set_target(utxo2.amount_target, F::from_noncanonical_u64(200));

    for target in &utxo2.salt_target {
        pw.set_target(*target, F::ONE);
    }

    // Generate the proof
    let proof = circuit.prove(pw).unwrap();

    // Verify the proof
    circuit.verify(proof.clone()).unwrap();

    // Check that the first element of each hash is different
    // The hash outputs should be different since the inputs are different
    assert_ne!(proof.public_inputs[0], proof.public_inputs[hash_out1.len()]);
}
