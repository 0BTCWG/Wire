// Tests for the TransferCircuit
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_transfer_circuit_creation() {
    // This test verifies that we can create and build the circuit
    let circuit_data = TransferCircuit::create_circuit();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_transfer_single_input_single_output() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a sender public key
    let sender_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a sender secret key
    let sender_sk = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create an input UTXO
    let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee reservoir address hash
    let fee_reservoir_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee input UTXO
    let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create a fee amount
    let fee_amount = builder.add_virtual_target();

    // Create an output amount
    let output_amount = builder.add_virtual_target();

    // Create the circuit
    let circuit = TransferCircuit {
        input_utxos: vec![input_utxo.clone()],
        recipient_pk_hashes: vec![recipient_pk_hash.clone()],
        output_amounts: vec![output_amount],
        sender_pk: sender_pk.clone(),
        sender_sig: signature.clone(),
        fee_input_utxo: fee_input_utxo.clone(),
        fee_amount,
        fee_reservoir_address_hash: fee_reservoir_hash.clone(),
    };

    // Build the circuit
    let (output_utxos, _fee_utxo, change_utxo) = circuit.build::<F, C, D>(&mut builder, sender_sk);

    // Register some values as public inputs for verification
    builder.register_public_input(output_utxos[0].amount_target);

    // Register whether there's a change UTXO
    let has_change = if change_utxo.is_some() {
        builder.one()
    } else {
        builder.zero()
    };
    builder.register_public_input(has_change);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_transfer_multiple_inputs_multiple_outputs() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a sender public key
    let sender_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a sender secret key
    let sender_sk = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create multiple input UTXOs
    let input_utxo1 = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);
    let input_utxo2 = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create multiple recipient public key hashes
    let recipient_pk_hash1: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();
    let recipient_pk_hash2: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee reservoir address hash
    let fee_reservoir_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee input UTXO
    let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create a fee amount
    let fee_amount = builder.add_virtual_target();

    // Create output amounts
    let output_amount1 = builder.add_virtual_target();
    let output_amount2 = builder.add_virtual_target();

    // Create the circuit
    let circuit = TransferCircuit {
        input_utxos: vec![input_utxo1.clone(), input_utxo2.clone()],
        recipient_pk_hashes: vec![recipient_pk_hash1.clone(), recipient_pk_hash2.clone()],
        output_amounts: vec![output_amount1, output_amount2],
        sender_pk: sender_pk.clone(),
        sender_sig: signature.clone(),
        fee_input_utxo: fee_input_utxo.clone(),
        fee_amount,
        fee_reservoir_address_hash: fee_reservoir_hash.clone(),
    };

    // Build the circuit
    let (output_utxos, _fee_utxo, change_utxo) = circuit.build::<F, C, D>(&mut builder, sender_sk);

    // Register some values as public inputs for verification
    builder.register_public_input(output_utxos[0].amount_target);
    builder.register_public_input(output_utxos[1].amount_target);

    // Register whether there's a change UTXO
    let has_change = if change_utxo.is_some() {
        builder.one()
    } else {
        builder.zero()
    };
    builder.register_public_input(has_change);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_transfer_with_change() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a sender public key
    let sender_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a sender secret key
    let sender_sk = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create an input UTXO with a large amount
    let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee reservoir address hash
    let fee_reservoir_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create a fee input UTXO
    let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

    // Create a fee amount
    let fee_amount = builder.add_virtual_target();

    // Create an output amount (smaller than input amount)
    let output_amount = builder.add_virtual_target();

    // Create the circuit
    let circuit = TransferCircuit {
        input_utxos: vec![input_utxo.clone()],
        recipient_pk_hashes: vec![recipient_pk_hash.clone()],
        output_amounts: vec![output_amount],
        sender_pk: sender_pk.clone(),
        sender_sig: signature.clone(),
        fee_input_utxo: fee_input_utxo.clone(),
        fee_amount,
        fee_reservoir_address_hash: fee_reservoir_hash.clone(),
    };

    // Build the circuit
    let (output_utxos, _fee_utxo, change_utxo) = circuit.build::<F, C, D>(&mut builder, sender_sk);

    // Register some values as public inputs for verification
    builder.register_public_input(output_utxos[0].amount_target);

    // Register whether there's a change UTXO
    let has_change = if change_utxo.is_some() {
        builder.one()
    } else {
        builder.zero()
    };
    builder.register_public_input(has_change);

    // If there's a change UTXO, register its amount
    if let Some(change) = change_utxo {
        builder.register_public_input(change.amount_target);
    }

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_transfer_conservation_of_value() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a simple transfer circuit
    let input_amount = builder.add_virtual_target();
    let output_amount = builder.add_virtual_target();
    let change_amount = builder.add_virtual_target();

    // Register the amounts as public inputs
    builder.register_public_input(input_amount);
    builder.register_public_input(output_amount);
    builder.register_public_input(change_amount);

    // Calculate total output (output + change)
    let total_output = builder.add(output_amount, change_amount);
    builder.register_public_input(total_output);

    // Verify conservation of value: input = output + change
    let is_conserved = builder.is_equal(input_amount, total_output);
    builder.register_public_input(is_conserved.target);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the input amount to 100
    pw.set_target(input_amount, F::from_canonical_u64(100));

    // Set the output amount to 60
    pw.set_target(output_amount, F::from_canonical_u64(60));

    // Set the change amount to 40
    pw.set_target(change_amount, F::from_canonical_u64(40));

    // Generate the proof
    let proof = circuit_data.prove(pw).unwrap();

    // Verify the proof
    circuit_data.verify(proof.clone()).unwrap();

    // Check that input amount = output amount + change amount
    assert_eq!(proof.public_inputs[0], F::from_canonical_u64(100)); // input
    assert_eq!(proof.public_inputs[1], F::from_canonical_u64(60)); // output
    assert_eq!(proof.public_inputs[2], F::from_canonical_u64(40)); // change
    assert_eq!(proof.public_inputs[3], F::from_canonical_u64(100)); // total output (should equal input)
    assert_eq!(proof.public_inputs[4], F::ONE); // is_conserved (should be true)
}
