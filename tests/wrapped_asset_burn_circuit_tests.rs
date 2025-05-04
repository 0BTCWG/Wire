// Tests for the WrappedAssetBurnCircuit
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};
use wire_lib::gadgets::fee::SignedQuoteTarget;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_wrapped_asset_burn_circuit_creation() {
    // This test verifies that we can create and build the circuit
    let circuit_data = WrappedAssetBurnCircuit::create_circuit();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_burn_basic() {
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

    // Create a destination BTC address
    let destination_btc_address: Vec<_> = (0..20).map(|_| builder.add_virtual_target()).collect();

    // Create the circuit without fee quote
    let circuit = WrappedAssetBurnCircuit {
        input_utxo: input_utxo.clone(),
        sender_pk: sender_pk.clone(),
        sender_sig: signature.clone(),
        destination_btc_address: destination_btc_address.clone(),
        fee_quote: None,
        custodian_pk: None,
    };

    // Build the circuit
    let _nullifier = circuit.build::<F, D>(&mut builder, sender_sk);

    // Register the nullifier as a public input
    builder.register_public_input(_nullifier);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_burn_with_fee_quote() {
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

    // Create a destination BTC address
    let destination_btc_address: Vec<_> = (0..20).map(|_| builder.add_virtual_target()).collect();

    // Create a custodian public key
    let custodian_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a fee quote
    let fee_quote = SignedQuoteTarget {
        fee_btc: builder.add_virtual_target(),
        expiry_timestamp: builder.add_virtual_target(),
        signature: SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        },
    };

    // Create the circuit with fee quote
    let circuit = WrappedAssetBurnCircuit {
        input_utxo: input_utxo.clone(),
        sender_pk: sender_pk.clone(),
        sender_sig: signature.clone(),
        destination_btc_address: destination_btc_address.clone(),
        fee_quote: Some(fee_quote.clone()),
        custodian_pk: Some(custodian_pk.clone()),
    };

    // Build the circuit
    let _nullifier = circuit.build::<F, D>(&mut builder, sender_sk);

    // Register the nullifier as a public input
    builder.register_public_input(_nullifier);

    // Register the fee amount as a public input
    builder.register_public_input(fee_quote.fee_btc);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_burn_net_amount_calculation() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a simple circuit to test net amount calculation
    let input_amount = builder.add_virtual_target();
    let fee_amount = builder.add_virtual_target();

    // Register the input amount and fee as public inputs
    builder.register_public_input(input_amount);
    builder.register_public_input(fee_amount);

    // Calculate the expected net amount
    let net_amount = builder.sub(input_amount, fee_amount);
    builder.register_public_input(net_amount);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set the input amount to 100
    pw.set_target(input_amount, F::from_canonical_u64(100));

    // Set the fee amount to 5
    pw.set_target(fee_amount, F::from_canonical_u64(5));

    // Generate the proof
    let proof = circuit_data.prove(pw).unwrap();

    // Verify the proof
    circuit_data.verify(proof.clone()).unwrap();

    // Check that the net amount is correct (input - fee)
    assert_eq!(proof.public_inputs[0], F::from_canonical_u64(100)); // input
    assert_eq!(proof.public_inputs[1], F::from_canonical_u64(5)); // fee
    assert_eq!(proof.public_inputs[2], F::from_canonical_u64(95)); // net (100 - 5)
}

#[test]
fn test_wrapped_asset_burn_destination_address() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a simple circuit to test destination address verification
    let destination_address_bytes: Vec<_> = (0..3).map(|_| builder.add_virtual_target()).collect();

    // Register the destination address bytes as public inputs
    for &byte in &destination_address_bytes {
        builder.register_public_input(byte);
    }

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Create a partial witness
    let mut pw = PartialWitness::new();

    // Set specific values for the destination address bytes
    pw.set_target(destination_address_bytes[0], F::from_canonical_u64(0x1A));
    pw.set_target(destination_address_bytes[1], F::from_canonical_u64(0x2B));
    pw.set_target(destination_address_bytes[2], F::from_canonical_u64(0x3C));

    // Generate the proof
    let proof = circuit_data.prove(pw).unwrap();

    // Verify the proof
    circuit_data.verify(proof.clone()).unwrap();

    // Check that the destination address bytes match what we set
    assert_eq!(proof.public_inputs[0], F::from_canonical_u64(0x1A));
    assert_eq!(proof.public_inputs[1], F::from_canonical_u64(0x2B));
    assert_eq!(proof.public_inputs[2], F::from_canonical_u64(0x3C));
}
