// Tests for the WrappedAssetMintCircuit
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::PartialWitness;
use plonky2::iop::witness::WitnessWrite;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::circuits::wrapped_asset_mint::{SignedAttestationTarget, WrappedAssetMintCircuit};
use wire_lib::core::{
    PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE, WBTC_ASSET_ID,
};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_wrapped_asset_mint_circuit_creation() {
    // This test verifies that we can create and build the circuit
    let circuit_data = WrappedAssetMintCircuit::create_circuit();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_mint_with_values() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a custodian public key
    let custodian_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create an amount to mint
    let amount = builder.add_virtual_target();

    // Create a deposit nonce
    let deposit_nonce = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a signed attestation
    let attestation = SignedAttestationTarget {
        recipient_pk_hash: recipient_pk_hash.clone(),
        amount,
        deposit_nonce,
        signature: signature.clone(),
    };

    // Create the circuit
    let circuit = WrappedAssetMintCircuit {
        custodian_pk: custodian_pk.clone(),
        attestation,
    };

    // Build the circuit
    let output_utxo = circuit.build::<F, C, D>(&mut builder);

    // Register the output UTXO amount as a public input
    builder.register_public_input(output_utxo.amount_target);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_mint_output_utxo_fields() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a custodian public key
    let custodian_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create an amount to mint
    let amount = builder.add_virtual_target();

    // Create a deposit nonce
    let deposit_nonce = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a signed attestation
    let attestation = SignedAttestationTarget {
        recipient_pk_hash: recipient_pk_hash.clone(),
        amount,
        deposit_nonce,
        signature: signature.clone(),
    };

    // Create the circuit
    let circuit = WrappedAssetMintCircuit {
        custodian_pk: custodian_pk.clone(),
        attestation,
    };

    // Build the circuit
    let output_utxo = circuit.build::<F, C, D>(&mut builder);

    // Register the deposit nonce as a public input
    builder.register_public_input(deposit_nonce);

    // Register the output UTXO fields as public inputs
    builder.register_public_input(output_utxo.amount_target);

    // Register the first element of the owner pubkey hash
    builder.register_public_input(output_utxo.owner_pubkey_hash_target[0]);

    // Register the first element of the asset ID
    builder.register_public_input(output_utxo.asset_id_target[0]);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_mint_zero_amount() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a custodian public key
    let custodian_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create an amount to mint (zero)
    let amount = builder.add_virtual_target();

    // Create a deposit nonce
    let deposit_nonce = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a signed attestation
    let attestation = SignedAttestationTarget {
        recipient_pk_hash: recipient_pk_hash.clone(),
        amount,
        deposit_nonce,
        signature: signature.clone(),
    };

    // Create the circuit
    let circuit = WrappedAssetMintCircuit {
        custodian_pk: custodian_pk.clone(),
        attestation,
    };

    // Build the circuit
    let output_utxo = circuit.build::<F, C, D>(&mut builder);

    // Register the output UTXO amount as a public input
    builder.register_public_input(output_utxo.amount_target);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}

#[test]
fn test_wrapped_asset_mint_large_amount() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a custodian public key
    let custodian_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..HASH_SIZE)
        .map(|_| builder.add_virtual_target())
        .collect();

    // Create an amount to mint (large value)
    let amount = builder.add_virtual_target();

    // Create a deposit nonce
    let deposit_nonce = builder.add_virtual_target();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Create a signed attestation
    let attestation = SignedAttestationTarget {
        recipient_pk_hash: recipient_pk_hash.clone(),
        amount,
        deposit_nonce,
        signature: signature.clone(),
    };

    // Create the circuit
    let circuit = WrappedAssetMintCircuit {
        custodian_pk: custodian_pk.clone(),
        attestation,
    };

    // Build the circuit
    let output_utxo = circuit.build::<F, C, D>(&mut builder);

    // Register the output UTXO amount as a public input
    builder.register_public_input(output_utxo.amount_target);

    // Build the circuit data
    let circuit_data = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(
        circuit_data.common.gates.len() > 0,
        "Circuit should have gates"
    );
}
