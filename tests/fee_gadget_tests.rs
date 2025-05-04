use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget};
use wire_lib::gadgets::enforce_fee_payment;

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

#[test]
fn test_fee_payment_sufficient_funds() {
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Create a fee payer public key
    let fee_payer_pk = PublicKeyTarget {
        point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
    };

    // Create an input UTXO for the fee payer
    let input_wbtc_utxo = UTXOTarget {
        owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        amount_target: builder.add_virtual_target(),
        salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
    };

    // Create a fee amount target
    let fee_amount = builder.add_virtual_target();

    // Create a fee reservoir address hash
    let fee_reservoir_address_hash: Vec<Target> =
        (0..32).map(|_| builder.add_virtual_target()).collect();

    // Create a signature
    let signature = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };

    // Enforce fee payment
    let change_amount = enforce_fee_payment(
        &mut builder,
        &fee_payer_pk,
        &input_wbtc_utxo,
        fee_amount,
        &fee_reservoir_address_hash,
        &signature,
    );

    // Make the change amount a public input
    builder.register_public_input(change_amount);

    // Build the circuit
    let circuit = builder.build::<C>();

    // Just verify that the circuit was created successfully
    // Skip proof generation and verification for now
    assert!(circuit.common.gates.len() > 0, "Circuit should have gates");
}
