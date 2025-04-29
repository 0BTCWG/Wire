// Simple Transfer Example
//
// This example demonstrates how to create and verify a transfer circuit proof
// using the 0BTC Wire library.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget};
use wire_lib::circuits::TransferCircuit;

fn main() {
    println!("0BTC Wire - Simple Transfer Example");
    
    // Initialize the library
    wire_lib::init();
    
    // Define constants
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
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
    
    // Create a sender signature
    let sender_sig = SignatureTarget {
        r_point: PointTarget {
            x: builder.add_virtual_target(),
            y: builder.add_virtual_target(),
        },
        s_scalar: builder.add_virtual_target(),
    };
    
    // Create an input UTXO
    let input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
    
    // Create a recipient public key hash
    let recipient_pk_hash: Vec<_> = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect();
    
    // Create an output amount
    let output_amount = builder.add_virtual_target();
    
    // Create a fee input UTXO
    let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
    
    // Create a fee amount
    let fee_amount = builder.add_virtual_target();
    
    // Create a fee reservoir address hash
    let fee_reservoir_address_hash: Vec<_> = (0..32)
        .map(|_| builder.add_virtual_target())
        .collect();
    
    // Create a transfer circuit
    let circuit = TransferCircuit {
        input_utxos: vec![input_utxo.clone()],
        recipient_pk_hashes: vec![recipient_pk_hash],
        output_amounts: vec![output_amount],
        sender_pk,
        sender_sig,
        fee_input_utxo: fee_input_utxo.clone(),
        fee_amount,
        fee_reservoir_address_hash,
    };
    
    // Add a virtual target for the sender's secret key
    let sender_sk = builder.add_virtual_target();
    
    // Build the circuit
    let (_output_utxos, _fee_utxo, _change_utxo) = circuit.build::<F, C, D>(&mut builder, sender_sk);
    
    // Build the circuit data
    let circuit_data = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    
    // Set the input UTXO amount to 1000
    pw.set_target(input_utxo.amount_target, F::from_canonical_u64(1000));
    
    // Set the output amount to 500
    pw.set_target(output_amount, F::from_canonical_u64(500));
    
    // Set the fee amount to 100
    pw.set_target(fee_amount, F::from_canonical_u64(100));
    
    // Set the fee input UTXO amount to 1000
    pw.set_target(fee_input_utxo.amount_target, F::from_canonical_u64(1000));
    
    // Set the sender's secret key
    pw.set_target(sender_sk, F::from_canonical_u64(123456));
    
    // In a real example, we would set all the other witness values
    
    println!("Generating proof...");
    
    // Generate the proof
    let proof = circuit_data.prove(pw).unwrap();
    
    println!("Verifying proof...");
    
    // Verify the proof
    circuit_data.verify(proof).unwrap();
    
    println!("Proof verified successfully!");
}
