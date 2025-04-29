// Basic Hash Example
//
// This example demonstrates how to use the hash gadgets in the 0BTC Wire library.

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire_lib::gadgets::hash::{hash_single, hash_pair, hash_n, hash_utxo_commitment};
use wire_lib::core::UTXOTarget;

fn main() {
    println!("0BTC Wire - Basic Hash Example");
    
    // Initialize the library
    wire_lib::init();
    
    // Define constants
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    // Create a new circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Example 1: Single Hash
    println!("\nExample 1: Single Hash");
    
    // Create an input value
    let input_value = F::from_canonical_u64(42);
    let input_target = builder.add_virtual_target();
    
    // Hash the input
    let hash_result = hash_single(&mut builder, input_target);
    
    // Register the hash result as a public input
    builder.register_public_input(hash_result);
    
    // Example 2: Pair Hash
    println!("\nExample 2: Pair Hash");
    
    // Create two input values
    let input1_target = builder.add_virtual_target();
    let input2_target = builder.add_virtual_target();
    
    // Hash the pair
    let pair_hash_result = hash_pair(&mut builder, input1_target, input2_target);
    
    // Register the hash result as a public input
    builder.register_public_input(pair_hash_result);
    
    // Example 3: Multi-element Hash
    println!("\nExample 3: Multi-element Hash");
    
    // Create multiple input values
    let mut inputs = Vec::new();
    for _ in 0..5 {
        inputs.push(builder.add_virtual_target());
    }
    
    // Hash the inputs
    let multi_hash_result = hash_n(&mut builder, &inputs);
    
    // Register the hash result as a public input
    builder.register_public_input(multi_hash_result);
    
    // Example 4: UTXO Commitment Hash
    println!("\nExample 4: UTXO Commitment Hash");
    
    // Create a UTXO
    let utxo = UTXOTarget::add_virtual(&mut builder, 32);
    
    // Hash the UTXO
    let utxo_hash_result = hash_utxo_commitment(&mut builder, &utxo);
    
    // Register the hash result as a public input
    builder.register_public_input(utxo_hash_result);
    
    // Build the circuit
    println!("\nBuilding circuit...");
    let circuit = builder.build::<C>();
    
    // Create a witness
    let mut pw = PartialWitness::new();
    
    // Set values for Example 1
    pw.set_target(input_target, input_value);
    
    // Set values for Example 2
    pw.set_target(input1_target, F::from_canonical_u64(123));
    pw.set_target(input2_target, F::from_canonical_u64(456));
    
    // Set values for Example 3
    for (i, input) in inputs.iter().enumerate() {
        pw.set_target(*input, F::from_canonical_u64(i as u64 + 1));
    }
    
    // Set values for Example 4
    for i in 0..32 {
        pw.set_target(utxo.owner_pubkey_hash_target[i], F::from_canonical_u64(i as u64));
    }
    for i in 0..32 {
        pw.set_target(utxo.asset_id_target[i], F::from_canonical_u64((i + 32) as u64));
    }
    pw.set_target(utxo.amount_target, F::from_canonical_u64(1000));
    pw.set_target(utxo.salt_target, F::from_canonical_u64(12345));
    
    // Generate a proof
    println!("Generating proof...");
    let proof = circuit.prove(pw).unwrap();
    
    // Verify the proof
    println!("Verifying proof...");
    circuit.verify(&proof).unwrap();
    
    println!("Proof verified successfully!");
    
    // Print the public inputs (hash results)
    println!("\nHash Results:");
    println!("Single Hash: {:?}", proof.public_inputs[0]);
    println!("Pair Hash: {:?}", proof.public_inputs[1]);
    println!("Multi-element Hash: {:?}", proof.public_inputs[2]);
    println!("UTXO Commitment Hash: {:?}", proof.public_inputs[3]);
}
