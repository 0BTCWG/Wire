// Fee enforcement gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{PublicKeyTarget, UTXOTarget};
use crate::gadgets::comparison::is_less_than_or_equal;
use crate::gadgets::hash_for_signature;
use crate::gadgets::hash_utxo_target;

/// Enforce fee payment for a transaction
///
/// This gadget verifies that:
/// 1. The fee payer owns the input UTXO (by verifying their signature)
/// 2. The input UTXO has enough funds to pay the fee
/// 3. The input UTXO is of the correct asset type (wBTC)
/// 4. The fee is sent to the reservoir address
///
/// Returns the change amount for the fee payer and the fee UTXO
pub fn enforce_fee_payment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_payer_pk: &PublicKeyTarget,
    input_wbtc_utxo: &UTXOTarget,
    fee_amount: Target,
    reservoir_address_hash: &[Target],
    signature: &crate::core::SignatureTarget,
    expected_asset_id: &[Target],
) -> (Target, UTXOTarget) {
    // 1. Verify the input UTXO is of the correct asset type (wBTC)
    for (i, (actual, expected)) in input_wbtc_utxo.asset_id_target.iter().zip(expected_asset_id.iter()).enumerate() {
        builder.assert_equal(*actual, *expected);
    }
    
    // 2. Verify ownership of the input UTXO
    // Create a message containing the UTXO details and fee information
    let mut message = Vec::new();
    message.extend_from_slice(&input_wbtc_utxo.owner_pubkey_hash_target);
    message.extend_from_slice(&input_wbtc_utxo.asset_id_target);
    message.push(input_wbtc_utxo.amount_target);
    message.extend_from_slice(&input_wbtc_utxo.salt_target);
    message.push(fee_amount); // Include fee amount in the signed message
    message.extend_from_slice(reservoir_address_hash); // Include fee recipient in the signed message
    
    // Verify the signature using domain-separated hash
    let message_hash = hash_for_signature(builder, &message);
    
    // Create a message for signature verification
    let mut sig_message = Vec::new();
    sig_message.push(message_hash);
    
    // Verify the signature
    let is_signature_valid = crate::gadgets::verify_message_signature(
        builder,
        &sig_message,
        signature,
        fee_payer_pk,
    );
    
    // Ensure the signature is valid
    builder.assert_one(is_signature_valid);
    
    // 3. Verify the input UTXO has enough funds
    let has_enough_funds = is_less_than_or_equal(
        builder,
        fee_amount,
        input_wbtc_utxo.amount_target,
    );
    
    // Ensure there are enough funds
    builder.assert_one(has_enough_funds);
    
    // 4. Calculate the change amount
    let change_amount = builder.sub(input_wbtc_utxo.amount_target, fee_amount);
    
    // 5. Create the fee UTXO that sends the fee to the reservoir address
    let fee_utxo = UTXOTarget {
        owner_pubkey_hash_target: reservoir_address_hash.to_vec(),
        asset_id_target: input_wbtc_utxo.asset_id_target.clone(),
        amount_target: fee_amount,
        salt_target: input_wbtc_utxo.salt_target.clone(), // Reuse the salt for simplicity
    };
    
    // 6. Calculate and register the fee UTXO hash
    let fee_utxo_hash = hash_utxo_target(builder, &fee_utxo);
    builder.register_public_input(fee_utxo_hash);
    
    // Return the change amount and fee UTXO
    (change_amount, fee_utxo)
}

/// Enforce fee payment with a change UTXO
///
/// This gadget verifies fee payment and creates a change UTXO for the fee payer
/// Returns the change UTXO
pub fn enforce_fee_payment_with_change<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_payer_pk: &PublicKeyTarget,
    input_wbtc_utxo: &UTXOTarget,
    fee_amount: Target,
    reservoir_address_hash: &[Target],
    signature: &crate::core::SignatureTarget,
    expected_asset_id: &[Target],
    change_salt: &[Target],
) -> UTXOTarget {
    // Enforce fee payment
    let (change_amount, fee_utxo) = enforce_fee_payment(
        builder,
        fee_payer_pk,
        input_wbtc_utxo,
        fee_amount,
        reservoir_address_hash,
        signature,
        expected_asset_id,
    );
    
    // Create the change UTXO
    let change_utxo = UTXOTarget {
        owner_pubkey_hash_target: input_wbtc_utxo.owner_pubkey_hash_target.clone(),
        asset_id_target: input_wbtc_utxo.asset_id_target.clone(),
        amount_target: change_amount,
        salt_target: change_salt.to_vec(),
    };
    
    // Calculate and register the change UTXO hash
    let change_utxo_hash = hash_utxo_target(builder, &change_utxo);
    builder.register_public_input(change_utxo_hash);
    
    // Return the change UTXO
    change_utxo
}

/// Validate a fee amount
///
/// This gadget validates that a fee amount is within acceptable bounds
pub fn validate_fee_amount<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_amount: Target,
    min_fee: Target,
    max_fee: Target,
) -> Target {
    // Check if the fee is at least the minimum fee
    let is_above_min = is_less_than_or_equal(
        builder,
        min_fee,
        fee_amount,
    );
    
    // Check if the fee is at most the maximum fee
    let is_below_max = is_less_than_or_equal(
        builder,
        fee_amount,
        max_fee,
    );
    
    // Both conditions must be true
    let is_valid_fee = builder.and(is_above_min, is_below_max);
    
    // Ensure the fee is valid
    builder.assert_one(is_valid_fee);
    
    // Return the validated fee amount
    fee_amount
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PointTarget, SignatureTarget, HASH_SIZE};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;
    
    #[test]
    fn test_fee_payment() {
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
        
        // Create an input UTXO
        let input_wbtc_utxo = UTXOTarget {
            owner_pubkey_hash_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Create a fee amount
        let fee_amount = builder.add_virtual_target();
        
        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a signature
        let signature = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create an expected asset ID
        let expected_asset_id: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Enforce fee payment
        let (change_amount, fee_utxo) = enforce_fee_payment(
            &mut builder,
            &fee_payer_pk,
            &input_wbtc_utxo,
            fee_amount,
            &fee_reservoir_address_hash,
            &signature,
            &expected_asset_id,
        );
        
        // Register the change amount as a public input
        builder.register_public_input(change_amount);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set values for the fee payer public key
        pw.set_target(fee_payer_pk.point.x, F::from_canonical_u64(1));
        pw.set_target(fee_payer_pk.point.y, F::from_canonical_u64(2));
        
        // Set values for the input UTXO
        for (i, target) in input_wbtc_utxo.owner_pubkey_hash_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        for (i, target) in input_wbtc_utxo.asset_id_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        pw.set_target(input_wbtc_utxo.amount_target, F::from_canonical_u64(100));
        
        for (i, target) in input_wbtc_utxo.salt_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the fee amount
        pw.set_target(fee_amount, F::from_canonical_u64(10));
        
        // Set values for the fee reservoir address
        for (i, target) in fee_reservoir_address_hash.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the expected asset ID
        for (i, target) in expected_asset_id.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the signature
        pw.set_target(signature.r_point.x, F::from_canonical_u64(3));
        pw.set_target(signature.r_point.y, F::from_canonical_u64(4));
        pw.set_target(signature.s_scalar, F::from_canonical_u64(5));
        
        // Generate a proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the change amount is correct
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(90));
    }
    
    #[test]
    fn test_fee_payment_with_change() {
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
        
        // Create an input UTXO
        let input_wbtc_utxo = UTXOTarget {
            owner_pubkey_hash_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Create a fee amount
        let fee_amount = builder.add_virtual_target();
        
        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a signature
        let signature = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create an expected asset ID
        let expected_asset_id: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a change salt
        let change_salt: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Enforce fee payment with change
        let change_utxo = enforce_fee_payment_with_change(
            &mut builder,
            &fee_payer_pk,
            &input_wbtc_utxo,
            fee_amount,
            &fee_reservoir_address_hash,
            &signature,
            &expected_asset_id,
            &change_salt,
        );
        
        // Register the change amount as a public input
        builder.register_public_input(change_utxo.amount_target);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set values for the fee payer public key
        pw.set_target(fee_payer_pk.point.x, F::from_canonical_u64(1));
        pw.set_target(fee_payer_pk.point.y, F::from_canonical_u64(2));
        
        // Set values for the input UTXO
        for (i, target) in input_wbtc_utxo.owner_pubkey_hash_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        for (i, target) in input_wbtc_utxo.asset_id_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        pw.set_target(input_wbtc_utxo.amount_target, F::from_canonical_u64(100));
        
        for (i, target) in input_wbtc_utxo.salt_target.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the fee amount
        pw.set_target(fee_amount, F::from_canonical_u64(10));
        
        // Set values for the fee reservoir address
        for (i, target) in fee_reservoir_address_hash.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the expected asset ID
        for (i, target) in expected_asset_id.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(i as u64));
        }
        
        // Set values for the change salt
        for (i, target) in change_salt.iter().enumerate() {
            pw.set_target(*target, F::from_canonical_u64(100 + i as u64));
        }
        
        // Set values for the signature
        pw.set_target(signature.r_point.x, F::from_canonical_u64(3));
        pw.set_target(signature.r_point.y, F::from_canonical_u64(4));
        pw.set_target(signature.s_scalar, F::from_canonical_u64(5));
        
        // Generate a proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the change amount is correct
        assert_eq!(proof.public_inputs[2], F::from_canonical_u64(90));
    }
    
    #[test]
    fn test_validate_fee_amount() {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create fee amounts
        let fee_amount = builder.add_virtual_target();
        let min_fee = builder.add_virtual_target();
        let max_fee = builder.add_virtual_target();
        
        // Validate the fee amount
        let validated_fee = validate_fee_amount(
            &mut builder,
            fee_amount,
            min_fee,
            max_fee,
        );
        
        // Register the validated fee as a public input
        builder.register_public_input(validated_fee);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set values for the fee amounts
        pw.set_target(fee_amount, F::from_canonical_u64(50));
        pw.set_target(min_fee, F::from_canonical_u64(10));
        pw.set_target(max_fee, F::from_canonical_u64(100));
        
        // Generate a proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof.clone()).unwrap();
        
        // Check that the validated fee is correct
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(50));
    }
}
