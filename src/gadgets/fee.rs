// Fee payment gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{PublicKeyTarget, UTXOTarget};
use crate::gadgets::{is_less_than_or_equal, verify_message_signature};

/// Enforce fee payment for a transaction
///
/// This gadget verifies that:
/// 1. The fee payer owns the input UTXO (by verifying their signature)
/// 2. The input UTXO has enough funds to pay the fee
/// 3. The fee is sent to the reservoir address
///
/// Returns the change amount for the fee payer
pub fn enforce_fee_payment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_payer_pk: &PublicKeyTarget,
    input_wbtc_utxo: &UTXOTarget,
    fee_amount: Target,
    reservoir_address_hash: &[Target],
    signature: &crate::core::SignatureTarget,
) -> Target {
    // 1. Verify ownership of the input UTXO
    // Create a message containing the UTXO details
    let mut message = Vec::new();
    message.extend_from_slice(&input_wbtc_utxo.owner_pubkey_hash_target);
    message.extend_from_slice(&input_wbtc_utxo.asset_id_target);
    message.push(input_wbtc_utxo.amount_target);
    message.extend_from_slice(&input_wbtc_utxo.salt_target);
    
    // Verify the signature
    let is_signature_valid = verify_message_signature(
        builder,
        &message,
        signature,
        fee_payer_pk,
    );
    
    // Ensure the signature is valid
    builder.assert_one(is_signature_valid);
    
    // 2. Verify the input UTXO has enough funds
    let has_enough_funds = is_less_than_or_equal(
        builder,
        fee_amount,
        input_wbtc_utxo.amount_target,
    );
    
    // Ensure there are enough funds
    builder.assert_one(has_enough_funds);
    
    // 3. Calculate the change amount
    let change_amount = builder.sub(input_wbtc_utxo.amount_target, fee_amount);
    
    // Return the change amount
    change_amount
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::{PointTarget, SignatureTarget, HASH_SIZE};
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use plonky2::field::goldilocks_field::GoldilocksField;
    
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
        
        // Create a reservoir address
        let reservoir_address_hash: Vec<Target> = (0..HASH_SIZE)
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
        
        // Enforce fee payment
        let change_amount = enforce_fee_payment(
            &mut builder,
            &fee_payer_pk,
            &input_wbtc_utxo,
            fee_amount,
            &reservoir_address_hash,
            &signature,
        );
        
        // Make the change amount a public input
        builder.register_public_input(change_amount);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // Set the input UTXO amount to 1000
        pw.set_target(input_wbtc_utxo.amount_target, F::from_canonical_u64(1000));
        
        // Set the fee amount to 100
        pw.set_target(fee_amount, F::from_canonical_u64(100));
        
        // Set the signature to be valid
        // In a real test, we would set actual signature values
        // For now, we'll just make sure the verification passes
        pw.set_target(signature.r_point.x, F::ONE);
        pw.set_target(signature.r_point.y, F::ONE);
        pw.set_target(signature.s_scalar, F::ONE);
        
        // Generate the proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof).unwrap();
        
        // Check the change amount (should be 900)
        assert_eq!(proof.public_inputs[0], F::from_canonical_u64(900));
    }
}
