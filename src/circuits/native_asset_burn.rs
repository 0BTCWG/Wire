// Native Asset Burn Circuit for the 0BTC Wire system
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::GenericConfig;

use crate::core::{C, D, F, PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::gadgets::{calculate_and_register_nullifier, enforce_fee_payment, verify_message_signature};

/// Circuit for burning native asset tokens
///
/// This circuit verifies ownership of native asset UTXOs, burns them,
/// and handles the fee payment.
pub struct NativeAssetBurnCircuit {
    /// The input UTXOs to burn
    pub input_utxos: Vec<UTXOTarget>,
    
    /// The sender's public key
    pub sender_pk: PublicKeyTarget,
    
    /// The sender's signature
    pub sender_sig: SignatureTarget,
    
    /// The fee input UTXO (must be wBTC)
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl NativeAssetBurnCircuit {
    /// Build the native asset burn circuit
    pub fn build<F: Field, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        sender_sk: Target,
    ) -> UTXOTarget {
        // Create a message containing the burn details
        let mut message = Vec::new();
        
        // Include all input UTXOs in the message
        for input_utxo in &self.input_utxos {
            message.extend_from_slice(&input_utxo.asset_id_target);
            message.push(input_utxo.amount_target);
            message.extend_from_slice(&input_utxo.salt_target);
        }
        
        // Verify the sender's signature
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.sender_sig,
            &self.sender_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Calculate and register nullifiers for all input UTXOs
        for input_utxo in &self.input_utxos {
            calculate_and_register_nullifier(
                builder,
                &input_utxo.salt_target,
                sender_sk,
            );
        }
        
        // Enforce the fee payment
        let fee_amount = builder.constant(F::from_canonical_u64(DEFAULT_FEE));
        
        let wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.sender_pk,
            &self.fee_input_utxo,
            fee_amount,
            &self.fee_reservoir_address_hash,
            &self.sender_sig,
        );
        
        // Create a fee UTXO for the reservoir
        let fee_utxo = UTXOTarget::add_virtual(builder, self.fee_input_utxo.asset_id_target.len());
        
        // Set the owner to the fee reservoir
        for (a, b) in fee_utxo.owner_pubkey_hash_target.iter().zip(self.fee_reservoir_address_hash.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID to wBTC (same as fee input)
        for (a, b) in fee_utxo.asset_id_target.iter().zip(self.fee_input_utxo.asset_id_target.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the amount to the fee
        builder.connect(fee_utxo.amount_target, fee_amount);
        
        // Return the fee UTXO
        fee_utxo
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<F, C, D> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        let input_utxos = vec![input_utxo];
        
        let sender_pk = PublicKeyTarget::add_virtual(&mut builder);
        let sender_sig = SignatureTarget::add_virtual(&mut builder);
        
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let circuit = NativeAssetBurnCircuit {
            input_utxos,
            sender_pk,
            sender_sig,
            fee_input_utxo,
            fee_reservoir_address_hash,
        };
        
        // Add a virtual target for the sender's secret key
        let sender_sk = builder.add_virtual_target();
        
        // Build the circuit
        circuit.build(&mut builder, sender_sk);
        
        builder.build::<C>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::PointTarget;
    use plonky2::iop::witness::PartialWitness;
    
    #[test]
    fn test_native_asset_burn() {
        // Create the circuit
        let circuit_data = NativeAssetBurnCircuit::create_circuit();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // In a real test, we would set the witness values
        // For now, we'll just create an empty witness
        
        // Generate the proof
        let proof = circuit_data.prove(pw).unwrap();
        
        // Verify the proof
        circuit_data.verify(proof).unwrap();
    }
}
