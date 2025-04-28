// Native Asset Mint Circuit for the 0BTC Wire system
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::GenericConfig;

use crate::core::{C, D, F, PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::gadgets::{enforce_fee_payment, verify_message_signature};

/// Circuit for minting additional tokens of an existing native asset
///
/// This circuit verifies authorization to mint more tokens of an asset,
/// enforces the fee payment, and creates new UTXOs for the minted tokens.
pub struct NativeAssetMintCircuit {
    /// The asset ID to mint
    pub asset_id: Vec<Target>,
    
    /// The creator's public key (for authorization)
    pub creator_pk: PublicKeyTarget,
    
    /// The creator's signature
    pub creator_sig: SignatureTarget,
    
    /// The amount to mint
    pub mint_amount: Target,
    
    /// The recipient's public key hash
    pub recipient_pk_hash: Vec<Target>,
    
    /// The fee input UTXO (must be wBTC)
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl NativeAssetMintCircuit {
    /// Build the native asset mint circuit
    pub fn build<F: Field, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> (UTXOTarget, UTXOTarget) {
        // Create a message containing the mint details
        let mut message = Vec::new();
        message.extend_from_slice(&self.asset_id);
        message.push(self.mint_amount);
        message.extend_from_slice(&self.recipient_pk_hash);
        
        // Verify the creator's signature
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.creator_sig,
            &self.creator_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Enforce the fee payment
        let fee_amount = builder.constant(F::from_canonical_u64(DEFAULT_FEE));
        
        let wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.creator_pk,
            &self.fee_input_utxo,
            fee_amount,
            &self.fee_reservoir_address_hash,
            &self.creator_sig,
        );
        
        // Create the output UTXO for the minted tokens
        let output_utxo = UTXOTarget::add_virtual(builder, self.asset_id.len());
        
        // Set the owner to the recipient
        for (a, b) in output_utxo.owner_pubkey_hash_target.iter().zip(self.recipient_pk_hash.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID
        for (a, b) in output_utxo.asset_id_target.iter().zip(self.asset_id.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the amount to the mint amount
        builder.connect(output_utxo.amount_target, self.mint_amount);
        
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
        
        // Return the output UTXO and fee UTXO
        (output_utxo, fee_utxo)
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<F, C, D> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let asset_id: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let creator_pk = PublicKeyTarget::add_virtual(&mut builder);
        let creator_sig = SignatureTarget::add_virtual(&mut builder);
        
        let mint_amount = builder.add_virtual_target();
        
        let recipient_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let circuit = NativeAssetMintCircuit {
            asset_id,
            creator_pk,
            creator_sig,
            mint_amount,
            recipient_pk_hash,
            fee_input_utxo,
            fee_reservoir_address_hash,
        };
        
        // Build the circuit
        circuit.build(&mut builder);
        
        builder.build::<C>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::PointTarget;
    use plonky2::iop::witness::PartialWitness;
    
    #[test]
    fn test_native_asset_mint() {
        // Create the circuit
        let circuit_data = NativeAssetMintCircuit::create_circuit();
        
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
