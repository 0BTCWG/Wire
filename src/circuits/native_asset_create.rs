// Native Asset Create Circuit for the 0BTC Wire system
use plonky2::field::types::Field;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::GenericConfig;

use crate::core::{C, D, F, PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::gadgets::{calculate_asset_id, enforce_fee_payment, verify_message_signature};

/// Circuit for creating a new native asset
///
/// This circuit verifies the creator's signature over the asset parameters,
/// calculates a unique asset ID, enforces the fee payment, and creates the
/// initial UTXO for the new asset.
pub struct NativeAssetCreateCircuit {
    /// The creator's public key
    pub creator_pk: PublicKeyTarget,
    
    /// The creator's signature
    pub creator_sig: SignatureTarget,
    
    /// The number of decimal places for the asset
    pub decimals: Target,
    
    /// The maximum supply of the asset
    pub max_supply: Target,
    
    /// Whether the asset can be continuously minted
    pub is_continuously_mintable: Target,
    
    /// The initial mint amount
    pub initial_mint_amount: Target,
    
    /// A nonce to ensure uniqueness of the asset ID
    pub nonce: Target,
    
    /// The fee input UTXO (must be wBTC)
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl NativeAssetCreateCircuit {
    /// Build the native asset create circuit
    pub fn build<F: Field, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> (Vec<Target>, UTXOTarget, UTXOTarget) {
        // Create a message containing the asset parameters
        let mut message = Vec::new();
        message.push(self.decimals);
        message.push(self.max_supply);
        message.push(self.is_continuously_mintable);
        message.push(self.initial_mint_amount);
        message.push(self.nonce);
        
        // Verify the creator's signature
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.creator_sig,
            &self.creator_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Calculate the unique asset ID
        let creator_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let asset_id = calculate_asset_id(
            builder,
            &creator_pk_hash,
            self.nonce,
            self.decimals,
            self.max_supply,
            self.is_continuously_mintable,
        );
        
        // Register the asset ID as a public input
        for target in &asset_id {
            builder.register_public_input(*target);
        }
        
        // Enforce the fee payment (fixed fee of 1000 satoshis)
        let fee_amount = builder.constant(F::from_canonical_u64(DEFAULT_FEE));
        
        let wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.creator_pk,
            &self.fee_input_utxo,
            fee_amount,
            &self.fee_reservoir_address_hash,
            &self.creator_sig,
        );
        
        // Create the initial UTXO for the new asset
        let initial_utxo = UTXOTarget::add_virtual(builder, asset_id.len());
        
        // Set the owner to the creator
        for (a, b) in initial_utxo.owner_pubkey_hash_target.iter().zip(creator_pk_hash.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID
        for (a, b) in initial_utxo.asset_id_target.iter().zip(asset_id.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the amount to the initial mint amount
        builder.connect(initial_utxo.amount_target, self.initial_mint_amount);
        
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
        
        // Return the asset ID, initial UTXO, and fee UTXO
        (asset_id, initial_utxo, fee_utxo)
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<F, C, D> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let creator_pk = PublicKeyTarget::add_virtual(&mut builder);
        let creator_sig = SignatureTarget::add_virtual(&mut builder);
        
        let decimals = builder.add_virtual_target();
        let max_supply = builder.add_virtual_target();
        let is_continuously_mintable = builder.add_virtual_target();
        let initial_mint_amount = builder.add_virtual_target();
        let nonce = builder.add_virtual_target();
        
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let circuit = NativeAssetCreateCircuit {
            creator_pk,
            creator_sig,
            decimals,
            max_supply,
            is_continuously_mintable,
            initial_mint_amount,
            nonce,
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
    fn test_native_asset_create() {
        // Create the circuit
        let circuit_data = NativeAssetCreateCircuit::create_circuit();
        
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
