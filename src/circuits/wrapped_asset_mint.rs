// Wrapped Asset Mint Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, WBTC_ASSET_ID};
use crate::gadgets::verify_message_signature;

/// Represents a signed attestation from a custodian
#[derive(Debug, Clone)]
pub struct SignedAttestationTarget {
    /// The recipient's public key hash
    pub recipient_pk_hash: Vec<Target>,
    
    /// The amount to mint
    pub amount: Target,
    
    /// The deposit nonce to prevent replay attacks
    pub deposit_nonce: Target,
    
    /// The custodian's signature
    pub signature: SignatureTarget,
}

/// Circuit for minting wrapped Bitcoin (wBTC)
///
/// This circuit verifies a custodian's attestation that BTC has been deposited
/// and mints the corresponding amount of wBTC to the recipient.
pub struct WrappedAssetMintCircuit {
    /// The custodian's public key
    pub custodian_pk: PublicKeyTarget,
    
    /// The signed attestation from the custodian
    pub attestation: SignedAttestationTarget,
}

impl WrappedAssetMintCircuit {
    /// Build the wrapped asset mint circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> UTXOTarget {
        // Verify the custodian's signature on the attestation
        let mut message = Vec::new();
        message.extend_from_slice(&self.attestation.recipient_pk_hash);
        message.push(self.attestation.amount);
        message.push(self.attestation.deposit_nonce);
        
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.attestation.signature,
            &self.custodian_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Register the deposit nonce as a public input to prevent replay attacks
        builder.register_public_input(self.attestation.deposit_nonce);
        
        // Create the output UTXO for the recipient
        let output_utxo = UTXOTarget::add_virtual(builder, WBTC_ASSET_ID.len());
        
        // Connect the output UTXO fields to the attestation data
        for (a, b) in output_utxo.owner_pubkey_hash_target.iter().zip(self.attestation.recipient_pk_hash.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID to wBTC (all zeros)
        for target in &output_utxo.asset_id_target {
            builder.connect(*target, builder.zero());
        }
        
        // Set the amount
        builder.connect(output_utxo.amount_target, self.attestation.amount);
        
        // The salt is a random value, so we don't need to connect it
        
        // Return the output UTXO
        output_utxo
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let custodian_pk = PublicKeyTarget::add_virtual(&mut builder);
        
        let recipient_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let amount = builder.add_virtual_target();
        let deposit_nonce = builder.add_virtual_target();
        
        let signature = SignatureTarget::add_virtual(&mut builder);
        
        let attestation = SignedAttestationTarget {
            recipient_pk_hash,
            amount,
            deposit_nonce,
            signature,
        };
        
        let circuit = WrappedAssetMintCircuit {
            custodian_pk,
            attestation,
        };
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);
        
        builder.build::<PoseidonGoldilocksConfig>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::PointTarget;
    use plonky2::iop::witness::PartialWitness;
    
    #[test]
    fn test_wrapped_asset_mint() {
        // Create the circuit
        let circuit_data = WrappedAssetMintCircuit::create_circuit();
        
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
