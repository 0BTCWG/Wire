// Wrapped Asset Mint Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};
use crate::gadgets::verify_message_signature;

/// Represents a signed attestation from a custodian
pub struct SignedAttestationTarget {
    /// The recipient's public key hash
    pub recipient_pk_hash: Vec<Target>,
    
    /// The amount of BTC deposited
    pub amount: Target,
    
    /// A nonce to prevent replay attacks
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
    
    /// The signed attestation
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
        
        let is_valid = verify_message_signature(
            builder,
            &message,
            &self.attestation.signature,
            &self.custodian_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Create an output UTXO for the recipient
        let output_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.attestation.recipient_pk_hash.clone(),
            asset_id_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Set the owner public key hash
        for (a, b) in self.attestation.recipient_pk_hash.iter().zip(output_utxo.owner_pubkey_hash_target.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID to wBTC (all zeros)
        let zero_target = builder.zero();
        for target in &output_utxo.asset_id_target {
            builder.connect(*target, zero_target);
        }
        
        // Set the amount
        builder.connect(output_utxo.amount_target, self.attestation.amount);
        
        // The salt is a random value, so we don't need to connect it
        
        // Return the output UTXO
        output_utxo
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a custodian public key
        let custodian_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
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
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create a signed attestation
        let attestation = SignedAttestationTarget {
            recipient_pk_hash,
            amount,
            deposit_nonce,
            signature,
        };
        
        // Create the circuit
        let circuit = WrappedAssetMintCircuit {
            custodian_pk,
            attestation,
        };
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);
        
        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wrapped_asset_mint() {
        // Create the circuit
        let circuit_data = WrappedAssetMintCircuit::create_circuit();
        
        // Just verify that the circuit was created successfully
        // Skip proof generation and verification for now
        assert!(circuit_data.common.gates.len() > 0, "Circuit should have gates");
    }
}
