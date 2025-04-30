// Wrapped Asset Mint Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData, VerifierOnlyCircuitData, CommonCircuitData};
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::iop::generator::{SimpleGenerator, WitnessGenerator, WitnessGeneratorRef};

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE, WBTC_ASSET_ID};
use crate::core::proof::{generate_proof, verify_proof, serialize_proof, SerializableProof, ProofError};
use crate::gadgets::verify_message_signature;
use crate::errors::{WireError, WireResult};

/// Represents a signed attestation from a custodian
#[derive(Clone)]
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
#[derive(Clone)]
pub struct WrappedAssetMintCircuit {
    /// The custodian's public key
    pub custodian_pk: PublicKeyTarget,
    
    /// The signed attestation
    pub attestation: SignedAttestationTarget,
}

impl WrappedAssetMintCircuit {
    /// Build the wrapped asset mint circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
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
        
        // Ensure the signature is valid
        builder.assert_one(is_valid);
        
        // Create the output UTXO
        let salt = builder.add_virtual_target();
        
        // Register the amount as a public input
        builder.register_public_input(self.attestation.amount);
        
        // Create the output UTXO
        let output_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.attestation.recipient_pk_hash.clone(),
            asset_id_target: (0..HASH_SIZE)
                .map(|i| {
                    if i < WBTC_ASSET_ID.len() {
                        builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64))
                    } else {
                        builder.zero()
                    }
                })
                .collect(),
            amount_target: self.attestation.amount,
            salt_target: vec![salt],
        };
        
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
        circuit.build(&mut builder);
        
        // Build the circuit data
        builder.build()
    }
    
    /// Generate a proof for the circuit with the given inputs
    pub fn generate_proof(
        recipient_pk_hash: &[u8],
        amount: u64,
        deposit_nonce: u64,
        custodian_pk_x: u64,
        custodian_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
    ) -> WireResult<SerializableProof> {
        // Create the circuit
        let circuit_data = Self::create_circuit();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
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
        let recipient_pk_hash_targets: Vec<_> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create an amount to mint
        let amount_target = builder.add_virtual_target();
        
        // Create a deposit nonce
        let deposit_nonce_target = builder.add_virtual_target();
        
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
            recipient_pk_hash: recipient_pk_hash_targets.clone(),
            amount: amount_target,
            deposit_nonce: deposit_nonce_target,
            signature: signature.clone(),
        };
        
        // Create the circuit
        let circuit = WrappedAssetMintCircuit {
            custodian_pk: custodian_pk.clone(),
            attestation: attestation.clone(),
        };
        
        // Set the witness values
        pw.set_target(custodian_pk.point.x, GoldilocksField::from_canonical_u64(custodian_pk_x));
        pw.set_target(custodian_pk.point.y, GoldilocksField::from_canonical_u64(custodian_pk_y));
        
        for i in 0..recipient_pk_hash.len().min(HASH_SIZE) {
            pw.set_target(
                attestation.recipient_pk_hash[i],
                GoldilocksField::from_canonical_u64(recipient_pk_hash[i] as u64),
            );
        }
        
        pw.set_target(attestation.amount, GoldilocksField::from_canonical_u64(amount));
        pw.set_target(attestation.deposit_nonce, GoldilocksField::from_canonical_u64(deposit_nonce));
        
        pw.set_target(signature.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x));
        pw.set_target(signature.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y));
        pw.set_target(signature.s_scalar, GoldilocksField::from_canonical_u64(signature_s));
        
        // Generate the proof
        let proof = circuit_data.prove(pw)
            .map_err(|e| WireError::ProofError(ProofError::ProofGenerationError(format!("Failed to generate proof: {}", e))))?;
        
        // Serialize the proof
        serialize_proof(&proof)
            .map_err(|e| WireError::ProofError(e))
    }
    
    /// Verify a proof for the circuit
    pub fn verify_proof(serializable_proof: &SerializableProof) -> WireResult<()> {
        let circuit_data = Self::create_circuit();
        let proof = serializable_proof.to_proof::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&circuit_data.common)
            .map_err(|e| WireError::ProofError(ProofError::VerificationError(format!("Failed to deserialize proof: {}", e))))?;
        
        circuit_data.verify(proof)
            .map_err(|e| WireError::ProofError(ProofError::VerificationError(format!("Failed to verify proof: {}", e))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_wrapped_asset_mint() {
        // This is a placeholder test
        // In a real implementation, this would test the circuit with actual inputs
        let circuit_data = WrappedAssetMintCircuit::create_circuit();
        assert!(circuit_data.common.num_public_inputs > 0);
    }
}
