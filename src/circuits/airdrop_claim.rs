// Airdrop Claim Circuit for the 0BTC Wire system
// This circuit allows users to claim their airdropped tokens

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::airdrop_types::{AirdropClaimNullifierTarget, AirdropLeafDataTarget, AirdropParametersTarget, MerkleProofTarget};
use crate::core::proof::{deserialize_proof, SerializableProof};
use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};
use crate::errors::{WireError, WireResult};
use crate::gadgets::arithmetic;
use crate::gadgets::fixed_point::{fixed_div, fixed_mul, FIXED_POINT_SCALING_FACTOR};
use crate::gadgets::verify_message_signature;
use crate::utils::compare::compare_vectors;
use crate::utils::hash::compute_hash_targets;
use crate::utils::nullifier::{
    compute_utxo_commitment_hash, compute_utxo_nullifier_target, UTXOTarget as NullifierUTXOTarget,
};

/// Maximum depth of the Merkle tree for airdrop claims
pub const MAX_MERKLE_TREE_DEPTH: usize = 32;

/// Circuit for claiming airdropped tokens
#[derive(Clone)]
pub struct AirdropClaimCircuit {
    /// The airdrop parameters
    pub airdrop_parameters: AirdropParametersTarget,
    
    /// The airdrop parameters hash
    pub airdrop_parameters_hash: Vec<Target>,
    
    /// The leaf data for the claim
    pub leaf_data: AirdropLeafDataTarget,
    
    /// The Merkle proof for the claim
    pub merkle_proof: MerkleProofTarget,
    
    /// The recipient's public key
    pub recipient_pk: PublicKeyTarget,
    
    /// The recipient's signature
    pub recipient_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
}

impl AirdropClaimCircuit {
    /// Build the airdrop claim circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Vec<Target>, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        
        // Verify that the airdrop is active (current time is between start and end timestamps)
        let after_start = arithmetic::gte(
            builder,
            self.current_timestamp,
            self.airdrop_parameters.start_timestamp,
        );
        builder.connect(after_start, one);
        
        let before_end = arithmetic::lte(
            builder,
            self.current_timestamp,
            self.airdrop_parameters.end_timestamp,
        );
        builder.connect(before_end, one);
        
        // Verify that the recipient's public key hash matches the one in the leaf data
        let recipient_pk_hash = compute_hash_targets(builder, &[self.recipient_pk.point.x, self.recipient_pk.point.y]);
        let recipient_match = compare_vectors(
            builder,
            &self.leaf_data.recipient_pubkey_hash,
            &recipient_pk_hash,
        );
        builder.connect(recipient_match, one);
        
        // Compute the leaf hash
        let leaf_hash = self.leaf_data.compute_hash(builder);
        
        // Verify the Merkle proof
        let merkle_proof_valid = self.merkle_proof.verify(
            builder,
            leaf_hash,
            &self.airdrop_parameters.merkle_root,
        );
        builder.connect(merkle_proof_valid, one);
        
        // Verify the recipient's signature on the claim data
        let signature_message = vec![
            self.airdrop_parameters_hash[0], // Use the first element of the hash as a representative
            self.leaf_data.token_amount,
            self.current_timestamp,
        ];
        let signature_valid = verify_message_signature(
            builder,
            &signature_message,
            &self.recipient_signature,
            &self.recipient_pk,
        );
        builder.connect(signature_valid, one);
        
        // Create a claim nullifier to prevent double-claiming
        let claim_nullifier = AirdropClaimNullifierTarget {
            airdrop_parameters_hash: self.airdrop_parameters_hash.clone(),
            recipient_pubkey_hash: recipient_pk_hash.clone(),
        };
        
        // Compute the nullifier hash
        let nullifier_hash = claim_nullifier.compute_hash(builder);
        
        // Create a token output UTXO for the recipient
        let token_output_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the token output UTXO's asset ID to the token asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                token_output_utxo.asset_id_target[i],
                self.airdrop_parameters.token_asset_id[i],
            );
        }
        
        // Set the token output UTXO's amount to the token amount in the leaf data
        builder.connect(token_output_utxo.amount_target, self.leaf_data.token_amount);
        
        // Set the token output UTXO's owner to the recipient's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                token_output_utxo.owner_pubkey_hash_target[i],
                recipient_pk_hash[i],
            );
        }
        
        // Return the nullifier hash and token output UTXO
        Ok((nullifier_hash, token_output_utxo))
    }

    // TODO: Implement create_circuit, generate_proof, and verify_proof methods
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use rand::Rng;

    #[test]
    fn test_airdrop_claim_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_airdrop_claim_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_airdrop_claim_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
    
    #[test]
    fn test_airdrop_claim_merkle_proof() {
        // TODO: Implement test for Merkle proof verification
    }
    
    #[test]
    fn test_airdrop_claim_nullifier() {
        // TODO: Implement test for nullifier generation
    }
}
