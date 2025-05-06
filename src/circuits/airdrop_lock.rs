// Airdrop Lock Circuit for the 0BTC Wire system
// This circuit allows creators to lock the total airdrop supply and commit to the Merkle root

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::airdrop_types::AirdropParametersTarget;
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

/// Circuit for locking tokens for an airdrop
#[derive(Clone)]
pub struct AirdropLockCircuit {
    /// The airdrop parameters
    pub airdrop_parameters: AirdropParametersTarget,
    
    /// The creator's token UTXO (containing the tokens to be airdropped)
    pub creator_token_utxo: UTXOTarget,
    
    /// The creator's public key
    pub creator_pk: PublicKeyTarget,
    
    /// The creator's signature
    pub creator_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
}

impl AirdropLockCircuit {
    /// Build the airdrop lock circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Vec<Target>, UTXOTarget, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        
        // Verify that the creator's token UTXO has the correct asset ID
        let token_asset_id_match = compare_vectors(
            builder,
            &self.creator_token_utxo.asset_id_target,
            &self.airdrop_parameters.token_asset_id,
        );
        builder.connect(token_asset_id_match, one);
        
        // Verify that the creator owns the token UTXO
        let creator_pk_hash = compute_hash_targets(builder, &[self.creator_pk.point.x, self.creator_pk.point.y]);
        let creator_owns_tokens = compare_vectors(
            builder,
            &self.creator_token_utxo.owner_pubkey_hash_target,
            &creator_pk_hash,
        );
        builder.connect(creator_owns_tokens, one);
        
        // Verify that the token supply in the UTXO matches the airdrop parameters
        let token_supply_match = builder.is_equal(
            self.creator_token_utxo.amount_target,
            self.airdrop_parameters.token_supply,
        );
        builder.connect(token_supply_match, one);
        
        // Verify that the airdrop parameters are valid
        
        // 1. Verify that the start timestamp is in the future or present
        let start_valid = arithmetic::gte(
            builder,
            self.airdrop_parameters.start_timestamp,
            self.current_timestamp,
        );
        builder.connect(start_valid, one);
        
        // 2. Verify that the end timestamp is after the start timestamp
        let end_after_start = arithmetic::gt(
            builder,
            self.airdrop_parameters.end_timestamp,
            self.airdrop_parameters.start_timestamp,
        );
        builder.connect(end_after_start, one);
        
        // 3. Verify that the creator's public key hash matches the one in the airdrop parameters
        let creator_pk_hash_match = compare_vectors(
            builder,
            &self.airdrop_parameters.creator_pubkey_hash,
            &creator_pk_hash,
        );
        builder.connect(creator_pk_hash_match, one);
        
        // Compute the airdrop parameters hash
        let airdrop_parameters_hash = self.airdrop_parameters.compute_hash(builder);
        
        // Verify the creator's signature on the airdrop parameters hash
        let signature_message = airdrop_parameters_hash.clone();
        let signature_valid = verify_message_signature(
            builder,
            &signature_message,
            &self.creator_signature,
            &self.creator_pk,
        );
        builder.connect(signature_valid, one);
        
        // Create an airdrop parameter UTXO to store the airdrop configuration on-chain
        let airdrop_parameter_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the airdrop parameter UTXO's asset ID to a special value (all zeros)
        for i in 0..HASH_SIZE {
            builder.connect(airdrop_parameter_utxo.asset_id_target[i], zero);
        }
        
        // Set the airdrop parameter UTXO's amount to zero (it's just a marker)
        builder.connect(airdrop_parameter_utxo.amount_target, zero);
        
        // Set the airdrop parameter UTXO's owner to the creator's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                airdrop_parameter_utxo.owner_pubkey_hash_target[i],
                creator_pk_hash[i],
            );
        }
        
        // Create a locked token UTXO to hold the tokens until they are claimed
        let locked_token_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the locked token UTXO's asset ID to the token asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                locked_token_utxo.asset_id_target[i],
                self.airdrop_parameters.token_asset_id[i],
            );
        }
        
        // Set the locked token UTXO's amount to the token supply
        builder.connect(locked_token_utxo.amount_target, self.airdrop_parameters.token_supply);
        
        // Set the locked token UTXO's owner to a hash of the airdrop parameters hash (to lock it)
        let locked_owner_hash = compute_hash_targets(builder, &airdrop_parameters_hash);
        for i in 0..HASH_SIZE {
            builder.connect(
                locked_token_utxo.owner_pubkey_hash_target[i],
                locked_owner_hash[i],
            );
        }
        
        // Return the airdrop parameters hash, airdrop parameter UTXO, and locked token UTXO
        Ok((airdrop_parameters_hash, airdrop_parameter_utxo, locked_token_utxo))
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
    fn test_airdrop_lock_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_airdrop_lock_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_airdrop_lock_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
}
