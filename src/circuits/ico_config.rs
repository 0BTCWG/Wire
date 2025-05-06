// ICO Config Circuit for the 0BTC Wire system
// This circuit allows creators to commit ICO parameters on-chain

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::ico_types::{ICOParametersTarget, ICO_PROTOCOL_FEE_PERCENTAGE};
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

/// Circuit for creating an ICO configuration
#[derive(Clone)]
pub struct ICOConfigCircuit {
    /// The ICO parameters
    pub ico_parameters: ICOParametersTarget,
    
    /// The creator's token UTXO (containing the tokens to be sold)
    pub creator_token_utxo: UTXOTarget,
    
    /// The creator's public key
    pub creator_pk: PublicKeyTarget,
    
    /// The creator's signature
    pub creator_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
}

impl ICOConfigCircuit {
    /// Build the ICO config circuit
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
            &self.ico_parameters.token_asset_id,
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
        
        // Verify that the token supply in the UTXO matches the ICO parameters
        let token_supply_match = builder.is_equal(
            self.creator_token_utxo.amount_target,
            self.ico_parameters.token_supply,
        );
        builder.connect(token_supply_match, one);
        
        // Verify that the ICO parameters are valid
        
        // 1. Verify that the start timestamp is in the future
        let start_in_future = arithmetic::gt(
            builder,
            self.ico_parameters.start_timestamp,
            self.current_timestamp,
        );
        builder.connect(start_in_future, one);
        
        // 2. Verify that the end timestamp is after the start timestamp
        let end_after_start = arithmetic::gt(
            builder,
            self.ico_parameters.end_timestamp,
            self.ico_parameters.start_timestamp,
        );
        builder.connect(end_after_start, one);
        
        // 3. Verify that the minimum funding goal is greater than zero
        let min_goal_positive = arithmetic::gt(
            builder,
            self.ico_parameters.min_funding_goal,
            zero,
        );
        builder.connect(min_goal_positive, one);
        
        // 4. Verify that the maximum funding cap is greater than or equal to the minimum funding goal
        let max_cap_valid = arithmetic::gte(
            builder,
            self.ico_parameters.max_funding_cap,
            self.ico_parameters.min_funding_goal,
        );
        builder.connect(max_cap_valid, one);
        
        // 5. Verify that the price per token is greater than zero
        let price_positive = arithmetic::gt(
            builder,
            self.ico_parameters.price_per_token,
            zero,
        );
        builder.connect(price_positive, one);
        
        // 6. Verify that the fee percentage is equal to the protocol fee percentage
        let fee_percentage_match = builder.is_equal(
            self.ico_parameters.fee_percentage,
            builder.constant(F::from_canonical_u64(ICO_PROTOCOL_FEE_PERCENTAGE)),
        );
        builder.connect(fee_percentage_match, one);
        
        // 7. Verify that the creator's public key hash matches the one in the ICO parameters
        let creator_pk_hash_match = compare_vectors(
            builder,
            &self.ico_parameters.creator_pubkey_hash,
            &creator_pk_hash,
        );
        builder.connect(creator_pk_hash_match, one);
        
        // Compute the ICO parameters hash
        let ico_parameters_hash = self.ico_parameters.compute_hash(builder);
        
        // Verify the creator's signature on the ICO parameters hash
        let signature_message = ico_parameters_hash.clone();
        let signature_valid = verify_message_signature(
            builder,
            &signature_message,
            &self.creator_signature,
            &self.creator_pk,
        );
        builder.connect(signature_valid, one);
        
        // Create an ICO parameter UTXO to store the ICO configuration on-chain
        let ico_parameter_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the ICO parameter UTXO's asset ID to a special value (all zeros)
        for i in 0..HASH_SIZE {
            builder.connect(ico_parameter_utxo.asset_id_target[i], zero);
        }
        
        // Set the ICO parameter UTXO's amount to zero (it's just a marker)
        builder.connect(ico_parameter_utxo.amount_target, zero);
        
        // Set the ICO parameter UTXO's owner to the creator's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                ico_parameter_utxo.owner_pubkey_hash_target[i],
                creator_pk_hash[i],
            );
        }
        
        // Create a locked token UTXO to hold the tokens until the ICO is settled
        let locked_token_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the locked token UTXO's asset ID to the token asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                locked_token_utxo.asset_id_target[i],
                self.ico_parameters.token_asset_id[i],
            );
        }
        
        // Set the locked token UTXO's amount to the token supply
        builder.connect(locked_token_utxo.amount_target, self.ico_parameters.token_supply);
        
        // Set the locked token UTXO's owner to a hash of the ICO parameters hash (to lock it)
        let locked_owner_hash = compute_hash_targets(builder, &ico_parameters_hash);
        for i in 0..HASH_SIZE {
            builder.connect(
                locked_token_utxo.owner_pubkey_hash_target[i],
                locked_owner_hash[i],
            );
        }
        
        // Return the ICO parameters hash, ICO parameter UTXO, and locked token UTXO
        Ok((ico_parameters_hash, ico_parameter_utxo, locked_token_utxo))
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
    fn test_ico_config_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_ico_config_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_ico_config_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
}
