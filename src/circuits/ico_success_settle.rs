// ICO Success Settle Circuit for the 0BTC Wire system
// This circuit distributes tokens and funds upon successful ICO completion

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::ico_types::{ICOEscrowUTXOTarget, ICOParametersTarget, ICOSettlementAttestationTarget, ICOStatus, ICO_PROTOCOL_FEE_PERCENTAGE};
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

/// Maximum number of contributions that can be processed in a single settlement
pub const MAX_CONTRIBUTIONS: usize = 10;

/// Circuit for settling a successful ICO
#[derive(Clone)]
pub struct ICOSuccessSettleCircuit {
    /// The ICO parameters
    pub ico_parameters: ICOParametersTarget,
    
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The ICO settlement attestation
    pub settlement_attestation: ICOSettlementAttestationTarget,
    
    /// The MPC operators' public key
    pub mpc_pk: PublicKeyTarget,
    
    /// The locked token UTXO
    pub locked_token_utxo: UTXOTarget,
    
    /// The escrow UTXOs (contributions)
    pub escrow_utxos: Vec<ICOEscrowUTXOTarget>,
    
    /// The current timestamp
    pub current_timestamp: Target,
    
    /// The protocol fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl ICOSuccessSettleCircuit {
    /// Build the ICO success settle circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, Vec<UTXOTarget>, UTXOTarget, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        let million = builder.constant(F::from_canonical_u64(1_000_000));
        
        // Verify that the ICO parameters hash in the settlement attestation matches the provided hash
        let params_hash_match = compare_vectors(
            builder,
            &self.settlement_attestation.ico_parameters_hash,
            &self.ico_parameters_hash,
        );
        builder.connect(params_hash_match, one);
        
        // Verify that the settlement attestation indicates a successful ICO
        let success_status = builder.constant(F::from_canonical_u64(ICOStatus::Successful as u64));
        let status_is_success = builder.is_equal(
            self.settlement_attestation.ico_status,
            success_status,
        );
        builder.connect(status_is_success, one);
        
        // Verify the settlement attestation signature
        let attestation_message = vec![
            self.settlement_attestation.ico_parameters_hash[0], // Use the first element of the hash as a representative
            self.settlement_attestation.ico_status,
            self.settlement_attestation.total_raised,
            self.settlement_attestation.timestamp,
        ];
        let attestation_sig_valid = verify_message_signature(
            builder,
            &attestation_message,
            &self.settlement_attestation.signature,
            &self.mpc_pk,
        );
        builder.connect(attestation_sig_valid, one);
        
        // Verify that the settlement timestamp is after the ICO end timestamp
        let after_end = arithmetic::gt(
            builder,
            self.settlement_attestation.timestamp,
            self.ico_parameters.end_timestamp,
        );
        builder.connect(after_end, one);
        
        // Verify that the settlement attestation is recent
        let time_diff = builder.sub(self.current_timestamp, self.settlement_attestation.timestamp);
        let is_recent = arithmetic::lt(
            builder,
            time_diff,
            builder.constant(F::from_canonical_u64(86400)), // 24 hours
        );
        builder.connect(is_recent, one);
        
        // Verify that the total raised is at least the minimum funding goal
        let min_goal_reached = arithmetic::gte(
            builder,
            self.settlement_attestation.total_raised,
            self.ico_parameters.min_funding_goal,
        );
        builder.connect(min_goal_reached, one);
        
        // Verify that the total raised is at most the maximum funding cap
        let max_cap_respected = arithmetic::lte(
            builder,
            self.settlement_attestation.total_raised,
            self.ico_parameters.max_funding_cap,
        );
        builder.connect(max_cap_respected, one);
        
        // Verify that the locked token UTXO has the correct asset ID
        let token_asset_id_match = compare_vectors(
            builder,
            &self.locked_token_utxo.asset_id_target,
            &self.ico_parameters.token_asset_id,
        );
        builder.connect(token_asset_id_match, one);
        
        // Verify that the locked token UTXO has the correct amount
        let token_amount_match = builder.is_equal(
            self.locked_token_utxo.amount_target,
            self.ico_parameters.token_supply,
        );
        builder.connect(token_amount_match, one);
        
        // Verify that the locked token UTXO is owned by the ICO (locked)
        let locked_owner_hash = compute_hash_targets(builder, &self.ico_parameters_hash);
        let locked_owner_match = compare_vectors(
            builder,
            &self.locked_token_utxo.owner_pubkey_hash_target,
            &locked_owner_hash,
        );
        builder.connect(locked_owner_match, one);
        
        // Process each escrow UTXO (contribution)
        let mut total_contribution = builder.zero();
        let mut token_output_utxos = Vec::new();
        
        for escrow_utxo in &self.escrow_utxos {
            // Verify that the escrow UTXO has the correct asset ID
            let payment_asset_id_match = compare_vectors(
                builder,
                &escrow_utxo.utxo.asset_id_target,
                &self.ico_parameters.payment_asset_id,
            );
            builder.connect(payment_asset_id_match, one);
            
            // Verify that the escrow UTXO is owned by the ICO (locked)
            let escrow_owner_match = compare_vectors(
                builder,
                &escrow_utxo.utxo.owner_pubkey_hash_target,
                &locked_owner_hash,
            );
            builder.connect(escrow_owner_match, one);
            
            // Verify that the escrow metadata has the correct ICO parameters hash
            let escrow_params_hash_match = compare_vectors(
                builder,
                &escrow_utxo.metadata.ico_parameters_hash,
                &self.ico_parameters_hash,
            );
            builder.connect(escrow_params_hash_match, one);
            
            // Verify that the contribution timestamp is within the ICO period
            let contribution_after_start = arithmetic::gte(
                builder,
                escrow_utxo.metadata.timestamp,
                self.ico_parameters.start_timestamp,
            );
            builder.connect(contribution_after_start, one);
            
            let contribution_before_end = arithmetic::lte(
                builder,
                escrow_utxo.metadata.timestamp,
                self.ico_parameters.end_timestamp,
            );
            builder.connect(contribution_before_end, one);
            
            // Add the contribution amount to the total
            total_contribution = builder.add(total_contribution, escrow_utxo.metadata.contribution_amount);
            
            // Calculate the token amount for this contributor
            // tokens = contribution_amount / price_per_token
            let token_amount_result = fixed_div(
                builder,
                escrow_utxo.metadata.contribution_amount,
                self.ico_parameters.price_per_token,
            );
            let token_amount = match token_amount_result {
                Ok(result) => result,
                Err(_) => builder.zero(), // Handle division error
            };
            
            // Create a token output UTXO for this contributor
            let token_output_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
            
            // Set the token output UTXO's asset ID to the token asset ID
            for i in 0..HASH_SIZE {
                builder.connect(
                    token_output_utxo.asset_id_target[i],
                    self.ico_parameters.token_asset_id[i],
                );
            }
            
            // Set the token output UTXO's amount to the calculated token amount
            builder.connect(token_output_utxo.amount_target, token_amount);
            
            // Set the token output UTXO's owner to the contributor's public key hash
            for i in 0..HASH_SIZE {
                builder.connect(
                    token_output_utxo.owner_pubkey_hash_target[i],
                    escrow_utxo.metadata.contributor_pubkey_hash[i],
                );
            }
            
            // Add the token output UTXO to the list
            token_output_utxos.push(token_output_utxo);
        }
        
        // Verify that the total contribution matches the total raised in the attestation
        let total_match = builder.is_equal(
            total_contribution,
            self.settlement_attestation.total_raised,
        );
        builder.connect(total_match, one);
        
        // Calculate the protocol fee
        // fee = total_raised * fee_percentage / 1_000_000
        let fee_percentage = builder.constant(F::from_canonical_u64(ICO_PROTOCOL_FEE_PERCENTAGE));
        let fee_result = fixed_mul(
            builder,
            self.settlement_attestation.total_raised,
            fee_percentage,
        );
        let protocol_fee = match fee_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the creator's payment amount (total raised minus protocol fee)
        let creator_payment = builder.sub(self.settlement_attestation.total_raised, protocol_fee);
        
        // Create a payment UTXO for the creator
        let creator_payment_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the creator payment UTXO's asset ID to the payment asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                creator_payment_utxo.asset_id_target[i],
                self.ico_parameters.payment_asset_id[i],
            );
        }
        
        // Set the creator payment UTXO's amount to the creator's payment amount
        builder.connect(creator_payment_utxo.amount_target, creator_payment);
        
        // Set the creator payment UTXO's owner to the creator's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                creator_payment_utxo.owner_pubkey_hash_target[i],
                self.ico_parameters.creator_pubkey_hash[i],
            );
        }
        
        // Create a protocol fee UTXO
        let protocol_fee_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the protocol fee UTXO's asset ID to the payment asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_fee_utxo.asset_id_target[i],
                self.ico_parameters.payment_asset_id[i],
            );
        }
        
        // Set the protocol fee UTXO's amount to the protocol fee
        builder.connect(protocol_fee_utxo.amount_target, protocol_fee);
        
        // Set the protocol fee UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_fee_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }
        
        // Return the total raised, token output UTXOs, creator payment UTXO, and protocol fee UTXO
        Ok((
            self.settlement_attestation.total_raised,
            token_output_utxos,
            creator_payment_utxo,
            protocol_fee_utxo,
        ))
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
    fn test_ico_success_settle_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_ico_success_settle_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_ico_success_settle_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
}
