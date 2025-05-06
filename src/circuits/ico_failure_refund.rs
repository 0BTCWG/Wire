// ICO Failure Refund Circuit for the 0BTC Wire system
// This circuit allows users to claim refunds upon failed ICO

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::ico_types::{ICOEscrowUTXOTarget, ICOParametersTarget, ICOSettlementAttestationTarget, ICOStatus};
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

/// Circuit for claiming a refund from a failed ICO
#[derive(Clone)]
pub struct ICOFailureRefundCircuit {
    /// The ICO parameters
    pub ico_parameters: ICOParametersTarget,
    
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The ICO settlement attestation
    pub settlement_attestation: ICOSettlementAttestationTarget,
    
    /// The MPC operators' public key
    pub mpc_pk: PublicKeyTarget,
    
    /// The escrow UTXO (contribution)
    pub escrow_utxo: ICOEscrowUTXOTarget,
    
    /// The contributor's public key
    pub contributor_pk: PublicKeyTarget,
    
    /// The contributor's signature
    pub contributor_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
}

impl ICOFailureRefundCircuit {
    /// Build the ICO failure refund circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        
        // Verify that the ICO parameters hash in the settlement attestation matches the provided hash
        let params_hash_match = compare_vectors(
            builder,
            &self.settlement_attestation.ico_parameters_hash,
            &self.ico_parameters_hash,
        );
        builder.connect(params_hash_match, one);
        
        // Verify that the settlement attestation indicates a failed or canceled ICO
        let failed_status = builder.constant(F::from_canonical_u64(ICOStatus::Failed as u64));
        let canceled_status = builder.constant(F::from_canonical_u64(ICOStatus::Canceled as u64));
        
        let status_is_failed = builder.is_equal(
            self.settlement_attestation.ico_status,
            failed_status,
        );
        
        let status_is_canceled = builder.is_equal(
            self.settlement_attestation.ico_status,
            canceled_status,
        );
        
        let status_valid = builder.or(status_is_failed, status_is_canceled);
        builder.connect(status_valid, one);
        
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
        // For a canceled ICO, this check is not necessary, but we'll keep it for simplicity
        let after_end = arithmetic::gt(
            builder,
            self.settlement_attestation.timestamp,
            self.ico_parameters.end_timestamp,
        );
        
        // If the ICO is canceled, we don't need to check if the settlement is after the end
        let need_to_check_after_end = builder.not(status_is_canceled);
        let after_end_or_canceled = builder.or(after_end, status_is_canceled);
        builder.connect(after_end_or_canceled, one);
        
        // Verify that the settlement attestation is recent
        let time_diff = builder.sub(self.current_timestamp, self.settlement_attestation.timestamp);
        let is_recent = arithmetic::lt(
            builder,
            time_diff,
            builder.constant(F::from_canonical_u64(86400 * 30)), // 30 days
        );
        builder.connect(is_recent, one);
        
        // Verify that the escrow UTXO has the correct asset ID
        let payment_asset_id_match = compare_vectors(
            builder,
            &self.escrow_utxo.utxo.asset_id_target,
            &self.ico_parameters.payment_asset_id,
        );
        builder.connect(payment_asset_id_match, one);
        
        // Verify that the escrow UTXO is owned by the ICO (locked)
        let locked_owner_hash = compute_hash_targets(builder, &self.ico_parameters_hash);
        let escrow_owner_match = compare_vectors(
            builder,
            &self.escrow_utxo.utxo.owner_pubkey_hash_target,
            &locked_owner_hash,
        );
        builder.connect(escrow_owner_match, one);
        
        // Verify that the escrow metadata has the correct ICO parameters hash
        let escrow_params_hash_match = compare_vectors(
            builder,
            &self.escrow_utxo.metadata.ico_parameters_hash,
            &self.ico_parameters_hash,
        );
        builder.connect(escrow_params_hash_match, one);
        
        // Verify that the contributor's public key hash matches the one in the escrow metadata
        let contributor_pk_hash = compute_hash_targets(builder, &[self.contributor_pk.point.x, self.contributor_pk.point.y]);
        let contributor_match = compare_vectors(
            builder,
            &self.escrow_utxo.metadata.contributor_pubkey_hash,
            &contributor_pk_hash,
        );
        builder.connect(contributor_match, one);
        
        // Verify the contributor's signature on the refund request
        let signature_message = vec![
            self.ico_parameters_hash[0], // Use the first element of the hash as a representative
            self.escrow_utxo.metadata.contribution_amount,
            self.current_timestamp,
        ];
        let signature_valid = verify_message_signature(
            builder,
            &signature_message,
            &self.contributor_signature,
            &self.contributor_pk,
        );
        builder.connect(signature_valid, one);
        
        // Create a refund UTXO for the contributor
        let refund_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the refund UTXO's asset ID to the payment asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                refund_utxo.asset_id_target[i],
                self.ico_parameters.payment_asset_id[i],
            );
        }
        
        // Set the refund UTXO's amount to the contribution amount
        builder.connect(refund_utxo.amount_target, self.escrow_utxo.metadata.contribution_amount);
        
        // Set the refund UTXO's owner to the contributor's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                refund_utxo.owner_pubkey_hash_target[i],
                contributor_pk_hash[i],
            );
        }
        
        // Return the contribution amount and refund UTXO
        Ok((self.escrow_utxo.metadata.contribution_amount, refund_utxo))
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
    fn test_ico_failure_refund_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_ico_failure_refund_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_ico_failure_refund_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
}
