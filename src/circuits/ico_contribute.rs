// ICO Contribute Circuit for the 0BTC Wire system
// This circuit allows users to contribute payment assets to an ICO

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::ico_types::{ICOEscrowUTXOTarget, ICOParametersTarget, ICOStatus};
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

/// Circuit for contributing to an ICO
#[derive(Clone)]
pub struct ICOContributeCircuit {
    /// The ICO parameters
    pub ico_parameters: ICOParametersTarget,
    
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The contributor's payment UTXO
    pub payment_utxo: UTXOTarget,
    
    /// The contribution amount in payment asset units
    pub contribution_amount: Target,
    
    /// The contributor's public key
    pub contributor_pk: PublicKeyTarget,
    
    /// The contributor's signature
    pub contributor_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
}

impl ICOContributeCircuit {
    /// Build the ICO contribute circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, ICOEscrowUTXOTarget, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        
        // Verify that the payment UTXO has the correct asset ID
        let payment_asset_id_match = compare_vectors(
            builder,
            &self.payment_utxo.asset_id_target,
            &self.ico_parameters.payment_asset_id,
        );
        builder.connect(payment_asset_id_match, one);
        
        // Verify that the contributor owns the payment UTXO
        let contributor_pk_hash = compute_hash_targets(builder, &[self.contributor_pk.point.x, self.contributor_pk.point.y]);
        let contributor_owns_payment = compare_vectors(
            builder,
            &self.payment_utxo.owner_pubkey_hash_target,
            &contributor_pk_hash,
        );
        builder.connect(contributor_owns_payment, one);
        
        // Verify that the contribution amount is greater than zero
        let contribution_positive = arithmetic::gt(
            builder,
            self.contribution_amount,
            zero,
        );
        builder.connect(contribution_positive, one);
        
        // Verify that the contribution amount is less than or equal to the payment UTXO amount
        let contribution_valid = arithmetic::lte(
            builder,
            self.contribution_amount,
            self.payment_utxo.amount_target,
        );
        builder.connect(contribution_valid, one);
        
        // Verify that the ICO is active (current time is between start and end timestamps)
        let after_start = arithmetic::gte(
            builder,
            self.current_timestamp,
            self.ico_parameters.start_timestamp,
        );
        builder.connect(after_start, one);
        
        let before_end = arithmetic::lte(
            builder,
            self.current_timestamp,
            self.ico_parameters.end_timestamp,
        );
        builder.connect(before_end, one);
        
        // Verify the contributor's signature on the contribution data
        let signature_message = vec![
            self.ico_parameters_hash[0], // Use the first element of the hash as a representative
            self.contribution_amount,
            self.current_timestamp,
        ];
        let signature_valid = verify_message_signature(
            builder,
            &signature_message,
            &self.contributor_signature,
            &self.contributor_pk,
        );
        builder.connect(signature_valid, one);
        
        // Create an ICO escrow UTXO to hold the contribution
        let escrow_utxo = ICOEscrowUTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the escrow UTXO's asset ID to the payment asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                escrow_utxo.utxo.asset_id_target[i],
                self.ico_parameters.payment_asset_id[i],
            );
        }
        
        // Set the escrow UTXO's amount to the contribution amount
        builder.connect(escrow_utxo.utxo.amount_target, self.contribution_amount);
        
        // Set the escrow UTXO's owner to a hash of the ICO parameters hash (to lock it)
        let escrow_owner_hash = compute_hash_targets(builder, &self.ico_parameters_hash);
        for i in 0..HASH_SIZE {
            builder.connect(
                escrow_utxo.utxo.owner_pubkey_hash_target[i],
                escrow_owner_hash[i],
            );
        }
        
        // Set the escrow metadata
        for i in 0..HASH_SIZE {
            // Set the ICO parameters hash
            builder.connect(
                escrow_utxo.metadata.ico_parameters_hash[i],
                self.ico_parameters_hash[i],
            );
            
            // Set the contributor's public key hash
            builder.connect(
                escrow_utxo.metadata.contributor_pubkey_hash[i],
                contributor_pk_hash[i],
            );
        }
        
        // Set the contribution amount and timestamp in the metadata
        builder.connect(escrow_utxo.metadata.contribution_amount, self.contribution_amount);
        builder.connect(escrow_utxo.metadata.timestamp, self.current_timestamp);
        
        // Calculate the change amount
        let change_amount = builder.sub(self.payment_utxo.amount_target, self.contribution_amount);
        
        // Create a change UTXO if the change amount is greater than zero
        let change_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the change UTXO's asset ID to the payment asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                change_utxo.asset_id_target[i],
                self.ico_parameters.payment_asset_id[i],
            );
        }
        
        // Set the change UTXO's amount to the change amount
        builder.connect(change_utxo.amount_target, change_amount);
        
        // Set the change UTXO's owner to the contributor's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(
                change_utxo.owner_pubkey_hash_target[i],
                contributor_pk_hash[i],
            );
        }
        
        // Return the contribution amount, escrow UTXO, and change UTXO
        Ok((self.contribution_amount, escrow_utxo, change_utxo))
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
    fn test_ico_contribute_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_ico_contribute_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_ico_contribute_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }
}
