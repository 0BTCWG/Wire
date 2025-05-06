// Stablecoin Redeem V2 Circuit for the 0BTC Wire system
// This circuit supports mixed collateral redemption (70% wBTC, 30% "zero") and protocol fees

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::collateral_utxo::CollateralMetadataTarget;
use crate::core::proof::{deserialize_proof, SerializableProof};
use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE, WBTC_ASSET_ID};
use crate::errors::{WireError, WireResult};
use crate::gadgets::arithmetic;
use crate::gadgets::fixed_point::{fixed_div, fixed_mul, FIXED_POINT_SCALING_FACTOR};
use crate::gadgets::verify_message_signature;
use crate::utils::compare::compare_vectors;
use crate::utils::hash::compute_hash_targets;
use crate::utils::nullifier::{
    compute_utxo_commitment_hash, compute_utxo_nullifier_target, UTXOTarget as NullifierUTXOTarget,
};

use crate::circuits::stablecoin_mint_v2::{ZUSD_ASSET_ID, ZERO_ASSET_ID, WBTC_COLLATERAL_PERCENTAGE, ZERO_COLLATERAL_PERCENTAGE, PROTOCOL_FEE_PERCENTAGE};

/// Represents a redemption approval from MPC operators
#[derive(Clone)]
pub struct RedemptionApprovalTarget {
    /// The timestamp of the approval
    pub timestamp: Target,
    
    /// The zUSD amount being redeemed
    pub zusd_amount: Target,
    
    /// The issuance ID of the stablecoin being redeemed
    pub issuance_id: Vec<Target>,

    /// The MPC operators' signature
    pub signature: SignatureTarget,
}

/// Circuit for redeeming zUSD stablecoins back to mixed collateral (wBTC and ZERO)
#[derive(Clone)]
pub struct StablecoinRedeemV2Circuit {
    /// The input zUSD UTXO
    pub zusd_input_utxo: UTXOTarget,
    
    /// The dual-price attestation
    pub price_attestation: DualPriceAttestationTarget,
    
    /// The redemption approval from MPC operators
    pub redemption_approval: RedemptionApprovalTarget,

    /// The MPC operators' public key
    pub mpc_pk: PublicKeyTarget,

    /// The user's public key
    pub user_pk: PublicKeyTarget,

    /// The user's signature
    pub user_signature: SignatureTarget,

    /// The current timestamp
    pub current_timestamp: Target,

    /// The time window for attestation validity
    pub time_window: Target,
    
    /// The protocol fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

/// Represents a dual-price attestation from MPC operators
#[derive(Clone)]
pub struct DualPriceAttestationTarget {
    /// The timestamp of the attestation
    pub timestamp: Target,

    /// The BTC/USD price
    pub btc_usd_price: Target,
    
    /// The ZERO/USD price
    pub zero_usd_price: Target,

    /// The MPC operators' signature
    pub signature: SignatureTarget,
}

impl StablecoinRedeemV2Circuit {
    /// Build the stablecoin redeem v2 circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, UTXOTarget, UTXOTarget, UTXOTarget, UTXOTarget)> {
        // Verify that the input UTXO has the correct asset ID (zUSD)
        let one = builder.one();
        let zero = builder.zero();

        // Verify zUSD input UTXO
        let is_zusd = compare_vectors(
            builder,
            &self.zusd_input_utxo.asset_id_target,
            &[builder.constant(F::from_canonical_u64(ZUSD_ASSET_ID[0] as u64))],
        );
        let is_zusd_target = builder.select(is_zusd, one, zero);
        builder.connect(is_zusd_target, one);

        // Verify the dual-price attestation signature
        let price_message = vec![
            self.price_attestation.timestamp,
            self.price_attestation.btc_usd_price,
            self.price_attestation.zero_usd_price,
        ];

        let price_sig_valid = verify_message_signature(
            builder,
            &price_message,
            &self.price_attestation.signature,
            &self.mpc_pk,
        );
        // Connect the result to a constant 1 (true)
        builder.connect(price_sig_valid, one);

        // Verify the timestamp is recent
        let time_diff = builder.sub(self.current_timestamp, self.price_attestation.timestamp);
        let is_recent = arithmetic::lt(builder, time_diff, self.time_window);
        builder.connect(is_recent, one);

        // Verify the redemption approval signature
        let approval_message = vec![
            self.redemption_approval.timestamp,
            self.redemption_approval.zusd_amount,
        ];
        // Add issuance ID to the message
        let mut full_approval_message = approval_message.clone();
        full_approval_message.extend_from_slice(&self.redemption_approval.issuance_id);

        let approval_sig_valid = verify_message_signature(
            builder,
            &full_approval_message,
            &self.redemption_approval.signature,
            &self.mpc_pk,
        );
        // Connect the result to a constant 1 (true)
        builder.connect(approval_sig_valid, one);

        // Verify the approval timestamp is recent
        let approval_time_diff = builder.sub(self.current_timestamp, self.redemption_approval.timestamp);
        let approval_is_recent = arithmetic::lt(builder, approval_time_diff, self.time_window);
        builder.connect(approval_is_recent, one);

        // Verify that the approved zUSD amount matches the input UTXO amount
        let amounts_match = builder.is_equal(self.redemption_approval.zusd_amount, self.zusd_input_utxo.amount_target);
        builder.connect(amounts_match, one);

        // Calculate the total USD value being redeemed
        let zusd_usd_value = self.zusd_input_utxo.amount_target; // 1:1 peg

        // Calculate protocol fee (0.1% of redeemed USD value)
        let million = builder.constant(F::from_canonical_u64(1_000_000));
        let fee_percentage = builder.constant(F::from_canonical_u64(PROTOCOL_FEE_PERCENTAGE));
        let protocol_fee_usd_result = fixed_mul(builder, zusd_usd_value, fee_percentage);
        let protocol_fee_usd = match protocol_fee_usd_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the net USD value after fee
        let net_zusd_usd_value = builder.sub(zusd_usd_value, protocol_fee_usd);

        // Calculate the target wBTC amount to return (70% of redeemed USD value / current wBTC/USD price)
        let wbtc_percentage = builder.constant(F::from_canonical_u64(WBTC_COLLATERAL_PERCENTAGE));
        
        // Calculate 70% of the net USD value
        let wbtc_usd_portion_result = fixed_mul(builder, net_zusd_usd_value, wbtc_percentage);
        let wbtc_usd_portion = match wbtc_usd_portion_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Convert wBTC USD value to wBTC amount
        let wbtc_amount_result = fixed_div(builder, wbtc_usd_portion, self.price_attestation.btc_usd_price);
        let wbtc_amount = match wbtc_amount_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Calculate the target ZERO amount to return (30% of redeemed USD value / current zero/USD price)
        let zero_percentage = builder.constant(F::from_canonical_u64(ZERO_COLLATERAL_PERCENTAGE));
        
        // Calculate 30% of the net USD value
        let zero_usd_portion_result = fixed_mul(builder, net_zusd_usd_value, zero_percentage);
        let zero_usd_portion = match zero_usd_portion_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Convert ZERO USD value to ZERO amount
        let zero_amount_result = fixed_div(builder, zero_usd_portion, self.price_attestation.zero_usd_price);
        let zero_amount = match zero_amount_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Create wBTC output UTXO
        let wbtc_output_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the wBTC output UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    wbtc_output_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(wbtc_output_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the wBTC output UTXO's amount
        builder.connect(wbtc_output_utxo.amount_target, wbtc_amount);
        
        // Set the wBTC output UTXO's owner to the user's public key hash
        let user_pk_hash = compute_hash_targets(builder, &[self.user_pk.point.x, self.user_pk.point.y]);
        for i in 0..HASH_SIZE {
            builder.connect(wbtc_output_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }
        
        // Create ZERO output UTXO
        let zero_output_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the ZERO output UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    zero_output_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zero_output_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the ZERO output UTXO's amount
        builder.connect(zero_output_utxo.amount_target, zero_amount);
        
        // Set the ZERO output UTXO's owner to the user's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(zero_output_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }

        // Create protocol fee UTXO (in zUSD)
        let fee_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the fee UTXO's asset ID to zUSD
        for i in 0..HASH_SIZE {
            if i < ZUSD_ASSET_ID.len() {
                builder.connect(
                    fee_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZUSD_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(fee_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the fee UTXO's amount
        builder.connect(fee_utxo.amount_target, protocol_fee_usd);
        
        // Set the fee UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                fee_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }

        // Return the redeemed zUSD amount, wBTC output UTXO, ZERO output UTXO, and fee UTXO
        Ok((
            self.zusd_input_utxo.amount_target,
            wbtc_output_utxo,
            zero_output_utxo,
            fee_utxo,
            self.zusd_input_utxo.clone(),
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
    fn test_stablecoin_redeem_v2_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_stablecoin_redeem_v2_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_stablecoin_redeem_v2_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }

    #[test]
    fn test_stablecoin_redeem_v2_protocol_fees() {
        // TODO: Implement test for protocol fees
    }
}
