// Liquidation Circuit for the 0BTC Wire system
// This circuit handles liquidation of undercollateralized stablecoin positions

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

use crate::circuits::stablecoin_mint_v2::{ZUSD_ASSET_ID, ZERO_ASSET_ID, WBTC_COLLATERAL_PERCENTAGE, ZERO_COLLATERAL_PERCENTAGE};

/// Minimum collateralization ratio (150%)
pub const MIN_COLLATERALIZATION_RATIO: u64 = 150 * FIXED_POINT_SCALING_FACTOR / 100;

/// Liquidation threshold ratio (120%)
pub const LIQUIDATION_THRESHOLD_RATIO: u64 = 120 * FIXED_POINT_SCALING_FACTOR / 100;

/// Liquidation penalty percentage (10%)
pub const LIQUIDATION_PENALTY_PERCENTAGE: u64 = 100_000; // 10% = 100_000 / 1_000_000

/// Liquidator reward percentage (5%)
pub const LIQUIDATOR_REWARD_PERCENTAGE: u64 = 50_000; // 5% = 50_000 / 1_000_000

/// Represents a liquidation attestation from MPC operators
#[derive(Clone)]
pub struct LiquidationAttestationTarget {
    /// The timestamp of the attestation
    pub timestamp: Target,
    
    /// The issuance ID of the stablecoin being liquidated
    pub issuance_id: Vec<Target>,
    
    /// The wBTC collateral amount
    pub wbtc_collateral_amount: Target,
    
    /// The ZERO collateral amount
    pub zero_collateral_amount: Target,
    
    /// The zUSD amount issued
    pub zusd_amount: Target,
    
    /// The BTC/USD price at the time of liquidation
    pub btc_usd_price: Target,
    
    /// The ZERO/USD price at the time of liquidation
    pub zero_usd_price: Target,

    /// The MPC operators' signature
    pub signature: SignatureTarget,
}

/// Circuit for liquidating undercollateralized stablecoin positions
#[derive(Clone)]
pub struct LiquidationCircuit {
    /// The liquidation attestation from MPC operators
    pub liquidation_attestation: LiquidationAttestationTarget,
    
    /// The MPC operators' public key
    pub mpc_pk: PublicKeyTarget,
    
    /// The liquidator's public key
    pub liquidator_pk: PublicKeyTarget,
    
    /// The liquidator's signature
    pub liquidator_signature: SignatureTarget,
    
    /// The current timestamp
    pub current_timestamp: Target,
    
    /// The time window for attestation validity
    pub time_window: Target,
    
    /// The protocol fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl LiquidationCircuit {
    /// Build the liquidation circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, UTXOTarget, UTXOTarget, UTXOTarget, UTXOTarget)> {
        let one = builder.one();
        let zero = builder.zero();
        let million = builder.constant(F::from_canonical_u64(1_000_000));
        
        // Verify the liquidation attestation signature
        let attestation_message = vec![
            self.liquidation_attestation.timestamp,
            self.liquidation_attestation.wbtc_collateral_amount,
            self.liquidation_attestation.zero_collateral_amount,
            self.liquidation_attestation.zusd_amount,
            self.liquidation_attestation.btc_usd_price,
            self.liquidation_attestation.zero_usd_price,
        ];
        // Add issuance ID to the message
        let mut full_attestation_message = attestation_message.clone();
        full_attestation_message.extend_from_slice(&self.liquidation_attestation.issuance_id);
        
        let attestation_sig_valid = verify_message_signature(
            builder,
            &full_attestation_message,
            &self.liquidation_attestation.signature,
            &self.mpc_pk,
        );
        // Connect the result to a constant 1 (true)
        builder.connect(attestation_sig_valid, one);
        
        // Verify the attestation timestamp is recent
        let time_diff = builder.sub(self.current_timestamp, self.liquidation_attestation.timestamp);
        let is_recent = arithmetic::lt(builder, time_diff, self.time_window);
        builder.connect(is_recent, one);
        
        // Calculate the USD value of the collateral
        // wbtc_usd_value = wbtc_collateral_amount * btc_usd_price
        let wbtc_usd_value_result = fixed_mul(
            builder,
            self.liquidation_attestation.wbtc_collateral_amount,
            self.liquidation_attestation.btc_usd_price,
        );
        let wbtc_usd_value = match wbtc_usd_value_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // zero_usd_value = zero_collateral_amount * zero_usd_price
        let zero_usd_value_result = fixed_mul(
            builder,
            self.liquidation_attestation.zero_collateral_amount,
            self.liquidation_attestation.zero_usd_price,
        );
        let zero_usd_value = match zero_usd_value_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // total_collateral_usd_value = wbtc_usd_value + zero_usd_value
        let total_collateral_usd_value = builder.add(wbtc_usd_value, zero_usd_value);
        
        // Calculate the current collateralization ratio
        // collateralization_ratio = total_collateral_usd_value / zusd_amount
        let collateralization_ratio_result = fixed_div(
            builder,
            total_collateral_usd_value,
            self.liquidation_attestation.zusd_amount,
        );
        let collateralization_ratio = match collateralization_ratio_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };
        
        // Verify that the position is undercollateralized
        // collateralization_ratio < LIQUIDATION_THRESHOLD_RATIO
        let liquidation_threshold = builder.constant(F::from_canonical_u64(LIQUIDATION_THRESHOLD_RATIO));
        let is_undercollateralized = arithmetic::lt(builder, collateralization_ratio, liquidation_threshold);
        builder.connect(is_undercollateralized, one);
        
        // Calculate the liquidation penalty
        // penalty_amount = zusd_amount * LIQUIDATION_PENALTY_PERCENTAGE / 1_000_000
        let penalty_percentage = builder.constant(F::from_canonical_u64(LIQUIDATION_PENALTY_PERCENTAGE));
        let penalty_amount_result = fixed_mul(
            builder,
            self.liquidation_attestation.zusd_amount,
            penalty_percentage,
        );
        let penalty_amount = match penalty_amount_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the liquidator reward
        // liquidator_reward = zusd_amount * LIQUIDATOR_REWARD_PERCENTAGE / 1_000_000
        let reward_percentage = builder.constant(F::from_canonical_u64(LIQUIDATOR_REWARD_PERCENTAGE));
        let liquidator_reward_result = fixed_mul(
            builder,
            self.liquidation_attestation.zusd_amount,
            reward_percentage,
        );
        let liquidator_reward = match liquidator_reward_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the protocol fee (remaining penalty after liquidator reward)
        // protocol_fee = penalty_amount - liquidator_reward
        let protocol_fee = builder.sub(penalty_amount, liquidator_reward);
        
        // Calculate the amount of zUSD to be burned
        // zusd_to_burn = zusd_amount
        let zusd_to_burn = self.liquidation_attestation.zusd_amount;
        
        // Create zUSD burn UTXO
        let zusd_burn_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the zUSD burn UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZUSD_ASSET_ID.len() {
                builder.connect(
                    zusd_burn_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZUSD_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zusd_burn_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the zUSD burn UTXO's amount
        builder.connect(zusd_burn_utxo.amount_target, zusd_to_burn);
        
        // Set the zUSD burn UTXO's owner to the MPC's public key hash (to be burned)
        let mpc_pk_hash = compute_hash_targets(builder, &[self.mpc_pk.point.x, self.mpc_pk.point.y]);
        for i in 0..HASH_SIZE {
            builder.connect(zusd_burn_utxo.owner_pubkey_hash_target[i], mpc_pk_hash[i]);
        }
        
        // Calculate the liquidator's wBTC reward
        // liquidator_wbtc_reward = wbtc_collateral_amount * liquidator_reward / zusd_amount
        let liquidator_wbtc_reward_result = fixed_mul(
            builder,
            self.liquidation_attestation.wbtc_collateral_amount,
            liquidator_reward,
        );
        let liquidator_wbtc_reward = match liquidator_wbtc_reward_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, self.liquidation_attestation.zusd_amount)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the liquidator's ZERO reward
        // liquidator_zero_reward = zero_collateral_amount * liquidator_reward / zusd_amount
        let liquidator_zero_reward_result = fixed_mul(
            builder,
            self.liquidation_attestation.zero_collateral_amount,
            liquidator_reward,
        );
        let liquidator_zero_reward = match liquidator_zero_reward_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, self.liquidation_attestation.zusd_amount)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the protocol's wBTC fee
        // protocol_wbtc_fee = wbtc_collateral_amount * protocol_fee / zusd_amount
        let protocol_wbtc_fee_result = fixed_mul(
            builder,
            self.liquidation_attestation.wbtc_collateral_amount,
            protocol_fee,
        );
        let protocol_wbtc_fee = match protocol_wbtc_fee_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, self.liquidation_attestation.zusd_amount)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the protocol's ZERO fee
        // protocol_zero_fee = zero_collateral_amount * protocol_fee / zusd_amount
        let protocol_zero_fee_result = fixed_mul(
            builder,
            self.liquidation_attestation.zero_collateral_amount,
            protocol_fee,
        );
        let protocol_zero_fee = match protocol_zero_fee_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, self.liquidation_attestation.zusd_amount)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Create liquidator wBTC reward UTXO
        let liquidator_wbtc_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the liquidator wBTC UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    liquidator_wbtc_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(liquidator_wbtc_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the liquidator wBTC UTXO's amount
        builder.connect(liquidator_wbtc_utxo.amount_target, liquidator_wbtc_reward);
        
        // Set the liquidator wBTC UTXO's owner to the liquidator's public key hash
        let liquidator_pk_hash = compute_hash_targets(builder, &[self.liquidator_pk.point.x, self.liquidator_pk.point.y]);
        for i in 0..HASH_SIZE {
            builder.connect(liquidator_wbtc_utxo.owner_pubkey_hash_target[i], liquidator_pk_hash[i]);
        }
        
        // Create liquidator ZERO reward UTXO
        let liquidator_zero_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the liquidator ZERO UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    liquidator_zero_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(liquidator_zero_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the liquidator ZERO UTXO's amount
        builder.connect(liquidator_zero_utxo.amount_target, liquidator_zero_reward);
        
        // Set the liquidator ZERO UTXO's owner to the liquidator's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(liquidator_zero_utxo.owner_pubkey_hash_target[i], liquidator_pk_hash[i]);
        }
        
        // Create protocol wBTC fee UTXO
        let protocol_wbtc_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the protocol wBTC UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    protocol_wbtc_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(protocol_wbtc_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the protocol wBTC UTXO's amount
        builder.connect(protocol_wbtc_utxo.amount_target, protocol_wbtc_fee);
        
        // Set the protocol wBTC UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_wbtc_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }
        
        // Create protocol ZERO fee UTXO
        let protocol_zero_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the protocol ZERO UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    protocol_zero_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(protocol_zero_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the protocol ZERO UTXO's amount
        builder.connect(protocol_zero_utxo.amount_target, protocol_zero_fee);
        
        // Set the protocol ZERO UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_zero_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }
        
        // Return the liquidation information and UTXOs
        Ok((
            self.liquidation_attestation.zusd_amount,
            zusd_burn_utxo,
            liquidator_wbtc_utxo,
            liquidator_zero_utxo,
            protocol_wbtc_utxo,
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
    fn test_liquidation_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_liquidation_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_liquidation_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }

    #[test]
    fn test_liquidation_reward_calculation() {
        // TODO: Implement test for liquidator reward calculation
    }
}
