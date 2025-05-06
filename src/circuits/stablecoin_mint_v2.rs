// Stablecoin Mint V2 Circuit for the 0BTC Wire system
// This circuit supports mixed collateral (70% wBTC, 30% "zero") and protocol fees

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

/// Constant for the ZUSD asset ID
pub const ZUSD_ASSET_ID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02];

/// Constant for the ZERO token asset ID
pub const ZERO_ASSET_ID: [u8; 8] = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03];

/// Protocol fee percentage (0.1%)
pub const PROTOCOL_FEE_PERCENTAGE: u64 = 1000; // 0.1% = 1000 / 1_000_000

/// wBTC collateral percentage (70%)
pub const WBTC_COLLATERAL_PERCENTAGE: u64 = 700_000; // 70% = 700_000 / 1_000_000

/// ZERO collateral percentage (30%)
pub const ZERO_COLLATERAL_PERCENTAGE: u64 = 300_000; // 30% = 300_000 / 1_000_000

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

/// Circuit for minting zUSD stablecoins with mixed collateral (wBTC and ZERO)
#[derive(Clone)]
pub struct StablecoinMintV2Circuit {
    /// The input wBTC UTXO
    pub wbtc_input_utxo: UTXOTarget,
    
    /// The input ZERO UTXO
    pub zero_input_utxo: UTXOTarget,

    /// The dual-price attestation
    pub price_attestation: DualPriceAttestationTarget,

    /// The MPC operators' public key
    pub mpc_pk: PublicKeyTarget,

    /// The user's public key
    pub user_pk: PublicKeyTarget,

    /// The user's signature
    pub user_signature: SignatureTarget,

    /// The amount of zUSD to mint
    pub zusd_amount: Target,

    /// The current timestamp
    pub current_timestamp: Target,

    /// The time window for price attestation validity
    pub time_window: Target,

    /// The overcollateralization ratio (e.g., 150% = 1.5 * FIXED_POINT_SCALING_FACTOR)
    pub overcollateralization_ratio: Target,
    
    /// The protocol fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl StablecoinMintV2Circuit {
    /// Build the stablecoin mint v2 circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, UTXOTarget, UTXOTarget, UTXOTarget, UTXOTarget, UTXOTarget, UTXOTarget)> {
        // Verify that the input UTXOs have the correct asset IDs
        let one = builder.one();
        let zero = builder.zero();

        // Verify wBTC input UTXO
        let is_wbtc = compare_vectors(
            builder,
            &self.wbtc_input_utxo.asset_id_target,
            &[builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[0] as u64))],
        );
        let is_wbtc_target = builder.select(is_wbtc, one, zero);
        builder.connect(is_wbtc_target, one);

        // Verify ZERO input UTXO
        let is_zero = compare_vectors(
            builder,
            &self.zero_input_utxo.asset_id_target,
            &[builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[0] as u64))],
        );
        let is_zero_target = builder.select(is_zero, one, zero);
        builder.connect(is_zero_target, one);

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

        // Calculate the USD value of the proposed zUSD mint amount
        let zusd_usd_value = self.zusd_amount; // 1:1 peg

        // Calculate the required USD value of wBTC collateral (70% of zUSD value / 1.5 CR)
        // wbtc_usd_required = (zusd_usd_value * 0.7) / 1.5
        let million = builder.constant(F::from_canonical_u64(1_000_000));
        let wbtc_percentage = builder.constant(F::from_canonical_u64(WBTC_COLLATERAL_PERCENTAGE));
        
        // Calculate 70% of the zUSD value
        let wbtc_usd_portion_result = fixed_mul(builder, zusd_usd_value, wbtc_percentage);
        let wbtc_usd_portion = match wbtc_usd_portion_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Divide by the overcollateralization ratio
        let wbtc_usd_required_result = fixed_div(builder, wbtc_usd_portion, self.overcollateralization_ratio);
        let wbtc_usd_required = match wbtc_usd_required_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Calculate the required USD value of ZERO collateral (30% of zUSD value / 1.5 CR)
        // zero_usd_required = (zusd_usd_value * 0.3) / 1.5
        let zero_percentage = builder.constant(F::from_canonical_u64(ZERO_COLLATERAL_PERCENTAGE));
        
        // Calculate 30% of the zUSD value
        let zero_usd_portion_result = fixed_mul(builder, zusd_usd_value, zero_percentage);
        let zero_usd_portion = match zero_usd_portion_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Divide by the overcollateralization ratio
        let zero_usd_required_result = fixed_div(builder, zero_usd_portion, self.overcollateralization_ratio);
        let zero_usd_required = match zero_usd_required_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Convert required USD values to required wBTC and ZERO token amounts using the attested prices
        // required_wbtc = wbtc_usd_required / btc_usd_price
        let required_wbtc_result = fixed_div(builder, wbtc_usd_required, self.price_attestation.btc_usd_price);
        let required_wbtc = match required_wbtc_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };
        
        // required_zero = zero_usd_required / zero_usd_price
        let required_zero_result = fixed_div(builder, zero_usd_required, self.price_attestation.zero_usd_price);
        let required_zero = match required_zero_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Calculate protocol fee (0.1% of the zUSD value)
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
        
        // Calculate the wBTC protocol fee (70% of the protocol fee)
        let wbtc_fee_usd_result = fixed_mul(builder, protocol_fee_usd, wbtc_percentage);
        let wbtc_fee_usd = match wbtc_fee_usd_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Convert wBTC fee from USD to wBTC
        let wbtc_fee_result = fixed_div(builder, wbtc_fee_usd, self.price_attestation.btc_usd_price);
        let wbtc_fee = match wbtc_fee_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };
        
        // Calculate the ZERO protocol fee (30% of the protocol fee)
        let zero_fee_usd_result = fixed_mul(builder, protocol_fee_usd, zero_percentage);
        let zero_fee_usd = match zero_fee_usd_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, million)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Convert ZERO fee from USD to ZERO
        let zero_fee_result = fixed_div(builder, zero_fee_usd, self.price_attestation.zero_usd_price);
        let zero_fee = match zero_fee_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // Handle division error
        };

        // Calculate the total required wBTC (required + fee)
        let total_required_wbtc = builder.add(required_wbtc, wbtc_fee);
        
        // Calculate the total required ZERO (required + fee)
        let total_required_zero = builder.add(required_zero, zero_fee);

        // Verify that the input UTXOs have sufficient collateral
        let sufficient_wbtc = arithmetic::gte(builder, self.wbtc_input_utxo.amount_target, total_required_wbtc);
        builder.connect(sufficient_wbtc, one);
        
        let sufficient_zero = arithmetic::gte(builder, self.zero_input_utxo.amount_target, total_required_zero);
        builder.connect(sufficient_zero, one);

        // Add explicit checks for the collateralization ratio
        let min_collateral_ratio = builder.constant(F::from_canonical_u64(
            150 * FIXED_POINT_SCALING_FACTOR / 100,
        ));
        let valid_collateral_ratio = arithmetic::gte(
            builder,
            self.overcollateralization_ratio,
            min_collateral_ratio,
        );
        // Convert Target to BoolTarget
        let valid_collateral_ratio_bool = builder.is_equal(valid_collateral_ratio, one);
        builder.assert_bool(valid_collateral_ratio_bool);

        // Verify the prices are reasonable (not zero or extremely low)
        let min_btc_price = builder.constant(F::from_canonical_u64(1000)); // $1000 minimum BTC price
        let valid_btc_price = arithmetic::gt(builder, self.price_attestation.btc_usd_price, min_btc_price);
        let valid_btc_price_bool = builder.is_equal(valid_btc_price, one);
        builder.assert_bool(valid_btc_price_bool);
        
        let min_zero_price = builder.constant(F::from_canonical_u64(1)); // $0.01 minimum ZERO price
        let valid_zero_price = arithmetic::gt(builder, self.price_attestation.zero_usd_price, min_zero_price);
        let valid_zero_price_bool = builder.is_equal(valid_zero_price, one);
        builder.assert_bool(valid_zero_price_bool);

        // Verify the zUSD amount is positive
        let valid_zusd_amount = arithmetic::gt(builder, self.zusd_amount, zero);
        let valid_zusd_amount_bool = builder.is_equal(valid_zusd_amount, one);
        builder.assert_bool(valid_zusd_amount_bool);

        // Verify the required amounts are positive
        let valid_required_wbtc = arithmetic::gt(builder, required_wbtc, zero);
        let valid_required_wbtc_bool = builder.is_equal(valid_required_wbtc, one);
        builder.assert_bool(valid_required_wbtc_bool);
        
        let valid_required_zero = arithmetic::gt(builder, required_zero, zero);
        let valid_required_zero_bool = builder.is_equal(valid_required_zero, one);
        builder.assert_bool(valid_required_zero_bool);

        // Create a unique issuance ID for this stablecoin mint
        let issuance_data = vec![
            self.user_pk.point.x,
            self.user_pk.point.y,
            self.zusd_amount,
            self.price_attestation.timestamp,
        ];
        let issuance_id = compute_hash_targets(builder, &issuance_data);

        // Create wBTC collateral UTXO
        let wbtc_collateral_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the wBTC collateral UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    wbtc_collateral_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(wbtc_collateral_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the wBTC collateral UTXO's amount
        builder.connect(wbtc_collateral_utxo.amount_target, required_wbtc);
        
        // Set the wBTC collateral UTXO's owner to the MPC's public key hash
        let mpc_pk_hash = compute_hash_targets(builder, &[self.mpc_pk.point.x, self.mpc_pk.point.y]);
        for i in 0..HASH_SIZE {
            builder.connect(wbtc_collateral_utxo.owner_pubkey_hash_target[i], mpc_pk_hash[i]);
        }
        
        // Create ZERO collateral UTXO
        let zero_collateral_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the ZERO collateral UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    zero_collateral_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zero_collateral_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the ZERO collateral UTXO's amount
        builder.connect(zero_collateral_utxo.amount_target, required_zero);
        
        // Set the ZERO collateral UTXO's owner to the MPC's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(zero_collateral_utxo.owner_pubkey_hash_target[i], mpc_pk_hash[i]);
        }

        // Create wBTC fee UTXO
        let wbtc_fee_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the wBTC fee UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    wbtc_fee_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(wbtc_fee_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the wBTC fee UTXO's amount
        builder.connect(wbtc_fee_utxo.amount_target, wbtc_fee);
        
        // Set the wBTC fee UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                wbtc_fee_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }
        
        // Create ZERO fee UTXO
        let zero_fee_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the ZERO fee UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    zero_fee_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zero_fee_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the ZERO fee UTXO's amount
        builder.connect(zero_fee_utxo.amount_target, zero_fee);
        
        // Set the ZERO fee UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                zero_fee_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }

        // Create zUSD output UTXO
        let zusd_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the zUSD UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZUSD_ASSET_ID.len() {
                builder.connect(
                    zusd_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZUSD_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zusd_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the zUSD UTXO's amount
        builder.connect(zusd_utxo.amount_target, self.zusd_amount);
        
        // Set the zUSD UTXO's owner to the user's public key hash
        let user_pk_hash = compute_hash_targets(builder, &[self.user_pk.point.x, self.user_pk.point.y]);
        for i in 0..HASH_SIZE {
            builder.connect(zusd_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }

        // Calculate wBTC change amount
        let wbtc_change_amount = builder.sub(self.wbtc_input_utxo.amount_target, total_required_wbtc);
        
        // Create wBTC change UTXO
        let wbtc_change_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the wBTC change UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < WBTC_ASSET_ID.len() {
                builder.connect(
                    wbtc_change_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(WBTC_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(wbtc_change_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the wBTC change UTXO's amount
        builder.connect(wbtc_change_utxo.amount_target, wbtc_change_amount);
        
        // Set the wBTC change UTXO's owner to the user's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(wbtc_change_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }
        
        // Calculate ZERO change amount
        let zero_change_amount = builder.sub(self.zero_input_utxo.amount_target, total_required_zero);
        
        // Create ZERO change UTXO
        let zero_change_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the ZERO change UTXO's asset ID
        for i in 0..HASH_SIZE {
            if i < ZERO_ASSET_ID.len() {
                builder.connect(
                    zero_change_utxo.asset_id_target[i],
                    builder.constant(F::from_canonical_u64(ZERO_ASSET_ID[i] as u64)),
                );
            } else {
                builder.connect(zero_change_utxo.asset_id_target[i], zero);
            }
        }
        
        // Set the ZERO change UTXO's amount
        builder.connect(zero_change_utxo.amount_target, zero_change_amount);
        
        // Set the ZERO change UTXO's owner to the user's public key hash
        for i in 0..HASH_SIZE {
            builder.connect(zero_change_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }

        // Return the zUSD amount, zUSD UTXO, wBTC collateral UTXO, ZERO collateral UTXO, wBTC fee UTXO, ZERO fee UTXO, wBTC change UTXO, and ZERO change UTXO
        Ok((
            self.zusd_amount,
            zusd_utxo,
            wbtc_collateral_utxo,
            zero_collateral_utxo,
            wbtc_fee_utxo,
            zero_fee_utxo,
            wbtc_change_utxo,
            zero_change_utxo,
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
    fn test_stablecoin_mint_v2_circuit_creation() {
        // TODO: Implement test for circuit creation
    }

    #[test]
    fn test_stablecoin_mint_v2_proof_generation_and_verification() {
        // TODO: Implement test for proof generation and verification
    }

    #[test]
    fn test_stablecoin_mint_v2_circuit_constraints() {
        // TODO: Implement test for circuit constraints
    }

    #[test]
    fn test_stablecoin_mint_v2_collateralization_ratio() {
        // TODO: Implement test for collateralization ratio
    }

    #[test]
    fn test_stablecoin_mint_v2_protocol_fees() {
        // TODO: Implement test for protocol fees
    }
}
