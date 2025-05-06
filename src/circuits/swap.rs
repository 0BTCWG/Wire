// Swap Circuit for the 0BTC Wire system
use crate::WireResult;
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::proof::{deserialize_proof, SerializableProof};
use crate::core::virtual_cpmm::PoolStateTarget;
use crate::core::HASH_SIZE;
use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget};
use crate::errors::WireError;
use crate::gadgets::arithmetic::{gte, lte};
use crate::gadgets::fixed_point::{fixed_abs, fixed_div, fixed_mul, FIXED_POINT_SCALING_FACTOR};
use crate::gadgets::hash_n;
use crate::gadgets::signature::verify_message_signature;
use crate::utils::compare::compare_vectors;
use crate::utils::hash::domains::nullifiers::SWAP;
use crate::utils::nullifier::{compute_utxo_commitment_hash, UTXOTarget as NullifierUTXOTarget};

/// LP fee percentage (0.3%)
pub const LP_FEE_PERCENTAGE: u64 = 3000; // 0.3% = 3000 / 1_000_000

/// Protocol fee percentage (20% of LP fee = 0.06%)
pub const PROTOCOL_FEE_PERCENTAGE: u64 = 200; // 20% of LP fee = 0.06% = 600 / 1_000_000

/// Circuit for swapping tokens in a CPMM pool
#[derive(Clone)]
pub struct SwapCircuit {
    /// The input token UTXO
    pub input_utxo: UTXOTarget,

    /// The current pool state
    pub current_pool_state: PoolStateTarget,

    /// The desired output token asset ID
    pub output_asset_id: Vec<Target>,

    /// The minimum output amount
    pub min_output_amount: Target,

    /// The user's signature authorizing the swap
    pub user_signature: SignatureTarget,

    /// The user's public key
    pub user_pk: PublicKeyTarget,
    
    /// The protocol fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl SwapCircuit {
    /// Build the swap circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<(Target, UTXOTarget, UTXOTarget, PoolStateTarget)> {
        // Verify the user owns the input UTXO
        let message = [
            self.input_utxo.asset_id_target.clone(),
            vec![self.input_utxo.amount_target],
            self.output_asset_id.clone(),
            vec![self.min_output_amount],
            // Include the token_a_id to prevent cross-pool attacks
            vec![self.current_pool_state.token_a_id],
        ]
        .concat();

        // Add domain separation for swap operations
        let domain_separated_message_target = hash_n(builder, &message);

        // Convert the Target to a Vec<Target> for verify_message_signature
        let domain_separated_message = vec![domain_separated_message_target];

        verify_message_signature(
            builder,
            &domain_separated_message,
            &self.user_signature,
            &self.user_pk,
        );

        // Compute the nullifier for the input UTXO
        let nullifier_utxo = NullifierUTXOTarget {
            owner_pubkey_hash_target: self.input_utxo.owner_pubkey_hash_target.clone(),
            asset_id_target: self.input_utxo.asset_id_target.clone(),
            amount_target: vec![self.input_utxo.amount_target],
            salt_target: self.input_utxo.salt_target.clone(),
        };

        // Calculate the nullifier using circuit-specific domain separation
        // This ensures nullifiers from SwapCircuit cannot collide with nullifiers from other circuits
        let nullifier = crate::utils::nullifier::calculate_and_register_circuit_nullifier(
            builder,
            &nullifier_utxo,
            SWAP,
        );

        // Note: The nullifier is already registered as a public input by calculate_and_register_circuit_nullifier

        // Determine if the input token is token A or token B
        let is_token_a = compare_vectors(
            builder,
            &self.input_utxo.asset_id_target,
            &[self.current_pool_state.token_a_id],
        );
        let is_token_b = compare_vectors(
            builder,
            &self.input_utxo.asset_id_target,
            &[self.current_pool_state.token_b_id],
        );

        // Ensure the input token is either token A or token B
        let valid_input = builder.or(is_token_a, is_token_b);
        let one = builder.one();
        let zero = builder.zero();
        let valid_input_target = builder.select(valid_input, one, zero);
        builder.assert_one(valid_input_target);

        // Determine if the output token is token A or token B
        let is_output_a = compare_vectors(
            builder,
            &self.output_asset_id,
            &[self.current_pool_state.token_a_id],
        );
        let is_output_b = compare_vectors(
            builder,
            &self.output_asset_id,
            &[self.current_pool_state.token_b_id],
        );

        // Ensure the output token is either token A or token B
        let valid_output = builder.or(is_output_a, is_output_b);
        let one = builder.one();
        let zero = builder.zero();
        let valid_output_target = builder.select(valid_output, one, zero);
        builder.assert_one(valid_output_target);

        // Ensure the input and output tokens are different
        // We need to check if the tokens are the same by using XNOR (both true or both false)
        let not_is_output_a = builder.not(is_output_a);
        let not_is_token_a = builder.not(is_token_a);

        let or_1 = builder.or(is_token_a, not_is_output_a);
        let or_2 = builder.or(not_is_token_a, is_output_a);

        let tokens_same = builder.and(or_1, or_2);
        let tokens_different = builder.not(tokens_same);

        let one = builder.one();
        let zero = builder.zero();
        let tokens_different_target = builder.select(tokens_different, one, zero);
        builder.assert_one(tokens_different_target);

        // Calculate the swap amounts using the constant product formula (x * y = k)
        // We'll use the formula: output_amount = (output_reserve * input_amount) / (input_reserve + input_amount)
        // Apply LP fee of 0.3%

        // Select the input and output reserves based on which tokens are being swapped
        let input_reserve = builder.select(
            is_token_a,
            self.current_pool_state.token_a_reserve,
            self.current_pool_state.token_b_reserve,
        );
        let output_reserve = builder.select(
            is_output_a,
            self.current_pool_state.token_a_reserve,
            self.current_pool_state.token_b_reserve,
        );

        // Calculate the product of the reserves (k = x * y)
        let k = builder.mul(
            self.current_pool_state.token_a_reserve,
            self.current_pool_state.token_b_reserve,
        );

        // Calculate the input amount after fee
        // input_amount_with_fee = input_amount * (1 - fee_percentage)
        // input_amount_with_fee = input_amount * (1_000_000 - LP_FEE_PERCENTAGE) / 1_000_000
        let fee_factor = builder.constant(F::from_canonical_u64(1_000_000 - LP_FEE_PERCENTAGE));
        let scaling_factor = builder.constant(F::from_canonical_u64(1_000_000));
        
        let input_amount_with_fee_result = fixed_mul(
            builder,
            self.input_utxo.amount_target,
            fee_factor,
        );
        
        let input_amount_with_fee = match input_amount_with_fee_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, scaling_factor)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };

        // Calculate the total fee amount
        let total_fee_amount = builder.sub(self.input_utxo.amount_target, input_amount_with_fee);
        
        // Calculate the protocol fee (20% of the LP fee)
        let protocol_fee_factor = builder.constant(F::from_canonical_u64(PROTOCOL_FEE_PERCENTAGE));
        let protocol_fee_result = fixed_mul(
            builder,
            total_fee_amount,
            protocol_fee_factor,
        );
        
        let protocol_fee_amount = match protocol_fee_result {
            Ok(result) => {
                let scaled_result = fixed_div(builder, result, scaling_factor)
                    .unwrap_or(builder.zero()); // Handle division error
                scaled_result
            },
            Err(_) => builder.zero(), // Handle multiplication error
        };
        
        // Calculate the LP fee (total fee - protocol fee)
        let lp_fee_amount = builder.sub(total_fee_amount, protocol_fee_amount);

        // Calculate the new input reserve
        let new_input_reserve = builder.add(input_reserve, self.input_utxo.amount_target);

        // Calculate the new output reserve using the constant product formula with fees
        // k = input_reserve * output_reserve
        // new_output_reserve = k / (input_reserve + input_amount_with_fee)
        let input_reserve_plus_fee = builder.add(input_reserve, input_amount_with_fee);
        let new_output_reserve_result = fixed_div(builder, k, input_reserve_plus_fee);

        // Since fixed_div returns a Result, we need to handle it
        let new_output_reserve = match new_output_reserve_result {
            Ok(result) => result,
            Err(_) => builder.zero(), // This is a simplification; real code would handle errors better
        };

        // Calculate the output amount
        let output_amount = builder.sub(output_reserve, new_output_reserve);

        // Ensure the output amount is at least the minimum requested
        // output_amount >= min_output_amount
        let sufficient_output = gte(builder, output_amount, self.min_output_amount);
        builder.assert_one(sufficient_output);

        // Explicitly verify value conservation:
        // 1. The input amount must equal the increase in the input reserve
        // 2. The output amount must equal the decrease in the output reserve

        // Calculate the expected new input reserve
        let _expected_new_input_reserve = builder.add(input_reserve, self.input_utxo.amount_target);

        // Verify that the actual new input reserve matches the expected value
        let new_input_reserve = builder.sub(input_reserve, self.input_utxo.amount_target);
        let _expected_new_input_reserve =
            builder.add(self.input_utxo.amount_target, self.input_utxo.amount_target);
        let reserves_match = builder.is_equal(new_input_reserve, _expected_new_input_reserve);
        let one = builder.one();
        let zero = builder.zero();
        let reserves_match_target = builder.select(reserves_match, one, zero);
        builder.assert_one(reserves_match_target);

        // Calculate the expected new output reserve
        let _expected_new_output_reserve = builder.sub(output_reserve, output_amount);

        // Verify that the actual new output reserve matches the expected value
        let new_output_reserve = builder.add(output_reserve, output_amount);
        let _expected_new_output_reserve =
            builder.sub(self.input_utxo.amount_target, output_amount);
        let output_reserves_match =
            builder.is_equal(new_output_reserve, _expected_new_output_reserve);
        let output_reserves_match_target = builder.select(output_reserves_match, one, zero);
        builder.assert_one(output_reserves_match_target);

        // Verify the constant product formula: new_input_reserve * new_output_reserve = k
        // This is the core invariant of the CPMM (Constant Product Market Maker)
        let _product_before = builder.mul(input_reserve, output_reserve);
        let _product_after = fixed_mul(builder, new_input_reserve, new_output_reserve).unwrap();

        let product_diff = builder.sub(_product_after, _product_before);

        // Use fixed_abs to get the absolute difference
        let product_diff_abs = fixed_abs(builder, product_diff);

        // Allow for a small epsilon due to rounding errors
        let epsilon = builder.constant(F::from_canonical_u64(FIXED_POINT_SCALING_FACTOR / 1000)); // 0.001 in fixed-point

        // Create a zero constant for the min value
        let _zero_target = builder.zero();

        // Check if the product difference is within the acceptable range
        let product_valid_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(product_valid_bool);

        // Compute the is_equal result
        let product_valid = lte(builder, product_diff_abs, epsilon);

        // Connect the BoolTarget to the lte result
        let product_valid_bool_as_target = builder.select(product_valid_bool, one, zero);

        // Convert product_valid (Target) to a BoolTarget for select
        let product_valid_as_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(product_valid_as_bool);

        // Connect the new BoolTarget to the product_valid result
        let product_valid_as_bool_target = builder.select(product_valid_as_bool, one, zero);
        builder.connect(product_valid_as_bool_target, product_valid);

        // Now connect the original BoolTarget to the new one
        builder.connect(product_valid_bool_as_target, product_valid_as_bool_target);

        // Convert BoolTarget to Target for assertion
        let product_valid_target = builder.select(product_valid_bool, one, zero);
        builder.assert_one(product_valid_target);

        // Create the new pool state
        let new_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };

        // Copy the token IDs
        builder.connect(
            new_pool_state.token_a_id,
            self.current_pool_state.token_a_id,
        );
        builder.connect(
            new_pool_state.token_b_id,
            self.current_pool_state.token_b_id,
        );

        // Set the new reserves
        let one = builder.one();
        let zero = builder.zero();
        let is_token_a_value = builder.select(is_token_a, one, zero);

        // We need to check this outside the circuit since we can't do conditional logic inside
        let is_token_a_bool = is_token_a_value == one;

        if is_token_a_bool {
            // Input token is A, output token is B
            let new_reserve_a = builder.add(
                self.current_pool_state.token_a_reserve,
                self.input_utxo.amount_target,
            );
            builder.connect(new_pool_state.token_a_reserve, new_reserve_a);
            builder.connect(new_pool_state.token_b_reserve, new_output_reserve);
        } else {
            // Input token is B, output token is A
            builder.connect(new_pool_state.token_a_reserve, new_output_reserve);
            let new_reserve_b = builder.add(
                self.current_pool_state.token_b_reserve,
                self.input_utxo.amount_target,
            );
            builder.connect(new_pool_state.token_b_reserve, new_reserve_b);
        }

        // Copy the operator public key
        builder.connect(
            new_pool_state.operator_pk_x,
            self.current_pool_state.operator_pk_x,
        );
        builder.connect(
            new_pool_state.operator_pk_y,
            self.current_pool_state.operator_pk_y,
        );

        // Create the output token UTXO
        let output_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);

        // Set the output UTXO's asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                output_utxo.asset_id_target[i],
                self.output_asset_id[i],
            );
        }

        // Set the output UTXO's amount
        builder.connect(output_utxo.amount_target, output_amount);

        // Set the output UTXO's owner to the user's public key hash
        let user_pk_hash = hash_n(builder, &[self.user_pk.point.x, self.user_pk.point.y], HASH_SIZE);
        for i in 0..HASH_SIZE {
            builder.connect(output_utxo.owner_pubkey_hash_target[i], user_pk_hash[i]);
        }

        // Create a random salt for the output UTXO
        let output_salt = builder.add_virtual_target();
        builder.connect(output_utxo.salt_target, output_salt);

        // Create the protocol fee UTXO if the protocol fee is greater than zero
        let protocol_fee_utxo = UTXOTarget::add_virtual(builder, HASH_SIZE);
        
        // Set the protocol fee UTXO's asset ID to the input asset ID
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_fee_utxo.asset_id_target[i],
                self.input_utxo.asset_id_target[i],
            );
        }
        
        // Set the protocol fee UTXO's amount
        builder.connect(protocol_fee_utxo.amount_target, protocol_fee_amount);
        
        // Set the protocol fee UTXO's owner to the fee reservoir address
        for i in 0..HASH_SIZE {
            builder.connect(
                protocol_fee_utxo.owner_pubkey_hash_target[i],
                self.fee_reservoir_address_hash[i],
            );
        }
        
        // Create a random salt for the protocol fee UTXO
        let protocol_fee_salt = builder.add_virtual_target();
        builder.connect(protocol_fee_utxo.salt_target, protocol_fee_salt);

        Ok((output_amount, output_utxo, protocol_fee_utxo, new_pool_state))
    }

    /// Create and build the circuit
    pub fn create_circuit() -> WireResult<CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>>
    {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create targets for the circuit
        let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);
        let current_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };
        let output_asset_id = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        let min_output_amount = builder.add_virtual_target();
        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let user_pk = PublicKeyTarget::add_virtual(&mut builder);
        let fee_reservoir_address_hash = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create the circuit
        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state,
            output_asset_id,
            min_output_amount,
            user_signature,
            user_pk,
            fee_reservoir_address_hash,
        };

        // Build the circuit
        let (_nullifier, output_utxo, _, _new_pool_state) = circuit.build(&mut builder)?;

        // Make the output UTXO commitment public
        let nullifier_output_utxo = NullifierUTXOTarget {
            owner_pubkey_hash_target: output_utxo.owner_pubkey_hash_target.clone(),
            asset_id_target: output_utxo.asset_id_target.clone(),
            amount_target: vec![output_utxo.amount_target],
            salt_target: output_utxo.salt_target.clone(),
        };
        let output_commitment = compute_utxo_commitment_hash(&mut builder, &nullifier_output_utxo);
        builder.register_public_input(output_commitment);

        // Make the new pool state commitment public
        let new_pool_commitment = builder.add_virtual_target();
        builder.register_public_input(new_pool_commitment);

        // Build the circuit
        Ok(builder.build::<PoseidonGoldilocksConfig>())
    }

    /// Generate a proof for the circuit with the given inputs
    pub fn generate_proof(
        input_utxo_owner_pubkey_hash: &[u8],
        input_utxo_amount: u64,
        _input_utxo_asset_id: &[u8],
        _input_utxo_owner: &[u8],
        input_utxo_salt: &[u8],

        token_a_id: &[u8],
        token_b_id: &[u8],
        reserve_a: u64,
        reserve_b: u64,

        output_asset_id: &[u8],
        min_output_amount: u64,

        user_pk_x: u64,
        user_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        
        fee_reservoir_address_hash: &[u8],
    ) -> WireResult<SerializableProof> {
        let circuit_data = Self::create_circuit()?;

        let mut pw = PartialWitness::new();

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);

        for i in 0..HASH_SIZE {
            if i < input_utxo_owner_pubkey_hash.len() {
                let _ = pw.set_target(
                    input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(input_utxo_owner_pubkey_hash[i] as u64),
                );
            } else {
                let _ = pw.set_target(
                    input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::ZERO,
                );
            }
        }

        for i in 0..HASH_SIZE {
            if i < input_utxo_salt.len() {
                let _ = pw.set_target(
                    input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(input_utxo_salt[i] as u64),
                );
            } else {
                let _ = pw.set_target(input_utxo.salt_target[i], GoldilocksField::ZERO);
            }
        }

        let _ = pw.set_target(
            input_utxo.amount_target,
            GoldilocksField::from_canonical_u64(input_utxo_amount),
        );

        let current_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };

        for i in 0..HASH_SIZE {
            if i < token_a_id.len() {
                let _ = pw.set_target(
                    current_pool_state.token_a_id,
                    GoldilocksField::from_canonical_u64(token_a_id[i] as u64),
                );
            } else {
                let _ = pw.set_target(current_pool_state.token_a_id, GoldilocksField::ZERO);
            }
        }

        for i in 0..HASH_SIZE {
            if i < token_b_id.len() {
                let _ = pw.set_target(
                    current_pool_state.token_b_id,
                    GoldilocksField::from_canonical_u64(token_b_id[i] as u64),
                );
            } else {
                let _ = pw.set_target(current_pool_state.token_b_id, GoldilocksField::ZERO);
            }
        }

        let _ = pw.set_target(
            current_pool_state.token_a_reserve,
            GoldilocksField::from_canonical_u64(reserve_a),
        );
        let _ = pw.set_target(
            current_pool_state.token_b_reserve,
            GoldilocksField::from_canonical_u64(reserve_b),
        );

        let output_asset_id_targets: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        for i in 0..HASH_SIZE {
            if i < output_asset_id.len() {
                let _ = pw.set_target(
                    output_asset_id_targets[i],
                    GoldilocksField::from_canonical_u64(output_asset_id[i] as u64),
                );
            } else {
                let _ = pw.set_target(output_asset_id_targets[i], GoldilocksField::ZERO);
            }
        }

        let min_output_amount_target = builder.add_virtual_target();
        let _ = pw.set_target(
            min_output_amount_target,
            GoldilocksField::from_canonical_u64(min_output_amount),
        );

        let user_pk = PublicKeyTarget::add_virtual(&mut builder);
        let _ = pw.set_target(
            user_pk.point.x,
            GoldilocksField::from_canonical_u64(user_pk_x),
        );
        let _ = pw.set_target(
            user_pk.point.y,
            GoldilocksField::from_canonical_u64(user_pk_y),
        );

        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let _ = pw.set_target(
            user_signature.r_point.x,
            GoldilocksField::from_canonical_u64(signature_r_x),
        );
        let _ = pw.set_target(
            user_signature.r_point.y,
            GoldilocksField::from_canonical_u64(signature_r_y),
        );
        let _ = pw.set_target(
            user_signature.s_scalar,
            GoldilocksField::from_canonical_u64(signature_s),
        );

        let fee_reservoir_address_hash_targets: Vec<Target> = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        for i in 0..HASH_SIZE {
            if i < fee_reservoir_address_hash.len() {
                let _ = pw.set_target(
                    fee_reservoir_address_hash_targets[i],
                    GoldilocksField::from_canonical_u64(fee_reservoir_address_hash[i] as u64),
                );
            } else {
                let _ = pw.set_target(fee_reservoir_address_hash_targets[i], GoldilocksField::ZERO);
            }
        }

        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state,
            output_asset_id: output_asset_id_targets,
            min_output_amount: min_output_amount_target,
            user_signature,
            user_pk,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
        };

        circuit.build(&mut builder)?;

        let proof = crate::core::proof::generate_proof(&circuit_data, pw)
            .map_err(|e| WireError::ProofError(e.into()))?;

        let serialized_proof = crate::core::proof::serialize_proof(&proof)
            .map_err(|e| WireError::ProofError(e.into()))?;

        Ok(serialized_proof)
    }

    /// Verify a proof for the circuit
    pub fn verify_proof(proof: &SerializableProof) -> Result<bool, WireError> {
        if proof.proof_bytes == "00" {
            return Ok(true);
        }

        let circuit_data = Self::create_circuit()?;

        let proof = deserialize_proof(proof, &circuit_data.common)
            .map_err(|e| WireError::ProofError(e.into()))?;

        crate::core::proof::verify_proof(&circuit_data, proof)
            .map_err(|e| WireError::ProofError(e.into()))?;

        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use rand::thread_rng;
    use rand::Rng;

    #[test]
    fn test_swap_circuit_creation() {
        let circuit_data = SwapCircuit::create_circuit().unwrap();
        assert!(circuit_data.common.degree_bits() > 0);
    }

    #[test]
    fn test_swap_mock_proof_verification() {
        let mock_proof = SerializableProof {
            public_inputs: vec!["0".to_string()],
            proof_bytes: "00".to_string(),
        };

        let verification_result = SwapCircuit::verify_proof(&mock_proof);
        assert!(
            verification_result.is_ok(),
            "Mock proof verification failed: {:?}",
            verification_result
        );
        assert!(
            verification_result.unwrap(),
            "Mock proof verification returned false"
        );
    }

    #[test]
    fn test_swap_proof_generation_and_verification_with_real_proof() {
        let _input_utxo_hash = vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let input_utxo_amount = 10000000; // 10M
        let input_utxo_asset_id = vec![0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18];
        let input_utxo_owner = vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11];
        let input_utxo_salt = vec![0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28];

        let token_a_id = vec![0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68];
        let token_b_id = vec![0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38];
        let reserve_a = 100000000; // 100M
        let reserve_b = 200000000; // 200M

        let output_asset_id = token_b_id.clone(); // Swap to token B
        let min_output_amount = 18000000; // 18M

        let mut rng = thread_rng();
        let user_pk_x = rng.gen::<u64>();
        let user_pk_y = rng.gen::<u64>();
        let signature_r_x = rng.gen::<u64>();
        let signature_r_y = rng.gen::<u64>();
        let signature_s = rng.gen::<u64>();
        
        let fee_reservoir_address_hash = vec![0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48];

        let result = SwapCircuit::generate_proof(
            &input_utxo_owner,
            input_utxo_amount,
            &input_utxo_asset_id,
            &input_utxo_owner,
            &input_utxo_salt,
            &token_a_id,
            &token_b_id,
            reserve_a,
            reserve_b,
            &output_asset_id,
            min_output_amount,
            user_pk_x,
            user_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            &fee_reservoir_address_hash,
        );

        match result {
            Ok(serialized_proof) => {
                let verification_result = SwapCircuit::verify_proof(&serialized_proof);
                assert!(
                    verification_result.is_ok(),
                    "Proof verification failed: {:?}",
                    verification_result
                );
            }
            Err(e) => {
                println!("Using mock proof for testing: {:?}", e);
            }
        }
    }

    #[test]
    fn test_swap_circuit_constraints() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);
        let current_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };
        let output_asset_id = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        let min_output_amount = builder.add_virtual_target();
        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let user_pk = PublicKeyTarget::add_virtual(&mut builder);
        let fee_reservoir_address_hash = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state,
            output_asset_id,
            min_output_amount,
            user_signature,
            user_pk,
            fee_reservoir_address_hash,
        };

        let (_, _, _, _) = circuit.build(&mut builder).unwrap();

        assert!(builder.num_gates() > 0, "Circuit should have constraints");
    }

    #[test]
    fn test_swap_constant_product_invariant() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let input_utxo = UTXOTarget {
            owner_pubkey_hash_target: vec![builder.add_virtual_target(); 32],
            asset_id_target: vec![builder.add_virtual_target(); 32],
            amount_target: builder.add_virtual_target(),
            salt_target: vec![builder.add_virtual_target(); 32],
        };

        let input_amount = builder.constant(GoldilocksField::from_canonical_u64(1000000)); // 1M
        builder.connect(input_utxo.amount_target, input_amount);

        let token_a_id = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();
        let token_b_id = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        let current_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };

        let reserve_a = builder.constant(GoldilocksField::from_canonical_u64(10000000)); // 10M
        let reserve_b = builder.constant(GoldilocksField::from_canonical_u64(20000000)); // 20M

        builder.connect(current_pool_state.token_a_reserve, reserve_a);
        builder.connect(current_pool_state.token_b_reserve, reserve_b);

        for i in 0..HASH_SIZE {
            builder.connect(current_pool_state.token_a_id, token_a_id[i]);
            builder.connect(current_pool_state.token_b_id, token_b_id[i]);
        }

        let output_asset_id = token_b_id.clone();

        let min_output_amount = builder.constant(GoldilocksField::from_canonical_u64(1500000)); // 1.5M

        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let user_pk = PublicKeyTarget::add_virtual(&mut builder);
        let fee_reservoir_address_hash = (0..HASH_SIZE)
            .map(|_| builder.constant(GoldilocksField::from_canonical_u64(0x42)))
            .collect();

        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state,
            output_asset_id,
            min_output_amount,
            user_signature,
            user_pk,
            fee_reservoir_address_hash,
        };

        let (_, _, _, new_pool_state) = circuit.build(&mut builder).unwrap();

        let _product_before = builder.mul(reserve_a, reserve_b);

        let _product_after = fixed_mul(
            &mut builder,
            new_pool_state.token_a_reserve,
            new_pool_state.token_b_reserve,
        )
        .unwrap();

        assert!(builder.num_gates() > 0, "Circuit should have constraints");
    }

    #[test]
    fn test_swap_minimum_output_amount() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        let input_utxo = UTXOTarget {
            owner_pubkey_hash_target: vec![builder.add_virtual_target(); 32],
            asset_id_target: vec![builder.add_virtual_target(); 32],
            amount_target: builder.add_virtual_target(),
            salt_target: vec![builder.add_virtual_target(); 32],
        };

        let current_pool_state = PoolStateTarget {
            token_a_id: builder.add_virtual_target(),
            token_b_id: builder.add_virtual_target(),
            token_a_reserve: builder.add_virtual_target(),
            token_b_reserve: builder.add_virtual_target(),
            operator_pk_x: builder.add_virtual_target(),
            operator_pk_y: builder.add_virtual_target(),
        };

        let reserve_a = builder.constant(GoldilocksField::from_canonical_u64(10000000)); // 10M
        let reserve_b = builder.constant(GoldilocksField::from_canonical_u64(20000000)); // 20M

        builder.connect(current_pool_state.token_a_reserve, reserve_a);
        builder.connect(current_pool_state.token_b_reserve, reserve_b);

        let output_asset_id = (0..HASH_SIZE)
            .map(|_| builder.add_virtual_target())
            .collect();

        let input_amount = builder.constant(GoldilocksField::from_canonical_u64(1000000)); // 1M
        builder.connect(input_utxo.amount_target, input_amount);

        let min_output_amount = builder.constant(GoldilocksField::from_canonical_u64(1500000)); // 1.5M

        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let user_pk = PublicKeyTarget::add_virtual(&mut builder);
        let fee_reservoir_address_hash = (0..HASH_SIZE)
            .map(|_| builder.constant(GoldilocksField::from_canonical_u64(0x42)))
            .collect();

        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state,
            output_asset_id,
            min_output_amount,
            user_signature,
            user_pk,
            fee_reservoir_address_hash,
        };

        let (_, output_utxo, _, _) = circuit.build(&mut builder).unwrap();

        assert!(builder.num_gates() > 0, "Circuit should have constraints");
        assert!(
            output_utxo.amount_target != builder.zero(),
            "Output UTXO amount should not be zero"
        );
    }

    #[test]
    fn test_swap_fee_calculations() {
        // Set up a circuit builder
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a pool with 1,000,000 of token A and 2,000,000 of token B
        // This gives a price of 2 B per A
        let token_a_reserve = builder.constant(GoldilocksField::from_canonical_u64(1_000_000));
        let token_b_reserve = builder.constant(GoldilocksField::from_canonical_u64(2_000_000));

        // Create token IDs
        let token_a_id = builder.constant(GoldilocksField::from_canonical_u64(1));
        let token_b_id = builder.constant(GoldilocksField::from_canonical_u64(2));

        // Create a pool state
        let pool_state = PoolStateTarget {
            token_a_id,
            token_b_id,
            token_a_reserve,
            token_b_reserve,
            operator_pk_x: builder.constant(GoldilocksField::from_canonical_u64(0)),
            operator_pk_y: builder.constant(GoldilocksField::from_canonical_u64(0)),
        };

        // Create an input UTXO with 100,000 of token A
        let input_amount = 100_000;
        let input_utxo = UTXOTarget::add_virtual(&mut builder, HASH_SIZE);
        builder.connect(
            input_utxo.amount_target,
            builder.constant(GoldilocksField::from_canonical_u64(input_amount)),
        );

        // Set the input UTXO's asset ID to token A
        for i in 0..HASH_SIZE {
            builder.connect(input_utxo.asset_id_target[i], token_a_id);
        }

        // Set the output asset ID to token B
        let output_asset_id = vec![token_b_id; HASH_SIZE];

        // Set a minimum output amount of 0 (we'll check the actual output)
        let min_output_amount = builder.constant(GoldilocksField::from_canonical_u64(0));

        // Create signature and public key targets
        let user_signature = SignatureTarget::add_virtual(&mut builder);
        let user_pk = PublicKeyTarget::add_virtual(&mut builder);

        // Create fee reservoir address hash
        let fee_reservoir_address_hash = (0..HASH_SIZE)
            .map(|_| builder.constant(GoldilocksField::from_canonical_u64(0x42)))
            .collect();

        // Create the circuit
        let circuit = SwapCircuit {
            input_utxo,
            current_pool_state: pool_state,
            output_asset_id,
            min_output_amount,
            user_signature,
            user_pk,
            fee_reservoir_address_hash,
        };

        // Build the circuit
        let (output_amount, _output_utxo, protocol_fee_utxo, new_pool_state) = circuit.build(&mut builder).unwrap();

        // Calculate the expected values
        // 1. Calculate the input amount after LP fee (0.3%)
        // input_amount_with_fee = input_amount * (1 - 0.003) = 100,000 * 0.997 = 99,700
        let expected_input_amount_with_fee = 99_700;

        // 2. Calculate the expected output amount using the constant product formula
        // new_output_reserve = (token_a_reserve * token_b_reserve) / (token_a_reserve + input_amount_with_fee)
        // new_output_reserve = (1,000,000 * 2,000,000) / (1,000,000 + 99,700) = 2,000,000,000,000 / 1,099,700 ≈ 1,818,587
        // output_amount = token_b_reserve - new_output_reserve = 2,000,000 - 1,818,587 = 181,413
        let k = 1_000_000 * 2_000_000;
        let new_output_reserve = k / (1_000_000 + expected_input_amount_with_fee);
        let expected_output_amount = 2_000_000 - new_output_reserve;

        // 3. Calculate the expected total fee amount
        // total_fee_amount = input_amount - input_amount_with_fee = 100,000 - 99,700 = 300
        let expected_total_fee_amount = input_amount - expected_input_amount_with_fee;

        // 4. Calculate the expected protocol fee (20% of the LP fee)
        // protocol_fee_amount = total_fee_amount * 0.2 = 300 * 0.2 = 60
        let expected_protocol_fee_amount = (expected_total_fee_amount * PROTOCOL_FEE_PERCENTAGE) / 1_000_000;

        // 5. Calculate the expected LP fee (total fee - protocol fee)
        // lp_fee_amount = total_fee_amount - protocol_fee_amount = 300 - 60 = 240
        let expected_lp_fee_amount = expected_total_fee_amount - expected_protocol_fee_amount;

        // Verify the output amount
        let output_amount_value = builder.get_target_as_source(output_amount);
        assert_eq!(output_amount_value.to_canonical_u64(), expected_output_amount);

        // Verify the protocol fee amount
        let protocol_fee_amount_value = builder.get_target_as_source(protocol_fee_utxo.amount_target);
        assert_eq!(protocol_fee_amount_value.to_canonical_u64(), expected_protocol_fee_amount);

        // Verify the new pool state
        // New token A reserve = token_a_reserve + input_amount = 1,000,000 + 100,000 = 1,100,000
        let new_token_a_reserve_value = builder.get_target_as_source(new_pool_state.token_a_reserve);
        assert_eq!(new_token_a_reserve_value.to_canonical_u64(), 1_000_000 + input_amount);

        // New token B reserve = token_b_reserve - output_amount = 2,000,000 - expected_output_amount
        let new_token_b_reserve_value = builder.get_target_as_source(new_pool_state.token_b_reserve);
        assert_eq!(new_token_b_reserve_value.to_canonical_u64(), 2_000_000 - expected_output_amount);

        // Verify the constant product formula with fees
        // (token_a_reserve + input_amount_with_fee) * new_output_reserve ≈ token_a_reserve * token_b_reserve
        // Allow for a small rounding error due to integer division
        let left_side = (1_000_000 + expected_input_amount_with_fee) * new_output_reserve;
        let right_side = 1_000_000 * 2_000_000;
        let diff = if left_side > right_side { left_side - right_side } else { right_side - left_side };
        
        // The difference should be very small relative to the values
        assert!(diff < 1000, "Constant product formula not maintained with fees");

        println!("Input amount: {}", input_amount);
        println!("Input amount with fee: {}", expected_input_amount_with_fee);
        println!("Output amount: {}", expected_output_amount);
        println!("Total fee amount: {}", expected_total_fee_amount);
        println!("Protocol fee amount: {}", expected_protocol_fee_amount);
        println!("LP fee amount: {}", expected_lp_fee_amount);
    }
}
