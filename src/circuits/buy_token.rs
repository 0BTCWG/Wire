// BuyTokenCircuit for the Virtual CPMM system
//
// This circuit allows users to buy tokens from a liquidity pool using the virtual CPMM model.
// It updates the virtual state without immediately affecting the actual reserves.

use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::field::extension::Extendable;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::core::{PublicKeyTarget, UTXOTarget, VirtualStateTarget};
use crate::errors::{CircuitError, WireError, WireResult};
use crate::gadgets::fixed_point::{fixed_div, fixed_mul};
use crate::gadgets::{hash_n, verify_message_signature};
use crate::utils::constants::{DOMAIN_BUY_TOKEN, SCALING_FACTOR};
use crate::utils::nullifier::{
    compute_utxo_commitment_hash, compute_utxo_nullifier_target, UTXOTarget as NullifierUTXOTarget,
};

/// Circuit for buying tokens from a virtual CPMM pool
#[derive(Debug, Clone)]
pub struct BuyTokenCircuit<F: RichField + Extendable<D>, const D: usize> {
    /// The input UTXO containing the tokens to pay with
    pub input_utxo: UTXOTarget,

    /// The current virtual state of the pool
    pub current_virtual_state: VirtualStateTarget,

    /// The amount of tokens to buy
    pub token_out_amount: Target,

    /// The maximum amount of input tokens willing to pay
    pub max_token_in_amount: Target,

    /// The owner's public key
    pub owner_pk_x: Target,
    pub owner_pk_y: Target,

    /// The signature of the transaction
    pub signature_r_x: Target,
    pub signature_r_y: Target,
    pub signature_s: Target,
}

impl<F: RichField + Extendable<D>, const D: usize> BuyTokenCircuit<F, D> {
    /// Generate a proof for the BuyTokenCircuit
    pub fn prove<C: GenericConfig<D, F = F> + 'static>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<()> {
        // Verify that the input UTXO belongs to the owner
        builder.assert_equal(self.input_utxo.owner_pk_x, self.owner_pk_x);
        builder.assert_equal(self.input_utxo.owner_pk_y, self.owner_pk_y);

        // Verify the signature
        let domain_separated_message = hash_n(
            builder,
            &[
                self.input_utxo.asset_id,
                self.input_utxo.amount,
                self.token_out_amount,
                self.max_token_in_amount,
                self.current_virtual_state.token_a_reserve,
                self.current_virtual_state.token_b_reserve,
                self.current_virtual_state.k_value,
            ],
            DOMAIN_BUY_TOKEN,
        )?;

        let owner_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: self.owner_pk_x,
                y: self.owner_pk_y,
            },
        };

        let signature = crate::core::SignatureTarget {
            r_point: crate::core::PointTarget {
                x: self.signature_r_x,
                y: self.signature_r_y,
            },
            s_scalar: self.signature_s,
        };

        verify_message_signature(builder, &[domain_separated_message], &signature, &owner_pk);

        // Verify that the input UTXO has the correct asset ID (token A or token B)
        // For simplicity, we'll assume token A is the input token and token B is the output token
        let is_token_a = builder.is_equal(
            self.input_utxo.asset_id,
            self.current_virtual_state.token_a_id,
        );

        let is_token_b = builder.is_equal(
            self.input_utxo.asset_id,
            self.current_virtual_state.token_b_id,
        );

        // Input UTXO must contain either token A or token B
        let valid_asset = builder.or(is_token_a, is_token_b);
        builder.assert_one(valid_asset.target);

        // Calculate the amount of input tokens needed based on the constant product formula
        // For token A input, token B output: (x + dx) * (y - dy) = k
        // For token B input, token A output: (x - dx) * (y + dy) = k

        // Calculate the new reserves and verify the constant product formula
        let (token_in_amount, new_virtual_state) = builder.if_else(
            is_token_a,
            // Token A input, Token B output
            {
                // Calculate token A input amount: dx = (k / (y - dy)) - x
                let new_token_b_reserve = builder.sub(
                    self.current_virtual_state.token_b_reserve,
                    self.token_out_amount,
                );

                // Ensure we're not trying to buy more than available
                let min_remaining = builder.constant(F::from_canonical_u64(SCALING_FACTOR)); // Minimum 1.0 in reserve
                let has_enough_liquidity = builder.gte(new_token_b_reserve, min_remaining);
                builder.assert_one(has_enough_liquidity.target);

                // Calculate token A input amount: dx = (k / (y - dy)) - x
                let denominator = new_token_b_reserve;
                let numerator = self.current_virtual_state.k_value;
                let new_token_a_reserve = fixed_div(builder, numerator, denominator)?;
                let token_in_amount = builder.sub(
                    new_token_a_reserve,
                    self.current_virtual_state.token_a_reserve,
                );

                // Verify token_in_amount <= max_token_in_amount
                let within_max = builder.lte(token_in_amount, self.max_token_in_amount);
                builder.assert_one(within_max.target);

                // Verify token_in_amount <= input_utxo.amount
                let has_enough_funds = builder.lte(token_in_amount, self.input_utxo.amount);
                builder.assert_one(has_enough_funds.target);

                // Create new virtual state
                let new_virtual_state = VirtualStateTarget {
                    token_a_id: self.current_virtual_state.token_a_id,
                    token_b_id: self.current_virtual_state.token_b_id,
                    token_a_reserve: new_token_a_reserve,
                    token_b_reserve: new_token_b_reserve,
                    k_value: self.current_virtual_state.k_value,
                    last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
                };

                (token_in_amount, new_virtual_state)
            },
            // Token B input, Token A output
            {
                // Calculate token B input amount: dx = (k / (x - dy)) - y
                let new_token_a_reserve = builder.sub(
                    self.current_virtual_state.token_a_reserve,
                    self.token_out_amount,
                );

                // Ensure we're not trying to buy more than available
                let min_remaining = builder.constant(F::from_canonical_u64(SCALING_FACTOR)); // Minimum 1.0 in reserve
                let has_enough_liquidity = builder.gte(new_token_a_reserve, min_remaining);
                builder.assert_one(has_enough_liquidity.target);

                // Calculate token B input amount: dx = (k / (x - dy)) - y
                let denominator = new_token_a_reserve;
                let numerator = self.current_virtual_state.k_value;
                let new_token_b_reserve = fixed_div(builder, numerator, denominator)?;
                let token_in_amount = builder.sub(
                    new_token_b_reserve,
                    self.current_virtual_state.token_b_reserve,
                );

                // Verify token_in_amount <= max_token_in_amount
                let within_max = builder.lte(token_in_amount, self.max_token_in_amount);
                builder.assert_one(within_max.target);

                // Verify token_in_amount <= input_utxo.amount
                let has_enough_funds = builder.lte(token_in_amount, self.input_utxo.amount);
                builder.assert_one(has_enough_funds.target);

                // Create new virtual state
                let new_virtual_state = VirtualStateTarget {
                    token_a_id: self.current_virtual_state.token_a_id,
                    token_b_id: self.current_virtual_state.token_b_id,
                    token_a_reserve: new_token_a_reserve,
                    token_b_reserve: new_token_b_reserve,
                    k_value: self.current_virtual_state.k_value,
                    last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
                };

                (token_in_amount, new_virtual_state)
            },
        );

        // Verify the constant product formula for the new virtual state
        let new_product = fixed_mul(
            builder,
            new_virtual_state.token_a_reserve,
            new_virtual_state.token_b_reserve,
        )?;

        // Allow for a small epsilon due to fixed-point arithmetic rounding
        let epsilon = builder.constant(F::from_canonical_u64(SCALING_FACTOR / 1000)); // 0.001 in fixed-point
        let product_diff = builder.sub(new_product, self.current_virtual_state.k_value);
        let product_diff_abs = builder.abs(product_diff);
        let product_valid = builder.lte(product_diff_abs, epsilon);
        builder.assert_one(product_valid.target);

        // Calculate the nullifier for the input UTXO
        let nullifier_utxo = NullifierUTXOTarget {
            owner_pubkey_hash_target: vec![self.owner_pk_x, self.owner_pk_y],
            asset_id_target: vec![self.input_utxo.asset_id],
            amount_target: self.input_utxo.amount,
            salt_target: vec![self.input_utxo.salt],
        };

        let nullifier = compute_utxo_nullifier_target(builder, &nullifier_utxo);

        // Register public inputs
        builder.register_public_input(nullifier);
        builder.register_public_input(self.token_out_amount);
        builder.register_public_input(token_in_amount);
        builder.register_public_input(new_virtual_state.token_a_reserve);
        builder.register_public_input(new_virtual_state.token_b_reserve);
        builder.register_public_input(new_virtual_state.k_value);

        Ok(())
    }

    /// Generate a static proof for the BuyTokenCircuit
    pub fn generate_proof_static<C: GenericConfig<D, F = F> + 'static>(
        input_utxo: &UTXOTarget,
        current_virtual_state: &VirtualStateTarget,
        token_out_amount: Target,
        max_token_in_amount: Target,
        owner_pk_x: Target,
        owner_pk_y: Target,
        signature_r_x: Target,
        signature_r_y: Target,
        signature_s: Target,
    ) -> WireResult<ProofWithPublicInputs<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit = BuyTokenCircuit {
            input_utxo: input_utxo.clone(),
            current_virtual_state: current_virtual_state.clone(),
            token_out_amount,
            max_token_in_amount,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        };

        circuit.prove(&mut builder)?;

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        data.prove(pw)
            .map_err(|e| WireError::CircuitError(CircuitError::ProofGenerationError(e.to_string())))
    }

    /// Verify a proof for the BuyTokenCircuit
    pub fn verify_proof<C: GenericConfig<D, F = F> + 'static>(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> WireResult<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a dummy circuit just to build the verification circuit
        let dummy_target = builder.add_virtual_target();
        let dummy_state = VirtualStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            k_value: dummy_target,
            last_transition_timestamp: dummy_target,
        };

        let dummy_utxo = UTXOTarget {
            owner_pk_x: dummy_target,
            owner_pk_y: dummy_target,
            asset_id: dummy_target,
            amount: dummy_target,
            salt: dummy_target,
        };

        let circuit = BuyTokenCircuit {
            input_utxo: dummy_utxo,
            current_virtual_state: dummy_state,
            token_out_amount: dummy_target,
            max_token_in_amount: dummy_target,
            owner_pk_x: dummy_target,
            owner_pk_y: dummy_target,
            signature_r_x: dummy_target,
            signature_r_y: dummy_target,
            signature_s: dummy_target,
        };

        circuit.prove(&mut builder)?;

        let data = builder.build::<C>();

        data.verify(proof.clone()).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofVerificationError(e.to_string()))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_buy_token_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create test inputs
        let owner_pk_x = builder.constant(F::from_canonical_u64(1234));
        let owner_pk_y = builder.constant(F::from_canonical_u64(5678));

        // Create input UTXO (with token A)
        let token_a_id = builder.constant(F::from_canonical_u64(1));
        let token_b_id = builder.constant(F::from_canonical_u64(2));
        let input_amount = builder.constant(F::from_canonical_u64(100 * SCALING_FACTOR)); // 100 token A
        let input_utxo = UTXOTarget {
            owner_pk_x,
            owner_pk_y,
            asset_id: token_a_id,
            amount: input_amount,
            salt: builder.constant(F::from_canonical_u64(9876)),
        };

        // Create virtual state
        let token_a_reserve = builder.constant(F::from_canonical_u64(1000 * SCALING_FACTOR)); // 1000 token A
        let token_b_reserve = builder.constant(F::from_canonical_u64(2000 * SCALING_FACTOR)); // 2000 token B
        let k_value = fixed_mul(&mut builder, token_a_reserve, token_b_reserve).unwrap();

        let virtual_state = VirtualStateTarget {
            token_a_id,
            token_b_id,
            token_a_reserve,
            token_b_reserve,
            k_value,
            last_transition_timestamp: builder.constant(F::from_canonical_u64(12345)),
        };

        // Buy 10 token B
        let token_out_amount = builder.constant(F::from_canonical_u64(10 * SCALING_FACTOR));
        let max_token_in_amount = builder.constant(F::from_canonical_u64(10 * SCALING_FACTOR));

        // Signature (dummy values for test)
        let signature_r_x = builder.constant(F::from_canonical_u64(1111));
        let signature_r_y = builder.constant(F::from_canonical_u64(2222));
        let signature_s = builder.constant(F::from_canonical_u64(3333));

        // Create the circuit
        let circuit = BuyTokenCircuit {
            input_utxo,
            current_virtual_state: virtual_state,
            token_out_amount,
            max_token_in_amount,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        };

        // This is just a structure test, we're not actually generating a valid proof
        let result = circuit.prove(&mut builder);
        assert!(
            result.is_ok(),
            "Circuit structure test failed: {:?}",
            result.err()
        );
    }
}
