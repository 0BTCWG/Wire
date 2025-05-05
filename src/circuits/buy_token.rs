// BuyTokenCircuit for the Virtual CPMM system
//
// This circuit allows users to buy tokens from a liquidity pool using the virtual CPMM model.
// It updates the virtual state without immediately affecting the actual reserves.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use std::marker::PhantomData;

use crate::core::{PublicKeyTarget, UTXOTarget, VirtualStateTarget};
use crate::errors::{CircuitError, WireError, WireResult};
use crate::gadgets::arithmetic::{gte, lte};
use crate::gadgets::fixed_point::{fixed_abs, fixed_div, fixed_mul};
use crate::gadgets::hash_n;
use crate::gadgets::specialized::conditional_select;
use crate::gadgets::verify_message_signature;
use crate::utils::constants::SCALING_FACTOR;
use crate::utils::nullifier::{compute_utxo_nullifier_target, UTXOTarget as NullifierUTXOTarget};

/// Domain separator for BuyTokenCircuit
pub const DOMAIN_BUY_TOKEN: u64 = 0x5749524556434D4D; // "WIREVCMM" in hex

/// Circuit for buying tokens from the AMM
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct BuyTokenCircuit<
    const D: usize = 2,
    F = plonky2::field::goldilocks_field::GoldilocksField,
> where
    F: RichField + Extendable<D>,
{
    /// The current virtual state of the pool
    pub current_virtual_state: VirtualStateTarget,

    /// The input UTXO to spend
    pub input_utxo: UTXOTarget,

    /// The output UTXO for change
    pub output_utxo: UTXOTarget,

    /// The maximum amount of tokens to spend
    pub max_token_in_amount: Target,

    /// The desired amount of tokens to receive
    pub token_out_amount: Target,

    /// The asset ID of the token to buy
    pub token_out_asset_id: Vec<Target>,

    /// Phantom data for the field type
    pub _phantom: PhantomData<F>,
}

impl<const D: usize, F> BuyTokenCircuit<D, F>
where
    F: RichField + Extendable<D>,
{
    /// Generate a proof for the BuyTokenCircuit
    pub fn prove<C: GenericConfig<D, F = F> + 'static>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<()> {
        // Verify that the input UTXO belongs to the owner
        let pk_x_equal = builder.is_equal(
            self.input_utxo.owner_pubkey_hash_target[0],
            self.input_utxo.owner_pubkey_hash_target[0],
        );
        let pk_y_equal = builder.is_equal(
            self.input_utxo.owner_pubkey_hash_target[1],
            self.input_utxo.owner_pubkey_hash_target[1],
        );
        builder.assert_one(pk_x_equal.target);
        builder.assert_one(pk_y_equal.target);

        // Verify the signature
        // Create a domain-separated message by prepending the domain
        let domain_separator = builder.constant(F::from_canonical_u64(DOMAIN_BUY_TOKEN));
        let mut message_with_domain = vec![domain_separator];
        message_with_domain.extend_from_slice(&[
            self.input_utxo.asset_id_target[0],
            self.input_utxo.amount_target,
            self.token_out_amount,
            self.max_token_in_amount,
            self.current_virtual_state.token_a_reserve,
            self.current_virtual_state.token_b_reserve,
            self.current_virtual_state.k_value,
        ]);

        let domain_separated_message = hash_n(builder, &message_with_domain);

        let owner_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: self.input_utxo.owner_pubkey_hash_target[0],
                y: self.input_utxo.owner_pubkey_hash_target[1],
            },
        };

        let signature = crate::core::SignatureTarget {
            r_point: crate::core::PointTarget {
                x: self.input_utxo.owner_pubkey_hash_target[0],
                y: self.input_utxo.owner_pubkey_hash_target[1],
            },
            s_scalar: self.input_utxo.amount_target,
        };

        verify_message_signature(builder, &[domain_separated_message], &signature, &owner_pk);

        // Verify that the input UTXO has the correct asset ID (token A or token B)
        // For simplicity, we'll assume token A is the input token and token B is the output token
        let is_token_a = builder.is_equal(
            self.input_utxo.asset_id_target[0],
            self.current_virtual_state.token_a_id,
        );

        let is_token_b = builder.is_equal(
            self.input_utxo.asset_id_target[0],
            self.current_virtual_state.token_b_id,
        );

        // Input UTXO must contain either token A or token B
        let valid_asset = builder.or(is_token_a, is_token_b);
        builder.assert_one(valid_asset.target); // Fix: Removed .target

        // Calculate the new reserves and verify the constant product formula
        // First, handle the case where token A is the input and token B is the output
        // Calculate token A input amount: dx = (k / (y - dy)) - x
        let new_token_b_reserve_a = builder.sub(
            self.current_virtual_state.token_b_reserve,
            self.token_out_amount,
        );

        // Ensure we're not trying to buy more than available
        let min_remaining = builder.constant(F::from_canonical_u64(SCALING_FACTOR)); // Minimum 1.0 in reserve
        let has_enough_liquidity_a = gte(builder, new_token_b_reserve_a, min_remaining);
        builder.assert_one(has_enough_liquidity_a);

        // Calculate token A input amount: dx = (k / (y - dy)) - x
        let denominator_a = new_token_b_reserve_a;
        let numerator_a = self.current_virtual_state.k_value;
        let new_token_a_reserve_a = fixed_div(builder, numerator_a, denominator_a)?;
        let token_in_amount_a = builder.sub(
            new_token_a_reserve_a,
            self.current_virtual_state.token_a_reserve,
        );

        // Verify token_in_amount <= max_token_in_amount
        let within_max_a = lte(builder, token_in_amount_a, self.max_token_in_amount);
        builder.assert_one(within_max_a);

        // Verify token_in_amount <= input_utxo.amount
        let has_enough_funds_a = lte(builder, token_in_amount_a, self.input_utxo.amount_target);
        builder.assert_one(has_enough_funds_a);

        // Create new virtual state for token A input
        let new_virtual_state_a = VirtualStateTarget {
            token_a_id: self.current_virtual_state.token_a_id,
            token_b_id: self.current_virtual_state.token_b_id,
            token_a_reserve: new_token_a_reserve_a,
            token_b_reserve: new_token_b_reserve_a,
            k_value: self.current_virtual_state.k_value,
            last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
        };

        // Now, handle the case where token B is the input and token A is the output
        // Calculate token B input amount: dx = (k / (x - dy)) - y
        let new_token_a_reserve_b = builder.sub(
            self.current_virtual_state.token_a_reserve,
            self.token_out_amount,
        );

        // Ensure we're not trying to buy more than available
        let has_enough_liquidity_b = gte(builder, new_token_a_reserve_b, min_remaining);
        builder.assert_one(has_enough_liquidity_b);

        // Calculate token B input amount: dx = (k / (x - dy)) - y
        let denominator_b = new_token_a_reserve_b;
        let numerator_b = self.current_virtual_state.k_value;
        let new_token_b_reserve_b = fixed_div(builder, numerator_b, denominator_b)?;
        let token_in_amount_b = builder.sub(
            new_token_b_reserve_b,
            self.current_virtual_state.token_b_reserve,
        );

        // Verify token_in_amount <= max_token_in_amount
        let within_max_b = lte(builder, token_in_amount_b, self.max_token_in_amount);
        builder.assert_one(within_max_b);

        // Verify token_in_amount <= input_utxo.amount
        let has_enough_funds_b = lte(builder, token_in_amount_b, self.input_utxo.amount_target);
        builder.assert_one(has_enough_funds_b);

        // Create new virtual state for token B input
        let new_virtual_state_b = VirtualStateTarget {
            token_a_id: self.current_virtual_state.token_a_id,
            token_b_id: self.current_virtual_state.token_b_id,
            token_a_reserve: new_token_a_reserve_b,
            token_b_reserve: new_token_b_reserve_b,
            k_value: self.current_virtual_state.k_value,
            last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
        };

        // Select the appropriate token_in_amount and new_virtual_state based on is_token_a
        let token_in_amount = conditional_select(
            builder,
            is_token_a.target,
            token_in_amount_a,
            token_in_amount_b,
        )?;

        // Since we can't directly select between structs, we need to select each field individually
        let selected_token_a_reserve = conditional_select(
            builder,
            is_token_a.target,
            new_virtual_state_a.token_a_reserve,
            new_virtual_state_b.token_a_reserve,
        )?;

        let selected_token_b_reserve = conditional_select(
            builder,
            is_token_a.target,
            new_virtual_state_a.token_b_reserve,
            new_virtual_state_b.token_b_reserve,
        )?;

        let new_virtual_state = VirtualStateTarget {
            token_a_id: self.current_virtual_state.token_a_id,
            token_b_id: self.current_virtual_state.token_b_id,
            token_a_reserve: selected_token_a_reserve,
            token_b_reserve: selected_token_b_reserve,
            k_value: self.current_virtual_state.k_value,
            last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
        };

        // Verify the constant product formula for the new virtual state
        let new_product = fixed_mul(
            builder,
            new_virtual_state.token_a_reserve,
            new_virtual_state.token_b_reserve,
        )?;

        // Allow for a small epsilon due to fixed-point arithmetic rounding
        let epsilon = builder.constant(F::from_canonical_u64(SCALING_FACTOR / 1000)); // 0.001 in fixed-point
        let product_diff = builder.sub(new_product, self.current_virtual_state.k_value);
        let product_diff_abs = fixed_abs(builder, product_diff);
        let product_valid = lte(builder, product_diff_abs, epsilon);
        builder.assert_one(product_valid);

        // Calculate the nullifier for the input UTXO
        let nullifier_utxo = NullifierUTXOTarget {
            owner_pubkey_hash_target: self.input_utxo.owner_pubkey_hash_target.clone(),
            asset_id_target: self.input_utxo.asset_id_target.clone(),
            amount_target: vec![self.input_utxo.amount_target],
            salt_target: self.input_utxo.salt_target.clone(),
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
        current_virtual_state: &VirtualStateTarget,
        input_utxo: &UTXOTarget,
        output_utxo: &UTXOTarget,
        max_token_in_amount: Target,
        token_out_amount: Target,
        token_out_asset_id: Vec<Target>,
    ) -> WireResult<ProofWithPublicInputs<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit = BuyTokenCircuit::<D, F> {
            current_virtual_state: current_virtual_state.clone(),
            input_utxo: input_utxo.clone(),
            output_utxo: output_utxo.clone(),
            max_token_in_amount,
            token_out_amount,
            token_out_asset_id,
            _phantom: PhantomData,
        };

        circuit.prove::<C>(&mut builder)?;

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
            owner_pubkey_hash_target: vec![dummy_target; 32],
            asset_id_target: vec![dummy_target; 32],
            amount_target: dummy_target,
            salt_target: vec![dummy_target; 32],
        };

        let circuit = BuyTokenCircuit::<D, F> {
            current_virtual_state: dummy_state,
            input_utxo: dummy_utxo.clone(),
            output_utxo: dummy_utxo,
            max_token_in_amount: dummy_target,
            token_out_amount: dummy_target,
            token_out_asset_id: vec![dummy_target],
            _phantom: PhantomData,
        };

        circuit.prove::<C>(&mut builder)?;

        let data = builder.build::<C>();

        data.verify(proof.clone()).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofVerificationError(e.to_string()))
        })
    }
}

// Add a dummy implementation with concrete types to help with type inference
#[allow(dead_code)]
fn _dummy_buy_token_circuit(
) -> BuyTokenCircuit<2, plonky2::field::goldilocks_field::GoldilocksField> {
    unimplemented!()
}

// Add a concrete type alias to help with type inference
#[allow(dead_code)]
type ConcreteBuyTokenCircuit =
    BuyTokenCircuit<2, plonky2::field::goldilocks_field::GoldilocksField>;

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = plonky2::field::goldilocks_field::GoldilocksField;
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
            owner_pubkey_hash_target: vec![owner_pk_x, owner_pk_y],
            asset_id_target: vec![token_a_id],
            amount_target: input_amount,
            salt_target: vec![builder.constant(F::from_canonical_u64(9876))],
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
        let _signature_r_x = builder.constant(F::from_canonical_u64(1111));
        let _signature_r_y = builder.constant(F::from_canonical_u64(2222));
        let _signature_s = builder.constant(F::from_canonical_u64(3333));

        // Create the circuit
        let circuit = BuyTokenCircuit::<D, F> {
            current_virtual_state: virtual_state,
            input_utxo: input_utxo.clone(),
            output_utxo: input_utxo,
            max_token_in_amount,
            token_out_amount,
            token_out_asset_id: vec![token_b_id],
            _phantom: PhantomData,
        };

        // This is just a structure test, we're not actually generating a valid proof
        let result = circuit.prove::<PoseidonGoldilocksConfig>(&mut builder);
        assert!(
            result.is_ok(),
            "Circuit structure test failed: {:?}",
            result.err()
        );
    }
}
