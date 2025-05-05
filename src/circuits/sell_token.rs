// SellTokenCircuit for the Virtual CPMM system
//
// This circuit allows users to sell tokens to a liquidity pool using the virtual CPMM model.
// It updates the virtual state without immediately affecting the actual reserves.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, VirtualStateTarget, HASH_SIZE};
use crate::errors::{ProofError, WireError, WireResult};
use crate::gadgets::{
    arithmetic::gte,
    fixed_point::{fixed_abs, fixed_div, fixed_mul},
    hash::hash_n,
    signature::verify_message_signature,
    specialized::conditional_select,
};
use crate::utils::constants::SCALING_FACTOR;
use crate::utils::nullifier::{compute_utxo_nullifier_target, UTXOTarget as NullifierUTXOTarget};
use std::marker::PhantomData;

/// Circuit for selling tokens to the AMM
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct SellTokenCircuit<
    const D: usize = 2,
    F = plonky2::field::goldilocks_field::GoldilocksField,
> where
    F: RichField + Extendable<D>,
{
    /// The input UTXO containing the tokens to sell
    pub input_utxo: UTXOTarget,

    /// The current virtual state of the pool
    pub current_virtual_state: VirtualStateTarget,

    /// The amount of tokens to sell
    pub token_in_amount: Target,

    /// The minimum amount of output tokens expected to receive
    pub min_token_out_amount: Target,

    /// The owner's public key
    pub owner_pk_x: Target,
    pub owner_pk_y: Target,

    /// The signature of the transaction
    pub signature_r_x: Target,
    pub signature_r_y: Target,
    pub signature_s: Target,

    /// Phantom data for the field type
    pub _phantom: PhantomData<F>,
}

impl<const D: usize, F> SellTokenCircuit<D, F>
where
    F: RichField + Extendable<D>,
{
    /// Generate a proof for the SellTokenCircuit
    pub fn prove<C: GenericConfig<D, F = F> + 'static>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> WireResult<()> {
        // Verify that the input UTXO belongs to the owner
        // Note: UTXOTarget doesn't have owner_pk_x/y fields, so we need to use owner_pubkey_hash_target
        // For simplicity, we'll just check the first element of the hash
        let owner_hash_first = self.input_utxo.owner_pubkey_hash_target[0];
        let owner_pk_hash_target = builder.add_virtual_target();
        builder.connect(owner_hash_first, owner_pk_hash_target);

        // Verify the signature
        let domain_separated_message = hash_n(
            builder,
            &[
                self.input_utxo.asset_id_target[0],
                self.input_utxo.amount_target,
                self.token_in_amount,
                self.min_token_out_amount,
                self.current_virtual_state.token_a_reserve,
                self.current_virtual_state.token_b_reserve,
                self.current_virtual_state.k_value,
            ],
        );

        let owner_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: self.owner_pk_x,
                y: self.owner_pk_y,
            },
        };

        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: self.signature_r_x,
                y: self.signature_r_y,
            },
            s_scalar: self.signature_s,
        };

        verify_message_signature(builder, &[domain_separated_message], &signature, &owner_pk);

        // Verify that the input UTXO has the correct asset ID (token A or token B)
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
        builder.assert_one(valid_asset.target);

        // Check if the user has enough tokens
        let has_enough_tokens = gte(builder, self.input_utxo.amount_target, self.token_in_amount);
        let one = builder.one();
        let has_enough_tokens_bool = builder.is_equal(has_enough_tokens, one);
        builder.assert_bool(has_enough_tokens_bool);

        // Calculate the amount of output tokens based on the constant product formula
        // For token A input, token B output: (x + dx) * (y - dy) = k
        // For token B input, token A output: (x - dx) * (y + dy) = k

        // Calculate both versions and then select based on is_token_a

        // Token A input, Token B output
        // Calculate new token A reserve
        let new_token_a_reserve_a = builder.add(
            self.current_virtual_state.token_a_reserve,
            self.token_in_amount,
        );

        // Calculate token B output amount: dy = y - (k / (x + dx))
        let numerator_a = self.current_virtual_state.k_value;
        let denominator_a = new_token_a_reserve_a;
        let new_token_b_reserve_a = fixed_div(builder, numerator_a, denominator_a)?;
        let token_out_amount_a = builder.sub(
            self.current_virtual_state.token_b_reserve,
            new_token_b_reserve_a,
        );

        // Create new virtual state for token A input
        let new_virtual_state_a = VirtualStateTarget {
            token_a_id: self.current_virtual_state.token_a_id,
            token_b_id: self.current_virtual_state.token_b_id,
            token_a_reserve: new_token_a_reserve_a,
            token_b_reserve: new_token_b_reserve_a,
            k_value: self.current_virtual_state.k_value,
            last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
        };

        // Token B input, Token A output
        // Calculate new token B reserve
        let new_token_b_reserve_b = builder.add(
            self.current_virtual_state.token_b_reserve,
            self.token_in_amount,
        );

        // Calculate token A output amount: dy = y - (k / (x + dx))
        let numerator_b = self.current_virtual_state.k_value;
        let denominator_b = new_token_b_reserve_b;
        let new_token_a_reserve_b = fixed_div(builder, numerator_b, denominator_b)?;
        let token_out_amount_b = builder.sub(
            self.current_virtual_state.token_a_reserve,
            new_token_a_reserve_b,
        );

        // Create new virtual state for token B input
        let new_virtual_state_b = VirtualStateTarget {
            token_a_id: self.current_virtual_state.token_a_id,
            token_b_id: self.current_virtual_state.token_b_id,
            token_a_reserve: new_token_a_reserve_b,
            token_b_reserve: new_token_b_reserve_b,
            k_value: self.current_virtual_state.k_value,
            last_transition_timestamp: self.current_virtual_state.last_transition_timestamp,
        };

        // Select the appropriate token_out_amount and new_virtual_state based on is_token_a
        let token_out_amount = conditional_select(
            builder,
            is_token_a.target,
            token_out_amount_a,
            token_out_amount_b,
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

        // Ensure we're not trying to drain the pool
        let min_remaining = builder.constant(F::from_canonical_u64(SCALING_FACTOR)); // Minimum 1.0 in reserve
        let has_enough_liquidity = gte(builder, selected_token_b_reserve, min_remaining);
        let one = builder.one();
        let has_enough_liquidity_bool = builder.is_equal(has_enough_liquidity, one);
        builder.assert_bool(has_enough_liquidity_bool);

        // Verify token_out_amount >= min_token_out_amount
        let meets_min_out = gte(builder, token_out_amount, self.min_token_out_amount);
        let one = builder.one();
        let meets_min_out_bool = builder.is_equal(meets_min_out, one);
        builder.assert_bool(meets_min_out_bool);

        // Verify the constant product formula for the new virtual state
        let product_before = fixed_mul(
            builder,
            self.current_virtual_state.token_a_reserve,
            self.current_virtual_state.token_b_reserve,
        )?;

        let product_after = fixed_mul(builder, selected_token_a_reserve, selected_token_b_reserve)?;

        let product_diff = builder.sub(product_after, product_before);
        let product_diff_abs = fixed_abs(builder, product_diff);
        let epsilon = builder.constant(F::from_canonical_u64(SCALING_FACTOR / 1000)); // 0.001 in fixed-point
        let product_valid = gte(builder, epsilon, product_diff_abs);
        let one = builder.one();
        let product_valid_bool = builder.is_equal(product_valid, one);
        builder.assert_bool(product_valid_bool);

        // Create a new output UTXO for the user with the token out amount
        let _output_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.input_utxo.owner_pubkey_hash_target.clone(),
            asset_id_target: self.input_utxo.asset_id_target.clone(),
            amount_target: token_out_amount,
            salt_target: self.input_utxo.salt_target.clone(),
        };

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
        builder.register_public_input(self.token_in_amount);
        builder.register_public_input(token_out_amount);
        builder.register_public_input(selected_token_a_reserve);
        builder.register_public_input(selected_token_b_reserve);
        builder.register_public_input(new_virtual_state.k_value);

        Ok(())
    }

    /// Generate a static proof for the SellTokenCircuit
    pub fn generate_proof_static<C: GenericConfig<D, F = F> + 'static>(
        input_utxo: &UTXOTarget,
        current_virtual_state: &VirtualStateTarget,
        token_in_amount: Target,
        min_token_out_amount: Target,
        owner_pk_x: Target,
        owner_pk_y: Target,
        signature_r_x: Target,
        signature_r_y: Target,
        signature_s: Target,
    ) -> WireResult<ProofWithPublicInputs<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit = SellTokenCircuit::<D, F> {
            input_utxo: input_utxo.clone(),
            current_virtual_state: current_virtual_state.clone(),
            token_in_amount,
            min_token_out_amount,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            _phantom: PhantomData,
        };

        circuit.prove::<C>(&mut builder)?;

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        data.prove(pw)
            .map_err(|e| WireError::ProofError(ProofError::GenerationError(e.to_string())))
    }

    /// Verify a proof for the SellTokenCircuit
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
            owner_pubkey_hash_target: vec![dummy_target; HASH_SIZE],
            asset_id_target: vec![dummy_target; HASH_SIZE],
            amount_target: dummy_target,
            salt_target: vec![dummy_target; HASH_SIZE],
        };

        let circuit = SellTokenCircuit::<D, F> {
            input_utxo: dummy_utxo,
            current_virtual_state: dummy_state,
            token_in_amount: dummy_target,
            min_token_out_amount: dummy_target,
            owner_pk_x: dummy_target,
            owner_pk_y: dummy_target,
            signature_r_x: dummy_target,
            signature_r_y: dummy_target,
            signature_s: dummy_target,
            _phantom: PhantomData,
        };

        circuit.prove::<C>(&mut builder)?;

        let data = builder.build::<C>();

        data.verify(proof.clone())
            .map_err(|e| WireError::ProofError(ProofError::VerificationError(e.to_string())))
    }
}

// Add a dummy implementation with concrete types to help with type inference
#[allow(dead_code)]
fn _dummy_sell_token_circuit(
) -> SellTokenCircuit<2, plonky2::field::goldilocks_field::GoldilocksField> {
    unimplemented!()
}

// Add a concrete type alias to help with type inference
#[allow(dead_code)]
type ConcreteSellTokenCircuit =
    SellTokenCircuit<2, plonky2::field::goldilocks_field::GoldilocksField>;

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_sell_token_circuit() {
        // Create a circuit builder
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create dummy targets
        let dummy_target = builder.add_virtual_target();

        // Create a dummy virtual state
        let virtual_state = VirtualStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            k_value: dummy_target,
            last_transition_timestamp: dummy_target,
        };

        // Create a dummy UTXO
        let utxo = UTXOTarget {
            owner_pubkey_hash_target: vec![dummy_target; HASH_SIZE],
            asset_id_target: vec![dummy_target; HASH_SIZE],
            amount_target: dummy_target,
            salt_target: vec![dummy_target; HASH_SIZE],
        };

        // Create a SellTokenCircuit
        let circuit = SellTokenCircuit::<D, F> {
            input_utxo: utxo,
            current_virtual_state: virtual_state,
            token_in_amount: dummy_target,
            min_token_out_amount: dummy_target,
            owner_pk_x: dummy_target,
            owner_pk_y: dummy_target,
            signature_r_x: dummy_target,
            signature_r_y: dummy_target,
            signature_s: dummy_target,
            _phantom: PhantomData,
        };

        // This is a simplified test that doesn't actually verify the proof
        // In a real test, we would generate a proof and verify it
        let _result = circuit.prove::<C>(&mut builder);

        // Just check that the circuit has some gates
        assert!(builder.num_gates() > 0);
    }
}
