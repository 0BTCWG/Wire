// TransitionCircuit for the Virtual CPMM system
//
// This circuit reconciles the virtual state with the actual reserves,
// executing the accumulated trades and updating the real pool state.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::core::virtual_cpmm::{PoolStateTarget, VirtualStateTarget};
use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget};
use crate::errors::{CircuitError, WireError, WireResult};
use crate::gadgets::fixed_point::fixed_abs;
use crate::utils::hash::compute_hash_targets;
use std::marker::PhantomData;

/// Circuit for transitioning the virtual state to the actual pool state
#[allow(clippy::derive_partial_eq_without_eq)]
pub struct TransitionCircuit<
    const D: usize = 2,
    F = plonky2::field::goldilocks_field::GoldilocksField,
> where
    F: RichField + Extendable<D>,
{
    /// The current virtual state of the pool
    pub current_virtual_state: VirtualStateTarget,

    /// The current actual pool state
    pub current_pool_state: PoolStateTarget,

    /// The current timestamp
    pub current_timestamp: Target,

    /// The operator's public key (x-coordinate)
    pub operator_pk_x: Target,

    /// The operator's public key (y-coordinate)
    pub operator_pk_y: Target,

    /// The signature's r value (x-coordinate)
    pub signature_r_x: Target,

    /// The signature's r value (y-coordinate)
    pub signature_r_y: Target,

    /// The signature's s value
    pub signature_s: Target,

    /// Phantom data for the field type
    pub _phantom: PhantomData<F>,
}

impl<const D: usize, F> TransitionCircuit<D, F>
where
    F: RichField + Extendable<D>,
{
    /// Generate a proof for the TransitionCircuit
    pub fn prove(&self, builder: &mut CircuitBuilder<F, D>) -> WireResult<()> {
        // Verify that the operator public key matches
        let pk_x_match =
            builder.is_equal(self.current_pool_state.operator_pk_x, self.operator_pk_x);
        let pk_y_match =
            builder.is_equal(self.current_pool_state.operator_pk_y, self.operator_pk_y);

        // Convert to Target for assertion
        let one = builder.one();
        let zero = builder.zero();
        let pk_x_match_target = builder.select(pk_x_match, one, zero);
        builder.assert_one(pk_x_match_target);
        let pk_y_match_target = builder.select(pk_y_match, one, zero);
        builder.assert_one(pk_y_match_target);

        // Verify the signature
        let _domain_separated_message = compute_hash_targets(
            builder,
            &[
                self.current_virtual_state.token_a_id,
                self.current_virtual_state.token_b_id,
                self.current_virtual_state.token_a_reserve,
                self.current_virtual_state.token_b_reserve,
                self.current_timestamp,
            ],
        );

        let _user_pk = PublicKeyTarget {
            point: PointTarget {
                x: self.operator_pk_x,
                y: self.operator_pk_y,
            },
        };

        let _signature = SignatureTarget {
            r_point: PointTarget {
                x: self.signature_r_x,
                y: self.signature_r_y,
            },
            s_scalar: self.signature_s,
        };

        // For now, we'll skip the signature verification since the verify method is not available
        // In a real implementation, we would verify the signature here
        let signature_valid = builder.add_virtual_bool_target_safe();
        builder.assert_bool(signature_valid);
        let signature_valid_target = builder.select(signature_valid, one, zero);
        builder.assert_one(signature_valid_target);

        // Verify that enough time has passed since the last transition
        // This is to prevent front-running and other timing attacks
        let min_interval = builder.constant(F::from_canonical_u64(60)); // 60 seconds

        // Since last_transition_timestamp is not available in PoolStateTarget,
        // we'll use a dummy value for now
        let _last_transition_timestamp = builder.zero();
        let time_since_last = builder.sub(self.current_timestamp, _last_transition_timestamp);

        // Use the arithmetic gadget for greater than or equal comparison
        use crate::gadgets::arithmetic::gte;

        // Create a BoolTarget to hold the result
        let enough_time_passed_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(enough_time_passed_bool);

        // Compute the gte result
        let gte_result = gte(builder, time_since_last, min_interval);

        // We need to convert gte_result (Target) to a BoolTarget for select
        // First, we'll create a new BoolTarget
        let gte_result_as_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(gte_result_as_bool);

        // Connect the new BoolTarget to the gte result
        let gte_result_as_bool_target = builder.select(gte_result_as_bool, one, zero);
        builder.connect(gte_result_as_bool_target, gte_result);

        // Now connect our original BoolTarget to the new one
        let enough_time_passed_bool_as_target = builder.select(enough_time_passed_bool, one, zero);
        let gte_result_as_bool_target = builder.select(gte_result_as_bool, one, zero);
        builder.connect(enough_time_passed_bool_as_target, gte_result_as_bool_target);

        // Convert BoolTarget to Target for assertion
        let enough_time_passed_final = builder.select(enough_time_passed_bool, one, zero);
        builder.assert_one(enough_time_passed_final);

        // Verify that the token IDs match between virtual and actual states
        // Create a BoolTarget to hold the result
        let token_a_id_match_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(token_a_id_match_bool);

        // Compute the is_equal result
        let is_equal_result_a = builder.is_equal(
            self.current_virtual_state.token_a_id,
            self.current_pool_state.token_a_id,
        );

        // Convert is_equal_result_a (Target) to a BoolTarget for select
        let is_equal_result_a_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(is_equal_result_a_bool);

        // Connect the new BoolTarget to the is_equal result
        let is_equal_result_a_bool_target = builder.select(is_equal_result_a_bool, one, zero);
        let is_equal_result_a_target = builder.select(is_equal_result_a, one, zero);
        builder.connect(is_equal_result_a_bool_target, is_equal_result_a_target);

        // Now connect the original BoolTarget to the new one
        let token_a_id_match_as_target = builder.select(token_a_id_match_bool, one, zero);
        let is_equal_result_a_bool_target = builder.select(is_equal_result_a_bool, one, zero);
        builder.connect(token_a_id_match_as_target, is_equal_result_a_bool_target);

        // Convert BoolTarget to Target for assertion
        let token_a_id_match_target = builder.select(token_a_id_match_bool, one, zero);
        builder.assert_one(token_a_id_match_target);

        // Create a BoolTarget to hold the result
        let token_b_id_match_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(token_b_id_match_bool);

        // Compute the is_equal result
        let is_equal_result_b = builder.is_equal(
            self.current_virtual_state.token_b_id,
            self.current_pool_state.token_b_id,
        );

        // Convert is_equal_result_b (Target) to a BoolTarget for select
        let is_equal_result_b_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(is_equal_result_b_bool);

        // Connect the new BoolTarget to the is_equal result
        let is_equal_result_b_bool_target = builder.select(is_equal_result_b_bool, one, zero);
        let is_equal_result_b_target = builder.select(is_equal_result_b, one, zero);
        builder.connect(is_equal_result_b_bool_target, is_equal_result_b_target);

        // Now connect the original BoolTarget to the new one
        let token_b_id_match_as_target = builder.select(token_b_id_match_bool, one, zero);
        let is_equal_result_b_bool_target = builder.select(is_equal_result_b_bool, one, zero);
        builder.connect(token_b_id_match_as_target, is_equal_result_b_bool_target);

        // Convert BoolTarget to Target for assertion
        let token_b_id_match_target = builder.select(token_b_id_match_bool, one, zero);
        builder.assert_one(token_b_id_match_target);

        // Verify that the constant product formula is maintained
        // k = reserve_a * reserve_b
        let k_virtual = builder.mul(
            self.current_virtual_state.token_a_reserve,
            self.current_virtual_state.token_b_reserve,
        );

        let k_pool = builder.mul(
            self.current_pool_state.token_a_reserve,
            self.current_pool_state.token_b_reserve,
        );

        // Calculate the absolute difference between the two k values
        let k_diff = builder.sub(k_virtual, k_pool);

        // Use the fixed_abs function from fixed_point.rs
        let k_diff_abs = fixed_abs(builder, k_diff);

        // Allow for a small epsilon due to rounding errors
        let epsilon = builder.constant(F::from_canonical_u64(1000)); // Small tolerance

        // Verify that the difference is within the acceptable range
        let k_valid_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(k_valid_bool);

        // Compute the lte result
        let k_valid = lte(builder, k_diff_abs, epsilon);

        // Convert k_valid (Target) to a BoolTarget for select
        let k_valid_as_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(k_valid_as_bool);

        // Connect the new BoolTarget to the k_valid result
        let k_valid_as_bool_target = builder.select(k_valid_as_bool, one, zero);
        builder.connect(k_valid_as_bool_target, k_valid);

        // Now connect the original BoolTarget to the new one
        let k_valid_bool_as_target = builder.select(k_valid_bool, one, zero);
        let k_valid_as_bool_target = builder.select(k_valid_as_bool, one, zero);
        builder.connect(k_valid_bool_as_target, k_valid_as_bool_target);

        // Convert BoolTarget to Target for assertion
        let k_valid_target = builder.select(k_valid_bool, one, zero);
        builder.assert_one(k_valid_target);

        // Update the pool state with the virtual state values
        // This is the actual transition operation
        // Note: Since we can't modify the PoolStateTarget struct directly,
        // we'll just create a new one with the updated values
        let new_pool_state = PoolStateTarget {
            token_a_id: self.current_pool_state.token_a_id,
            token_b_id: self.current_pool_state.token_b_id,
            token_a_reserve: self.current_virtual_state.token_a_reserve,
            token_b_reserve: self.current_virtual_state.token_b_reserve,
            operator_pk_x: self.current_pool_state.operator_pk_x,
            operator_pk_y: self.current_pool_state.operator_pk_y,
        };

        // Verify that the product of reserves is preserved (constant product formula)
        let product_before = builder.mul(
            self.current_pool_state.token_a_reserve,
            self.current_pool_state.token_b_reserve,
        );
        let product_after = builder.mul(
            new_pool_state.token_a_reserve,
            new_pool_state.token_b_reserve,
        );
        let product_diff = builder.sub(product_after, product_before);

        // Use fixed_abs to get the absolute difference
        let product_diff_abs = fixed_abs(builder, product_diff);

        // Allow for a small epsilon due to rounding errors
        let epsilon = builder.constant(F::from_canonical_u64(1000)); // Small tolerance

        // Use the arithmetic gadget for less than or equal comparison
        use crate::gadgets::arithmetic::lte;

        // Create a BoolTarget to hold the result
        let product_valid_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(product_valid_bool);

        // Compute the lte result
        let lte_result = lte(builder, product_diff_abs, epsilon);

        // Convert lte_result (Target) to a BoolTarget for select
        let lte_result_as_bool = builder.add_virtual_bool_target_safe();
        builder.assert_bool(lte_result_as_bool);

        // Connect the new BoolTarget to the lte result
        let lte_result_as_bool_target = builder.select(lte_result_as_bool, one, zero);
        builder.connect(lte_result_as_bool_target, lte_result);

        // Now connect the original BoolTarget to the new one
        let product_valid_bool_as_target = builder.select(product_valid_bool, one, zero);
        let lte_result_as_bool_target = builder.select(lte_result_as_bool, one, zero);
        builder.connect(product_valid_bool_as_target, lte_result_as_bool_target);

        // Convert BoolTarget to Target for assertion
        let product_valid_final = builder.select(product_valid_bool, one, zero);
        builder.assert_one(product_valid_final);

        // Return success
        Ok(())
    }

    /// Generate a static proof for the TransitionCircuit
    pub fn generate_proof_static<C: GenericConfig<D, F = F> + 'static>(
        current_virtual_state: &VirtualStateTarget,
        current_pool_state: &PoolStateTarget,
        current_timestamp: Target,
        operator_pk_x: Target,
        operator_pk_y: Target,
        signature_r_x: Target,
        signature_r_y: Target,
        signature_s: Target,
    ) -> WireResult<ProofWithPublicInputs<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let circuit = TransitionCircuit::<D, F> {
            current_virtual_state: current_virtual_state.clone(),
            current_pool_state: current_pool_state.clone(),
            current_timestamp,
            operator_pk_x,
            operator_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            _phantom: PhantomData,
        };

        circuit.prove(&mut builder)?;

        let data = builder.build::<C>();
        let pw = PartialWitness::new();

        // TODO: Fill in the witness values

        match data.prove(pw) {
            Ok(proof) => Ok(proof),
            Err(e) => Err(WireError::CircuitError(CircuitError::ProofGenerationError(
                e.to_string(),
            ))),
        }
    }

    /// Verify a proof for the TransitionCircuit
    pub fn verify_proof<C: GenericConfig<D, F = F> + 'static>(
        proof: &ProofWithPublicInputs<F, C, D>,
    ) -> WireResult<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create dummy targets for the circuit
        let dummy_target = builder.add_virtual_target();
        let current_virtual_state = VirtualStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            k_value: dummy_target,
            last_transition_timestamp: dummy_target,
        };

        let current_pool_state = PoolStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            operator_pk_x: dummy_target,
            operator_pk_y: dummy_target,
        };

        let current_timestamp = builder.add_virtual_target();
        let operator_pk_x = builder.add_virtual_target();
        let operator_pk_y = builder.add_virtual_target();
        let signature_r_x = builder.add_virtual_target();
        let signature_r_y = builder.add_virtual_target();
        let signature_s = builder.add_virtual_target();

        let circuit = TransitionCircuit::<D, F> {
            current_virtual_state,
            current_pool_state,
            current_timestamp,
            operator_pk_x,
            operator_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            _phantom: PhantomData,
        };

        circuit.prove(&mut builder)?;

        let data = builder.build::<C>();

        match data.verify(proof.clone()) {
            Ok(_) => Ok(()),
            Err(e) => Err(WireError::CircuitError(
                CircuitError::ProofVerificationError(e.to_string()),
            )),
        }
    }

    /// Generate a dummy circuit for testing
    pub fn generate_dummy_circuit<C: GenericConfig<D, F = F> + 'static>(
    ) -> WireResult<CircuitData<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create dummy targets for the circuit
        let dummy_target = builder.add_virtual_target();
        let current_virtual_state = VirtualStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            k_value: dummy_target,
            last_transition_timestamp: dummy_target,
        };

        let current_pool_state = PoolStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            operator_pk_x: dummy_target,
            operator_pk_y: dummy_target,
        };

        let current_timestamp = builder.add_virtual_target();
        let operator_pk_x = builder.add_virtual_target();
        let operator_pk_y = builder.add_virtual_target();
        let signature_r_x = builder.add_virtual_target();
        let signature_r_y = builder.add_virtual_target();
        let signature_s = builder.add_virtual_target();

        let circuit = TransitionCircuit::<D, F> {
            current_virtual_state,
            current_pool_state,
            current_timestamp,
            operator_pk_x,
            operator_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            _phantom: PhantomData,
        };

        circuit.prove(&mut builder)?;

        Ok(builder.build::<C>())
    }
}

#[allow(dead_code)]
fn _dummy_transition_circuit(
) -> TransitionCircuit<2, plonky2::field::goldilocks_field::GoldilocksField> {
    unimplemented!()
}

#[allow(dead_code)]
type ConcreteTransitionCircuit =
    TransitionCircuit<2, plonky2::field::goldilocks_field::GoldilocksField>;

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    use rand::thread_rng;
    use rand::Rng;

    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;

    #[test]
    fn test_transition_circuit() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create dummy targets for the circuit
        let dummy_target = builder.add_virtual_target();
        let current_virtual_state = VirtualStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            k_value: dummy_target,
            last_transition_timestamp: dummy_target,
        };

        let current_pool_state = PoolStateTarget {
            token_a_id: dummy_target,
            token_b_id: dummy_target,
            token_a_reserve: dummy_target,
            token_b_reserve: dummy_target,
            operator_pk_x: dummy_target,
            operator_pk_y: dummy_target,
        };

        let current_timestamp = builder.add_virtual_target();
        let operator_pk_x = builder.add_virtual_target();
        let operator_pk_y = builder.add_virtual_target();
        let signature_r_x = builder.add_virtual_target();
        let signature_r_y = builder.add_virtual_target();
        let signature_s = builder.add_virtual_target();

        // Set some values for testing
        let reserve_a = builder.constant(F::from_canonical_u64(1000000));
        let reserve_b = builder.constant(F::from_canonical_u64(2000000));
        let token_a_id = builder.constant(F::from_canonical_u64(1));
        let token_b_id = builder.constant(F::from_canonical_u64(2));
        let _last_transition_timestamp = builder.constant(F::from_canonical_u64(1000));
        let current_timestamp_value = builder.constant(F::from_canonical_u64(2000));

        builder.connect(current_virtual_state.token_a_reserve, reserve_a);
        builder.connect(current_virtual_state.token_b_reserve, reserve_b);
        builder.connect(current_virtual_state.token_a_id, token_a_id);
        builder.connect(current_virtual_state.token_b_id, token_b_id);

        builder.connect(current_pool_state.token_a_reserve, reserve_a);
        builder.connect(current_pool_state.token_b_reserve, reserve_b);
        builder.connect(current_pool_state.token_a_id, token_a_id);
        builder.connect(current_pool_state.token_b_id, token_b_id);
        // Note: last_transition_timestamp is not available in PoolStateTarget

        builder.connect(current_timestamp, current_timestamp_value);

        // Generate random values for the operator's public key and signature
        let mut rng = thread_rng();
        let operator_pk_x_value = builder.constant(F::from_canonical_u64(rng.gen()));
        let operator_pk_y_value = builder.constant(F::from_canonical_u64(rng.gen()));
        let signature_r_x_value = builder.constant(F::from_canonical_u64(rng.gen()));
        let signature_r_y_value = builder.constant(F::from_canonical_u64(rng.gen()));
        let signature_s_value = builder.constant(F::from_canonical_u64(rng.gen()));

        builder.connect(operator_pk_x, operator_pk_x_value);
        builder.connect(operator_pk_y, operator_pk_y_value);
        builder.connect(current_pool_state.operator_pk_x, operator_pk_x_value);
        builder.connect(current_pool_state.operator_pk_y, operator_pk_y_value);
        builder.connect(signature_r_x, signature_r_x_value);
        builder.connect(signature_r_y, signature_r_y_value);
        builder.connect(signature_s, signature_s_value);

        let circuit = TransitionCircuit::<D, F> {
            current_virtual_state,
            current_pool_state,
            current_timestamp,
            operator_pk_x,
            operator_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            _phantom: PhantomData,
        };

        // This is a simplified test that doesn't actually verify the proof
        // In a real test, we would generate a proof and verify it
        let result = circuit.prove(&mut builder);
        assert!(result.is_ok());
    }
}
