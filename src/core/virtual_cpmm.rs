// Virtual CPMM core types and structures
//
// This module defines the core data structures for the Virtual CPMM system,
// including the VirtualStateTarget and PoolStateTarget.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use serde::{Deserialize, Serialize};

/// Target representation of a virtual state in the CPMM
#[derive(Debug, Clone)]
pub struct VirtualStateTarget {
    /// The asset ID of token A
    pub token_a_id: Target,

    /// The asset ID of token B
    pub token_b_id: Target,

    /// The virtual reserve of token A
    pub token_a_reserve: Target,

    /// The virtual reserve of token B
    pub token_b_reserve: Target,

    /// The constant product value (k = x * y)
    pub k_value: Target,

    /// Timestamp of the last transition to actual pool state
    pub last_transition_timestamp: Target,
}

/// Target representation of an actual pool state in the CPMM
#[derive(Debug, Clone)]
pub struct PoolStateTarget {
    /// The asset ID of token A
    pub token_a_id: Target,

    /// The asset ID of token B
    pub token_b_id: Target,

    /// The actual reserve of token A
    pub token_a_reserve: Target,

    /// The actual reserve of token B
    pub token_b_reserve: Target,

    /// The operator's public key X coordinate
    pub operator_pk_x: Target,

    /// The operator's public key Y coordinate
    pub operator_pk_y: Target,
}

/// Native representation of a virtual state in the CPMM
#[derive(Debug, Clone, Serialize)]
pub struct VirtualState<F: RichField> {
    /// The asset ID of token A
    pub token_a_id: F,

    /// The asset ID of token B
    pub token_b_id: F,

    /// The virtual reserve of token A
    pub token_a_reserve: F,

    /// The virtual reserve of token B
    pub token_b_reserve: F,

    /// The constant product value (k = x * y)
    pub k_value: F,

    /// Timestamp of the last transition to actual pool state
    pub last_transition_timestamp: F,
}

/// Native representation of an actual pool state in the CPMM
#[derive(Debug, Clone, Serialize)]
pub struct PoolState<F: RichField> {
    /// The asset ID of token A
    pub token_a_id: F,

    /// The asset ID of token B
    pub token_b_id: F,

    /// The actual reserve of token A
    pub token_a_reserve: F,

    /// The actual reserve of token B
    pub token_b_reserve: F,

    /// The operator's public key X coordinate
    pub operator_pk_x: F,

    /// The operator's public key Y coordinate
    pub operator_pk_y: F,
}

impl<F: RichField + Extendable<D>, const D: usize> VirtualState<F> {
    /// Convert a native VirtualState to a VirtualStateTarget
    pub fn to_target(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> VirtualStateTarget {
        VirtualStateTarget {
            token_a_id: builder.constant(self.token_a_id),
            token_b_id: builder.constant(self.token_b_id),
            token_a_reserve: builder.constant(self.token_a_reserve),
            token_b_reserve: builder.constant(self.token_b_reserve),
            k_value: builder.constant(self.k_value),
            last_transition_timestamp: builder.constant(self.last_transition_timestamp),
        }
    }
}

impl<F: RichField + Extendable<D>, const D: usize> PoolState<F> {
    /// Convert a native PoolState to a PoolStateTarget
    pub fn to_target(
        &self,
        builder: &mut plonky2::plonk::circuit_builder::CircuitBuilder<F, D>,
    ) -> PoolStateTarget {
        PoolStateTarget {
            token_a_id: builder.constant(self.token_a_id),
            token_b_id: builder.constant(self.token_b_id),
            token_a_reserve: builder.constant(self.token_a_reserve),
            token_b_reserve: builder.constant(self.token_b_reserve),
            operator_pk_x: builder.constant(self.operator_pk_x),
            operator_pk_y: builder.constant(self.operator_pk_y),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;

    type F = GoldilocksField;
    const D: usize = 2;

    #[test]
    fn test_virtual_state_to_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let virtual_state = VirtualState {
            token_a_id: F::from_canonical_u64(1),
            token_b_id: F::from_canonical_u64(2),
            token_a_reserve: F::from_canonical_u64(1000),
            token_b_reserve: F::from_canonical_u64(2000),
            k_value: F::from_canonical_u64(2000000),
            last_transition_timestamp: F::from_canonical_u64(12345),
        };

        let target = virtual_state.to_target(&mut builder);

        // This is just a structure test
        assert!(target.token_a_id != target.token_b_id);
    }

    #[test]
    fn test_pool_state_to_target() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let pool_state = PoolState {
            token_a_id: F::from_canonical_u64(1),
            token_b_id: F::from_canonical_u64(2),
            token_a_reserve: F::from_canonical_u64(1000),
            token_b_reserve: F::from_canonical_u64(2000),
            operator_pk_x: F::from_canonical_u64(1234),
            operator_pk_y: F::from_canonical_u64(5678),
        };

        let target = pool_state.to_target(&mut builder);

        // This is just a structure test
        assert!(target.token_a_id != target.token_b_id);
    }
}
