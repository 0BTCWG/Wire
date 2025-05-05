// Pool State Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::HASH_SIZE;

/// Represents a liquidity pool state
#[derive(Clone)]
pub struct PoolStateTarget {
    /// The pool ID (hash of tokenA_asset_id and tokenB_asset_id)
    pub pool_id: Vec<Target>,

    /// The asset ID of token A
    pub tokenA_asset_id: Vec<Target>,

    /// The asset ID of token B
    pub tokenB_asset_id: Vec<Target>,

    /// The reserve of token A
    pub reserveA: Target,

    /// The reserve of token B
    pub reserveB: Target,

    /// The total supply of LP tokens
    pub total_lp_shares: Target,

    /// For virtual CPMM: has the pool transitioned to standard CPMM?
    pub has_transitioned: Target,

    /// For virtual CPMM: the current supply of the native token
    pub current_supply: Target,

    /// For virtual CPMM: the target reserve for transition
    pub target_reserve: Target,
}

/// Represents an LP share token
#[derive(Clone)]
pub struct LPShareTarget {
    /// The pool ID this share belongs to
    pub pool_id: Vec<Target>,

    /// The owner of the LP share
    pub owner: Vec<Target>,

    /// The amount of LP shares
    pub amount: Target,
}

impl PoolStateTarget {
    /// Create a new pool state target
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            pool_id: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            tokenA_asset_id: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            tokenB_asset_id: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            reserveA: builder.add_virtual_target(),
            reserveB: builder.add_virtual_target(),
            total_lp_shares: builder.add_virtual_target(),
            has_transitioned: builder.add_virtual_target(),
            current_supply: builder.add_virtual_target(),
            target_reserve: builder.add_virtual_target(),
        }
    }

    /// Compute the commitment for the pool state
    pub fn compute_commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        // Concatenate all fields
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&self.pool_id);
        inputs.extend_from_slice(&self.tokenA_asset_id);
        inputs.extend_from_slice(&self.tokenB_asset_id);
        inputs.push(self.reserveA);
        inputs.push(self.reserveB);
        inputs.push(self.total_lp_shares);
        inputs.push(self.has_transitioned);
        inputs.push(self.current_supply);
        inputs.push(self.target_reserve);

        // Use the hash utility to compute a proper hash
        crate::utils::hash::compute_hash_targets(builder, &inputs)
    }
}

impl LPShareTarget {
    /// Create a new LP share target
    pub fn new<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        Self {
            pool_id: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            owner: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount: builder.add_virtual_target(),
        }
    }

    /// Compute the commitment for the LP share
    pub fn compute_commitment<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        // Concatenate all fields
        let mut inputs = Vec::new();
        inputs.extend_from_slice(&self.pool_id);
        inputs.extend_from_slice(&self.owner);
        inputs.push(self.amount);

        // Compute the hash
        let mut commitment = Vec::with_capacity(HASH_SIZE);
        for _ in 0..HASH_SIZE {
            commitment.push(builder.add_virtual_target());
        }

        // In a real implementation, this would use a proper hash function
        // For simplicity, we'll just use a mock hash
        for _i in 0..HASH_SIZE {
            let hash_bit = builder.add_virtual_target();
            commitment[_i] = hash_bit;
        }

        commitment
    }
}
