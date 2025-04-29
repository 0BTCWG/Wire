// Constants for the 0BTC Wire system
use plonky2::hash::hash_types::NUM_HASH_OUT_ELTS;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::field::goldilocks_field::GoldilocksField;

/// Standard recursion-friendly degree
pub const D: usize = 2;

/// Type alias for Plonky2 config
pub type C = PoseidonGoldilocksConfig;

/// Type alias for field type
pub type F = GoldilocksField;

/// Size of hash outputs
pub const HASH_SIZE: usize = NUM_HASH_OUT_ELTS;

/// Default fee for operations (in satoshis)
pub const DEFAULT_FEE: u64 = 1000;

/// Asset ID for wrapped Bitcoin (all zeros)
pub const WBTC_ASSET_ID: [u8; HASH_SIZE] = [0; HASH_SIZE];
