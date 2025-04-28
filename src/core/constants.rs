// Constants for the 0BTC Wire system
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::extension::Extendable;

/// Standard recursion-friendly degree
pub const D: usize = 2;

/// Type alias for Plonky2 config
pub type C = PoseidonGoldilocksConfig;

/// Type alias for field type
pub type F = GoldilocksField;

/// Hash size in bytes
pub const HASH_SIZE: usize = 32;

/// Default fee for operations (in satoshis)
pub const DEFAULT_FEE: u64 = 1000;

/// Asset ID for wrapped Bitcoin (all zeros)
pub const WBTC_ASSET_ID: [u8; HASH_SIZE] = [0; HASH_SIZE];

/// Maximum supply for native assets
pub const MAX_NATIVE_ASSET_SUPPLY: u64 = u64::MAX;
