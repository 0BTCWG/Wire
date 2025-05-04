// Constants for the Virtual CPMM system
use plonky2::field::types::Field;

/// Scaling factor for fixed-point arithmetic (6 decimal places)
pub const SCALING_FACTOR: u64 = 1_000_000;

/// Domain separator for BuyTokenCircuit
pub const DOMAIN_BUY_TOKEN: &str = "WIRE_VCPMM_BUY_TOKEN_V1";

/// Domain separator for SellTokenCircuit
pub const DOMAIN_SELL_TOKEN: &str = "WIRE_VCPMM_SELL_TOKEN_V1";

/// Domain separator for TransitionCircuit
pub const DOMAIN_TRANSITION: &str = "WIRE_VCPMM_TRANSITION_V1";

/// Minimum interval between transitions (in seconds)
pub const MIN_TRANSITION_INTERVAL: u64 = 3600; // 1 hour

/// Maximum allowed slippage percentage (in basis points, 1% = 100 basis points)
pub const MAX_SLIPPAGE_BPS: u64 = 500; // 5%

/// Minimum liquidity required to remain in the pool (in scaled units)
pub const MIN_LIQUIDITY: u64 = SCALING_FACTOR; // 1.0 in fixed-point

/// Maximum allowed deviation between virtual and actual reserves (in basis points)
pub const MAX_VIRTUAL_DEVIATION_BPS: u64 = 1000; // 10%

/// Fee percentage charged on swaps (in basis points)
pub const SWAP_FEE_BPS: u64 = 30; // 0.3%
