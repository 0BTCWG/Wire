// Gadget modules for the 0BTC Wire system
pub mod arithmetic;
pub mod fee;
pub mod fixed_point;
pub mod hash;
pub mod merkle;
pub mod nullifier;
pub mod signature;
pub mod specialized;

// Re-export commonly used gadgets
pub use arithmetic::{add, div, eq, gt, gte, lt, lte, mul, sub};
pub use fee::{calculate_fee, verify_fee_payment};
pub use fixed_point::{
    fixed_abs, fixed_add, fixed_ceil, fixed_div, fixed_floor, fixed_in_range, fixed_max, fixed_min,
    fixed_mul, fixed_pow, fixed_round, fixed_sqrt, fixed_sub, from_fixed_point, to_fixed_point,
    FIXED_POINT_SCALING_FACTOR,
};
pub use hash::{hash, hash_n};
pub use merkle::{assert_merkle_proof, verify_merkle_proof};
pub use nullifier::{calculate_and_register_nullifier, calculate_nullifier};
pub use signature::{batch_verify_signatures, verify_message_signature};
pub use specialized::{
    batch_equality_check, batch_hash_with_domain, conditional_select, range_check,
    vector_dot_product, vector_sum,
};
