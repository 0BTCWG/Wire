// Gadget modules for the 0BTC Wire system
pub mod hash;
pub mod signature;
pub mod merkle;
pub mod nullifier;
pub mod arithmetic;
pub mod fee;
pub mod specialized;

// Re-export commonly used gadgets
pub use hash::{hash, hash_n};
pub use signature::{verify_message_signature, batch_verify_signatures};
pub use merkle::{verify_merkle_proof, assert_merkle_proof};
pub use nullifier::{calculate_nullifier, calculate_and_register_nullifier};
pub use arithmetic::{add, sub, mul, div, eq, lt, lte, gt, gte};
pub use fee::{calculate_fee, verify_fee_payment};
pub use specialized::{
    range_check,
    batch_hash_with_domain,
    batch_equality_check,
    conditional_select,
    vector_dot_product,
    vector_sum,
};
