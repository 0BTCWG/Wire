// Utility modules for the 0BTC Wire system
pub mod parallel_prover;
pub mod recursive_prover;

// Re-export commonly used utilities
pub use parallel_prover::{
    generate_proofs_in_parallel,
    generate_proofs_for_circuit,
    verify_proofs_in_parallel,
    ParallelProverOptions,
};

pub use recursive_prover::{
    aggregate_proofs,
    verify_aggregated_proof,
    RecursiveProverOptions,
};
