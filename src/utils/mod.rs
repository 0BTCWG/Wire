// Utility modules for the 0BTC Wire system

pub mod field;
pub mod hash;
pub mod parallel_prover;
// Temporarily disable the recursive_prover module to focus on fixing core functionality
// pub mod recursive_prover;
pub mod signature;
pub mod merkle;
pub mod nullifier;
// Temporarily disable the memory_efficient module to focus on fixing core functionality
// pub mod memory_efficient;

// Re-export utility modules
// Temporarily disable re-exports from recursive_prover
// pub use recursive_prover::{aggregate_proofs, verify_aggregated_proof, RecursiveProverOptions, RecursiveProofResult};

pub use parallel_prover::{
    verify_proofs_in_parallel,
    generate_proofs_in_parallel,
    ParallelProverOptions,
    ParallelProofResult,
};

// Define a simple MemoryEstimate struct to avoid import errors
pub struct MemoryEstimate {
    pub total_bytes: usize,
    pub witness_bytes: usize,
    pub proof_bytes: usize,
}

// Temporarily disable re-exports from memory_efficient
// pub use memory_efficient::{
//     generate_proof_memory_efficient,
//     verify_proof_memory_efficient,
//     estimate_memory_requirements,
//     MemoryEstimate,
// };

// Temporarily disable the benchmarking module to focus on fixing core functionality
// pub mod benchmarking;
// pub use benchmarking::{
//     benchmark_circuit,
//     benchmark_circuit_builder,
//     run_benchmark_suite,
//     save_benchmark_results,
//     save_benchmark_results_csv,
//     BenchmarkConfig,
//     BenchmarkResult,
//     BenchmarkSuiteResult,
// };
