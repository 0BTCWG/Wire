// Utility modules for the 0BTC Wire system
pub mod parallel_prover;
pub mod recursive_prover;
pub mod memory_efficient;
pub mod field;
pub mod hash;
pub mod signature;
pub mod merkle;
pub mod nullifier;
pub mod benchmarking;

// Re-export utility modules
pub use recursive_prover::{aggregate_proofs, verify_aggregated_proof, RecursiveProverOptions, RecursiveProofResult};

pub use parallel_prover::{generate_proofs_in_parallel, verify_proofs_in_parallel, ParallelProverOptions};

pub use memory_efficient::{
    generate_proof_memory_efficient,
    verify_proof_memory_efficient,
    estimate_memory_requirements,
    configure_memory_efficient_options,
    MemoryEfficientOptions,
    MemoryEstimate,
};

pub use benchmarking::{
    benchmark_circuit,
    benchmark_circuit_builder,
    run_benchmark_suite,
    save_benchmark_results,
    save_benchmark_results_csv,
    BenchmarkConfig,
    BenchmarkResult,
    BenchmarkSuiteResult,
};
