// Utility modules for the 0BTC Wire system
pub mod parallel_prover;
pub mod recursive_prover;
pub mod benchmarking;

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
