// Utility modules for the 0BTC Wire system

pub mod field;
pub mod hash;
pub mod parallel_prover;
// Temporarily disable the recursive_prover module to focus on fixing core functionality
// pub mod recursive_prover;
pub mod compare;
pub mod constants;
pub mod merkle;
pub mod nullifier;
pub mod signature;
pub mod wallet;
// Temporarily disable the memory_efficient module to focus on fixing core functionality
// pub mod memory_efficient;

#[cfg(test)]
pub mod tests;

// Re-export utility modules
// Temporarily disable re-exports from recursive_prover
// pub use recursive_prover::{aggregate_proofs, verify_aggregated_proof, RecursiveProverOptions, RecursiveProofResult};

pub use parallel_prover::{
    generate_proofs_in_parallel, verify_proofs_in_parallel, ParallelProofResult,
    ParallelProverOptions,
};

pub use constants::*;

// Define a simple MemoryEstimate struct to avoid import errors
pub struct MemoryEstimate {
    pub total_bytes: usize,
    pub witness_bytes: usize,
    pub proof_bytes: usize,
}

use std::fs::File;
use std::io::BufReader;
use std::path::Path;
use serde::de::DeserializeOwned;
use crate::errors::{WireError, WireResult, IOError};

/// Load a JSON file and deserialize it into the specified type
pub fn load_json_file<T: DeserializeOwned, P: AsRef<Path>>(path: P) -> WireResult<T> {
    let file = File::open(path).map_err(|e| WireError::IOError(IOError::FileSystem(e.to_string())))?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| WireError::IOError(IOError::DeserializationError(e.to_string())))
}
