// 0BTC Wire Library
// Main library entry point

// Re-export all modules
pub mod circuits;
// Temporarily disable the cli module to focus on fixing core functionality
// pub mod cli;
pub mod core;
pub mod errors;
pub mod gadgets;
pub mod utils;

#[cfg(feature = "wasm")]
pub mod wasm;

// Re-export common types
pub use errors::{WireError, WireResult};

// Re-export CLI modules
// pub use cli::{
//     execute_command,
//     generate_keypair,
//     prove_circuit,
//     verify_proof,
//     aggregate_proofs_cli,
//     verify_aggregated_proof_cli,
//     // Advanced CLI features
//     config,
//     batch,
//     workflow,
//     commands,
//     advanced,
// };

use log::info;

/// Initialize the library with default configuration
pub fn init() {
    info!("Initializing 0BTC Wire library v{}", env!("CARGO_PKG_VERSION"));
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
