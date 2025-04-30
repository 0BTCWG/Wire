// 0BTC Wire - Zero-Knowledge UTXO System
//
// This library implements Plonky2 circuits for a UTXO-based cryptocurrency
// platform with support for wrapped Bitcoin, token transfers, and native assets.

pub mod core;
pub mod gadgets;
pub mod circuits;
pub mod wasm;
pub mod utils;
pub mod errors;
pub mod tests {
    pub mod fuzz_tests;
}

// Re-export CLI modules
pub mod cli;
pub use cli::{
    execute_command,
    generate_keypair,
    prove_circuit,
    verify_proof,
    aggregate_proofs_cli,
    verify_aggregated_proof_cli,
    // Advanced CLI features
    config,
    batch,
    workflow,
    commands,
    advanced,
};

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
