// MPC Operator CLI for 0BTC Wire
//
// This binary provides a command-line interface for MPC operators
// to manage distributed key generation, mint attestations, burn processing,
// and fee consolidation.

use wire_lib::mpc::{self, MPCConfig, MPCResult};
use std::process;

fn main() {
    // Initialize logging
    env_logger::init_from_env(
        env_logger::Env::default().filter_or(env_logger::DEFAULT_FILTER_ENV, "info")
    );
    
    // Run the MPC operator CLI
    if let Err(err) = run() {
        eprintln!("Error: {}", err);
        process::exit(1);
    }
}

fn run() -> MPCResult<()> {
    // Run the MPC operator CLI
    mpc::run_cli()
}
