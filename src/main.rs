use clap::{Parser, Subcommand};
use env_logger::Env;
use log::{info, error};
use wire_lib;

mod cli;

#[derive(Parser)]
#[command(name = "wire")]
#[command(about = "0BTC Wire - Zero-Knowledge UTXO System", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new keypair
    KeyGen {
        /// Output file for the keypair
        #[arg(short, long)]
        output: Option<String>,
    },
    /// Prove a circuit
    Prove {
        /// Type of circuit to prove
        #[arg(short, long)]
        circuit: String,
        
        /// Input file with circuit parameters
        #[arg(short, long)]
        input: String,
        
        /// Output file for the proof
        #[arg(short, long)]
        output: String,
    },
    /// Verify a proof
    Verify {
        /// Type of circuit to verify
        #[arg(short, long)]
        circuit: String,
        
        /// Input file with the proof
        #[arg(short, long)]
        proof: String,
    },
}

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    // Initialize the library
    wire_lib::init();
    
    // Parse command line arguments
    let cli = Cli::parse();
    
    // Execute the command
    if let Err(e) = cli::execute_command(&cli) {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}
