use env_logger::Env;
use log::error;
use clap::Parser;
use wire_lib;

mod cli;

fn main() {
    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();
    
    // Initialize the library
    wire_lib::init();
    
    // Parse command line arguments
    let cli = cli::Cli::parse();
    
    // Execute the command
    if let Err(e) = cli::execute_command(&cli) {
        error!("Error: {}", e);
        std::process::exit(1);
    }
}
