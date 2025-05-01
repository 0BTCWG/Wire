// CLI module for MPC operations
//
// This module provides command-line interface functionality for MPC operators.

use crate::mpc::{MPCConfig, MPCCore, MPCError, MPCResult};
use crate::mpc::ceremonies::{DKGCeremony, SigningCeremony, CeremonyStatus};
use crate::mpc::bitcoin::{DepositMonitor, WithdrawalProcessor};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// MPC operator command-line interface
#[derive(Parser, Debug)]
#[clap(name = "mpc-operator", about = "MPC operator tooling for 0BTC Wire")]
pub struct Cli {
    /// Configuration file
    #[clap(short, long, value_parser)]
    config: Option<PathBuf>,
    
    /// Subcommand
    #[clap(subcommand)]
    command: Commands,
}

/// MPC operator subcommands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Initialize the MPC operator
    Init {
        /// Number of parties
        #[clap(short, long, value_parser, default_value = "3")]
        parties: usize,
        
        /// Threshold
        #[clap(short, long, value_parser, default_value = "2")]
        threshold: usize,
        
        /// Party index (0-based)
        #[clap(short, long, value_parser)]
        index: usize,
        
        /// Party addresses
        #[clap(short, long, value_parser, num_args = 1..)]
        addresses: Vec<String>,
        
        /// Output configuration file
        #[clap(short, long, value_parser)]
        output: PathBuf,
    },
    
    /// Perform distributed key generation (DKG)
    Dkg {
        /// Ceremony ID (optional, will be generated if not provided)
        #[clap(short, long, value_parser)]
        ceremony_id: Option<String>,
    },
    
    /// Generate a mint attestation
    Attest {
        /// Bitcoin transaction ID
        #[clap(short, long, value_parser)]
        txid: String,
        
        /// Output index
        #[clap(short, long, value_parser, default_value = "0")]
        vout: u32,
        
        /// Recipient's public key hash
        #[clap(short, long, value_parser)]
        recipient: String,
        
        /// Amount in satoshis
        #[clap(short, long, value_parser)]
        amount: u64,
    },
    
    /// Process a burn proof and initiate a withdrawal
    Withdraw {
        /// Burn transaction ID
        #[clap(short, long, value_parser)]
        burn_txid: String,
        
        /// Bitcoin address for withdrawal
        #[clap(short, long, value_parser)]
        address: String,
        
        /// Amount in satoshis
        #[clap(short, long, value_parser)]
        amount: u64,
        
        /// Fee in satoshis
        #[clap(short, long, value_parser, default_value = "1000")]
        fee: u64,
    },
    
    /// Consolidate fees from the fee reservoir
    ConsolidateFees {
        /// Destination address
        #[clap(short, long, value_parser)]
        address: String,
    },
    
    /// Monitor Bitcoin deposits
    MonitorDeposits {
        /// Required confirmations
        #[clap(short, long, value_parser, default_value = "6")]
        confirmations: u32,
        
        /// Interval in seconds
        #[clap(short, long, value_parser, default_value = "300")]
        interval: u64,
    },
    
    /// Process pending withdrawals
    ProcessWithdrawals {
        /// Interval in seconds
        #[clap(short, long, value_parser, default_value = "300")]
        interval: u64,
    },
}

/// Run the MPC operator CLI
pub fn run_cli() -> MPCResult<()> {
    let cli = Cli::parse();
    
    // Load configuration if provided
    let config = if let Some(config_path) = cli.config.as_ref() {
        load_config(config_path)?
    } else {
        // Default configuration
        MPCConfig {
            parties: 3,
            threshold: 2,
            party_addresses: vec![
                "localhost:50051".to_string(),
                "localhost:50052".to_string(),
                "localhost:50053".to_string(),
            ],
            my_index: 0,
            key_share_path: "key_share.json".to_string(),
            tls_cert_path: "tls/cert.pem".to_string(),
            tls_key_path: "tls/key.pem".to_string(),
        }
    };
    
    // Initialize MPC core
    let mpc_core = MPCCore::new(config.clone())?;
    
    // Process command
    match &cli.command {
        Commands::Init { parties, threshold, index, addresses, output } => {
            cmd_init(*parties, *threshold, *index, addresses.clone(), output)?;
        }
        Commands::Dkg { ceremony_id } => {
            cmd_dkg(&mpc_core, ceremony_id.clone())?;
        }
        Commands::Attest { txid, vout, recipient, amount } => {
            cmd_attest(&mpc_core, txid, *vout, recipient, *amount)?;
        }
        Commands::Withdraw { burn_txid, address, amount, fee } => {
            cmd_withdraw(&mpc_core, burn_txid, address, *amount, *fee)?;
        }
        Commands::ConsolidateFees { address } => {
            cmd_consolidate_fees(&mpc_core, address)?;
        }
        Commands::MonitorDeposits { confirmations, interval } => {
            cmd_monitor_deposits(&mpc_core, *confirmations, *interval)?;
        }
        Commands::ProcessWithdrawals { interval } => {
            cmd_process_withdrawals(&mpc_core, *interval)?;
        }
    }
    
    Ok(())
}

/// Load MPC configuration from a file
fn load_config(path: &PathBuf) -> MPCResult<MPCConfig> {
    let config_str = std::fs::read_to_string(path)
        .map_err(|e| MPCError::InternalError(format!("Failed to read config file: {}", e)))?;
    
    let config: MPCConfig = serde_json::from_str(&config_str)
        .map_err(|e| MPCError::InternalError(format!("Failed to parse config file: {}", e)))?;
    
    Ok(config)
}

/// Save MPC configuration to a file
fn save_config(config: &MPCConfig, path: &PathBuf) -> MPCResult<()> {
    let config_str = serde_json::to_string_pretty(config)
        .map_err(|e| MPCError::InternalError(format!("Failed to serialize config: {}", e)))?;
    
    std::fs::write(path, config_str)
        .map_err(|e| MPCError::InternalError(format!("Failed to write config file: {}", e)))?;
    
    Ok(())
}

/// Initialize the MPC operator
fn cmd_init(
    parties: usize,
    threshold: usize,
    index: usize,
    addresses: Vec<String>,
    output: &PathBuf,
) -> MPCResult<()> {
    if index >= parties {
        return Err(MPCError::InternalError(format!(
            "Invalid party index: {} (must be less than {})",
            index, parties
        )));
    }
    
    if addresses.len() != parties {
        return Err(MPCError::InternalError(format!(
            "Invalid number of addresses: {} (expected {})",
            addresses.len(), parties
        )));
    }
    
    if threshold > parties {
        return Err(MPCError::InternalError(format!(
            "Invalid threshold: {} (must be less than or equal to {})",
            threshold, parties
        )));
    }
    
    // Create TLS directory if it doesn't exist
    std::fs::create_dir_all("tls")
        .map_err(|e| MPCError::InternalError(format!("Failed to create TLS directory: {}", e)))?;
    
    // Create configuration
    let config = MPCConfig {
        parties,
        threshold,
        party_addresses: addresses,
        my_index: index,
        key_share_path: "key_share.json".to_string(),
        tls_cert_path: "tls/cert.pem".to_string(),
        tls_key_path: "tls/key.pem".to_string(),
    };
    
    // Save configuration
    save_config(&config, output)?;
    
    println!("MPC operator initialized successfully");
    println!("Configuration saved to: {}", output.display());
    
    Ok(())
}

/// Perform distributed key generation (DKG)
fn cmd_dkg(mpc_core: &MPCCore, ceremony_id: Option<String>) -> MPCResult<()> {
    let ceremony_id = ceremony_id.unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    
    println!("Starting DKG ceremony: {}", ceremony_id);
    
    // Create DKG ceremony
    let mut ceremony = DKGCeremony::new(
        mpc_core.clone(),
        mpc_core.config.parties,
        mpc_core.config.threshold,
    );
    
    // Start ceremony
    ceremony.start()?;
    
    // Generate and broadcast commitments
    println!("Generating commitments...");
    let _commitments = ceremony.generate_commitments()?;
    
    // Wait for commitments from other parties
    println!("Waiting for commitments from other parties...");
    // In a real implementation, this would wait for commitments from other parties
    
    // Generate and distribute shares
    println!("Generating shares...");
    let _shares = ceremony.generate_shares()?;
    
    // Wait for shares from other parties
    println!("Waiting for shares from other parties...");
    // In a real implementation, this would wait for shares from other parties
    
    // Compute key share
    println!("Computing key share...");
    let (_key_share, _public_key) = ceremony.compute_key_share()?;
    
    // Save key share
    println!("Saving key share...");
    mpc_core.save_key_share()?;
    
    println!("DKG ceremony completed successfully");
    
    Ok(())
}

/// Generate a mint attestation
fn cmd_attest(
    mpc_core: &MPCCore,
    txid: &str,
    vout: u32,
    recipient: &str,
    amount: u64,
) -> MPCResult<()> {
    println!("Generating attestation for deposit:");
    println!("  Transaction ID: {}", txid);
    println!("  Output Index: {}", vout);
    println!("  Recipient: {}", recipient);
    println!("  Amount: {} satoshis", amount);
    
    // Parse recipient public key hash
    let recipient_pubkey_hash = hex::decode(recipient)
        .map_err(|e| MPCError::InternalError(format!("Invalid recipient public key hash: {}", e)))?;
    
    if recipient_pubkey_hash.len() != 32 {
        return Err(MPCError::InternalError(format!(
            "Invalid recipient public key hash length: {} (expected 32)",
            recipient_pubkey_hash.len()
        )));
    }
    
    // Create message to sign
    let mut message = Vec::new();
    message.extend_from_slice(txid.as_bytes());
    message.extend_from_slice(&vout.to_le_bytes());
    message.extend_from_slice(&recipient_pubkey_hash);
    message.extend_from_slice(&amount.to_le_bytes());
    
    // Create signing ceremony
    let mut ceremony = SigningCeremony::new(
        mpc_core.clone(),
        message,
        mpc_core.config.parties,
        mpc_core.config.threshold,
    );
    
    // Start ceremony
    ceremony.start()?;
    
    // Generate signature share
    println!("Generating signature share...");
    let _signature_share = ceremony.generate_signature_share()?;
    
    // Wait for signature shares from other parties
    println!("Waiting for signature shares from other parties...");
    // In a real implementation, this would wait for signature shares from other parties
    
    // Combine signature shares
    println!("Combining signature shares...");
    let _signature = ceremony.combine_signature_shares()?;
    
    println!("Attestation generated successfully");
    
    Ok(())
}

/// Process a burn proof and initiate a withdrawal
fn cmd_withdraw(
    mpc_core: &MPCCore,
    burn_txid: &str,
    address: &str,
    amount: u64,
    fee: u64,
) -> MPCResult<()> {
    println!("Processing withdrawal:");
    println!("  Burn Transaction ID: {}", burn_txid);
    println!("  Bitcoin Address: {}", address);
    println!("  Amount: {} satoshis", amount);
    println!("  Fee: {} satoshis", fee);
    
    // Create withdrawal processor
    let mut processor = WithdrawalProcessor::new(
        mpc_core.clone(),
        "http://localhost:8332".to_string(),
        "user".to_string(),
        "password".to_string(),
    );
    
    // Create withdrawal
    let withdrawal = processor.create_withdrawal(
        burn_txid.to_string(),
        amount,
        address.to_string(),
        fee,
    )?;
    
    println!("Withdrawal created with ID: {}", withdrawal.id);
    
    // Process withdrawal
    processor.process_pending_withdrawals()?;
    
    println!("Withdrawal processed successfully");
    
    Ok(())
}

/// Consolidate fees from the fee reservoir
fn cmd_consolidate_fees(mpc_core: &MPCCore, address: &str) -> MPCResult<()> {
    println!("Consolidating fees to address: {}", address);
    
    // Parse the destination address
    let address_bytes = match hex::decode(address) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        },
        Ok(_) => return Err(MPCError::InternalError(
            "Address must be a 32-byte hex string".to_string()
        )),
        Err(e) => return Err(MPCError::InternalError(
            format!("Failed to parse address: {}", e)
        )),
    };
    
    // Create a fee manager
    let mut fee_manager = crate::mpc::fee::FeeManager::new(
        mpc_core.clone(),
        "fee_database.json".to_string(),
        [0u8; 32], // This would be the actual fee reservoir address in a real implementation
        1_000_000, // 0.01 BTC minimum consolidation amount
        10,        // Maximum 10 UTXOs per consolidation
    )?;
    
    // Scan for UTXOs
    println!("Scanning for UTXOs in the fee reservoir...");
    let new_utxos = fee_manager.scan_for_utxos()?;
    println!("Found {} new UTXOs", new_utxos.len());
    
    // Get available UTXOs
    let available_utxos = fee_manager.get_available_utxos();
    println!("Found {} available UTXOs for consolidation", available_utxos.len());
    
    if available_utxos.is_empty() {
        println!("No UTXOs available for consolidation");
        return Ok(());
    }
    
    // Calculate total amount
    let total_amount: u64 = available_utxos.iter().map(|u| u.amount).sum();
    println!("Total amount available for consolidation: {} satoshis", total_amount);
    
    // Create consolidation
    println!("Creating consolidation transaction...");
    let consolidation = fee_manager.create_consolidation(address_bytes)?;
    println!("Created consolidation: {}", consolidation.id);
    
    // Generate proof
    println!("Generating consolidation proof...");
    let proof = fee_manager.generate_consolidation_proof(&consolidation.id)?;
    println!("Generated proof: {} bytes", proof.len());
    
    // Complete consolidation
    println!("Completing consolidation...");
    fee_manager.complete_consolidation(&consolidation.id)?;
    
    println!("Fees consolidated successfully");
    println!("Consolidation ID: {}", consolidation.id);
    println!("Total amount: {} satoshis", consolidation.total_amount);
    println!("Number of UTXOs: {}", consolidation.input_utxos.len());
    
    Ok(())
}

/// Monitor Bitcoin deposits
fn cmd_monitor_deposits(
    mpc_core: &MPCCore,
    confirmations: u32,
    interval: u64,
) -> MPCResult<()> {
    println!("Starting deposit monitor:");
    println!("  Required Confirmations: {}", confirmations);
    println!("  Interval: {} seconds", interval);
    
    // Create deposit monitor
    let mut monitor = DepositMonitor::new(
        mpc_core.clone(),
        "http://localhost:8332".to_string(),
        "user".to_string(),
        "password".to_string(),
        confirmations,
    );
    
    // Run monitor loop
    loop {
        println!("Scanning for new deposits...");
        let new_deposits = monitor.scan_for_deposits()?;
        
        if !new_deposits.is_empty() {
            println!("Found {} new deposits", new_deposits.len());
        }
        
        println!("Updating confirmations...");
        let updated_deposits = monitor.update_confirmations()?;
        
        if !updated_deposits.is_empty() {
            println!("Updated {} deposits", updated_deposits.len());
        }
        
        let deposits_for_attestation = monitor.get_deposits_for_attestation();
        
        if !deposits_for_attestation.is_empty() {
            println!("Found {} deposits ready for attestation", deposits_for_attestation.len());
            
            for deposit in deposits_for_attestation {
                println!("Generating attestation for deposit: {}", deposit.txid);
                
                // In a real implementation, this would:
                // 1. Create a signing ceremony for the attestation
                // 2. Participate in the ceremony
                // 3. Mark the deposit as attested
                
                monitor.mark_deposit_attested(&deposit.txid)?;
            }
        }
        
        println!("Sleeping for {} seconds...", interval);
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}

/// Process pending withdrawals
fn cmd_process_withdrawals(
    mpc_core: &MPCCore,
    interval: u64,
) -> MPCResult<()> {
    println!("Starting withdrawal processor:");
    println!("  Interval: {} seconds", interval);
    
    // Create withdrawal processor
    let mut processor = WithdrawalProcessor::new(
        mpc_core.clone(),
        "http://localhost:8332".to_string(),
        "user".to_string(),
        "password".to_string(),
    );
    
    // Run processor loop
    loop {
        println!("Processing pending withdrawals...");
        let processed = processor.process_pending_withdrawals()?;
        
        if !processed.is_empty() {
            println!("Processed {} withdrawals", processed.len());
        }
        
        println!("Updating withdrawal status...");
        let updated = processor.update_withdrawal_status()?;
        
        if !updated.is_empty() {
            println!("Updated {} withdrawals", updated.len());
        }
        
        println!("Sleeping for {} seconds...", interval);
        std::thread::sleep(std::time::Duration::from_secs(interval));
    }
}
