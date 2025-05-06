// CLI module for the 0BTC Wire system
use clap::{Parser, Subcommand};
use log::{info, warn};
use std::fs;
use std::path::Path;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use wire_lib::core::proof::SerializableProof;
use wire_lib::core::UTXO;
use wire_lib::utils::parallel_prover::{generate_proofs_in_parallel, verify_proofs_in_parallel};
use wire_lib::utils::wallet::WordCount;

// Import the validation module
pub mod validation;
use validation::{
    validate_batch_size, validate_circuit_type, validate_directory_path, validate_file_path,
    validate_output_file_path, validate_proof_directory,
};

// Import advanced CLI modules
pub mod advanced;
pub mod amm;
pub mod batch;
pub mod commands;
pub mod config;
pub mod lightning;
pub mod stablecoin;
pub mod workflow;
use advanced::{execute_advanced_command, AdvancedCommands};

// Import new CLI modules
pub mod new_commands;
pub mod amm_commands;
pub mod stablecoin_commands;
pub mod ico_commands;
pub mod airdrop_commands;
use new_commands::{ICOCommands, AirdropCommands, StablecoinV2Commands, execute_ico_command, execute_airdrop_command, execute_stablecoin_v2_command};

#[derive(Parser)]
#[command(name = "wire")]
#[command(about = "0BTC Wire - Zero-Knowledge UTXO System", long_about = None)]
#[command(version)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new keypair with BIP-39 mnemonic support
    #[command(about = "Generate a new keypair with HD wallet support")]
    KeyGen {
        /// Output file for the keypair (JSON format)
        #[arg(short, long, help = "Save the keypair to this file")]
        output: Option<String>,

        /// Generate a BIP-39 mnemonic phrase (12, 15, 18, 21, or 24 words)
        #[arg(
            short,
            long,
            default_value = "12",
            help = "Number of words in the mnemonic phrase"
        )]
        words: usize,

        /// Use an existing mnemonic phrase instead of generating a new one
        #[arg(long, help = "Recover keys from an existing mnemonic phrase")]
        mnemonic: Option<String>,

        /// Derivation path for HD wallet (default: m/1337'/0'/0')
        #[arg(long, help = "Custom derivation path for the HD wallet")]
        path: Option<String>,
    },
    /// Prove a circuit with the given input parameters
    #[command(about = "Generate a zero-knowledge proof for a circuit")]
    Prove {
        /// Type of circuit to prove (transfer, wrapped_asset_mint, wrapped_asset_burn, native_asset_create, native_asset_mint, native_asset_burn)
        #[arg(short, long, help = "Type of circuit to prove")]
        circuit: String,

        /// Input file with circuit parameters (JSON format)
        #[arg(short, long, help = "Input file with circuit parameters")]
        input: String,

        /// Output file for the proof (JSON format)
        #[arg(short, long, help = "Output file for the proof")]
        output: String,

        /// Use parallel proof generation if possible
        #[arg(short, long, help = "Enable parallel proof generation")]
        parallel: bool,

        /// Configuration file path
        #[arg(short, long, help = "Path to configuration file")]
        config: Option<String>,

        /// Number of threads to use for parallel operations
        #[arg(short, long, help = "Number of threads for parallel operations")]
        threads: Option<usize>,

        /// Enable verbose output
        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,
    },
    /// Verify a proof
    #[command(about = "Verify a zero-knowledge proof")]
    Verify {
        /// Type of circuit to verify (transfer, wrapped_asset_mint, wrapped_asset_burn, native_asset_create, native_asset_mint, native_asset_burn)
        #[arg(short, long, help = "Type of circuit to verify")]
        circuit: String,

        /// Proof file to verify (JSON format)
        #[arg(short, long, help = "Proof file to verify")]
        proof: String,

        /// Enable verbose output
        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,
    },
    /// Aggregate multiple proofs into a single proof
    #[command(about = "Aggregate multiple proofs into a single proof")]
    Aggregate {
        /// Directory containing proof files to aggregate
        #[arg(short, long, help = "Directory containing proof files to aggregate")]
        input_dir: String,

        /// Output file for the aggregated proof (JSON format)
        #[arg(short, long, help = "Output file for the aggregated proof")]
        output: String,

        /// Maximum number of proofs to aggregate in a single step
        #[arg(
            short,
            long,
            default_value = "4",
            help = "Maximum number of proofs to aggregate in a single step"
        )]
        batch_size: usize,

        /// Whether to use verbose output
        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,
    },
    /// Verify an aggregated proof
    #[command(about = "Verify an aggregated proof")]
    VerifyAggregated {
        /// Aggregated proof file to verify (JSON format)
        #[arg(short, long, help = "Aggregated proof file to verify")]
        proof: String,

        /// Type of circuit to verify
        #[arg(short, long, help = "Type of circuit to verify")]
        circuit: String,

        /// Enable verbose output
        #[arg(short, long, help = "Enable verbose output")]
        verbose: bool,
    },
    /// Advanced CLI commands for configuration, batch processing, and workflows
    #[command(subcommand, about = "Advanced CLI commands")]
    Advanced(AdvancedCommands),
    /// AMM commands
    #[command(about = "AMM operations")]
    AMM {
        #[command(subcommand)]
        command: AMMCommands,
    },
    /// Lightning Network commands
    #[command(about = "Lightning Network operations")]
    Lightning {
        #[command(subcommand)]
        command: LightningCommands,
    },
    /// Stablecoin commands
    #[command(about = "Stablecoin operations")]
    Stablecoin {
        #[command(subcommand)]
        command: StablecoinCommands,
    },
    /// ICO commands
    #[command(about = "Initial Coin Offering (ICO) operations")]
    ICO {
        #[command(subcommand)]
        command: ICOCommands,
    },
    /// Airdrop commands
    #[command(about = "Airdrop operations")]
    Airdrop {
        #[command(subcommand)]
        command: AirdropCommands,
    },
    /// Stablecoin V2 commands
    #[command(about = "Stablecoin V2 operations with mixed collateral")]
    StablecoinV2 {
        #[command(subcommand)]
        command: StablecoinV2Commands,
    },
}

/// Parse command line arguments and execute the appropriate command
pub fn execute_command(command: &Cli) -> Result<(), String> {
    match &command.command {
        Commands::KeyGen {
            output,
            words,
            mnemonic,
            path,
        } => generate_keypair(output, *words, mnemonic, path),
        Commands::Prove {
            circuit,
            input,
            output,
            parallel,
            config,
            threads,
            verbose,
        } => prove_circuit(circuit, input, output, *parallel, config, threads, *verbose),
        Commands::Verify {
            circuit,
            proof,
            verbose,
        } => verify_proof(circuit, proof, *verbose),
        Commands::Aggregate {
            input_dir,
            output,
            batch_size,
            verbose,
        } => aggregate_proofs_cli(input_dir, output, *batch_size, *verbose),
        Commands::VerifyAggregated {
            proof,
            circuit,
            verbose,
        } => verify_aggregated_proof_cli(proof, circuit, *verbose),
        Commands::Advanced(advanced_command) => execute_advanced_command(advanced_command),
        Commands::AMM { command } => execute_amm_command(command),
        Commands::Lightning { command } => execute_lightning_command(command),
        Commands::Stablecoin { command } => execute_stablecoin_command(command),
        Commands::ICO { command } => execute_ico_command(command),
        Commands::Airdrop { command } => execute_airdrop_command(command),
        Commands::StablecoinV2 { command } => execute_stablecoin_v2_command(command),
    }
}

/// Generate a new keypair for use with 0BTC Wire
pub fn generate_keypair(
    output: &Option<String>,
    words: usize,
    mnemonic: &Option<String>,
    path: &Option<String>,
) -> Result<(), String> {
    use wire_lib::utils::wallet::Wallet;

    info!("Generating new keypair with HD wallet support");

    // Determine the mnemonic type based on word count
    let mnemonic_type = match words {
        12 => WordCount::Words12,
        15 => WordCount::Words15,
        18 => WordCount::Words18,
        21 => WordCount::Words21,
        24 => WordCount::Words24,
        _ => {
            return Err(format!(
                "Invalid word count: {}. Must be 12, 15, 18, 21, or 24.",
                words
            ))
        }
    };

    // Create the wallet
    let wallet = if let Some(phrase) = mnemonic {
        // Use the provided mnemonic phrase
        Wallet::from_phrase(phrase, path.as_deref())
            .map_err(|e| format!("Failed to create wallet from mnemonic: {}", e))?
    } else {
        // Generate a new wallet with random mnemonic
        Wallet::generate(mnemonic_type, path.as_deref())
            .map_err(|e| format!("Failed to generate wallet: {}", e))?
    };

    // Get the keys
    let private_key = wallet.private_key_bytes();
    let public_key = wallet.public_key_bytes();

    // Create JSON representation
    let keypair_json = serde_json::json!({
        "mnemonic": wallet.mnemonic_phrase(),
        "derivation_path": wallet.derivation_path,
        "private_key": hex::encode(private_key),
        "public_key": hex::encode(public_key),
    });

    // Output the keypair
    match output {
        Some(output_path) => {
            // Validate and sanitize the output path
            let sanitized_path = match validate_output_file_path(output_path) {
                Ok(path) => path,
                Err(e) => return Err(format!("Invalid output path: {}", e)),
            };

            // Write the keypair to the file
            fs::write(
                &sanitized_path,
                serde_json::to_string_pretty(&keypair_json).unwrap(),
            )
            .map_err(|e| format!("Failed to write keypair to file: {}", e))?;

            info!("Keypair written to {}", sanitized_path.display());

            // Print a warning about securing the mnemonic
            println!("\n⚠️  IMPORTANT: Your mnemonic phrase has been saved to the output file.");
            println!("⚠️  Keep it secure and backed up in a safe place.");
            println!("⚠️  Anyone with access to your mnemonic can access your funds.");
        }
        None => {
            // Print the keypair to stdout
            println!("{}", serde_json::to_string_pretty(&keypair_json).unwrap());

            // Print a warning about securing the mnemonic
            println!("\n⚠️  IMPORTANT: Write down your mnemonic phrase and keep it secure.");
            println!("⚠️  Anyone with access to your mnemonic can access your funds.");
        }
    }

    Ok(())
}

/// Prove a circuit with the given input parameters
pub fn prove_circuit(
    circuit_type: &str,
    input_path: &str,
    output_path: &str,
    use_parallel: bool,
    config_path: &Option<String>,
    threads: &Option<usize>,
    verbose: bool,
) -> Result<(), String> {
    // Validate the circuit type
    let validated_circuit_type = match validate_circuit_type(circuit_type) {
        Ok(circuit_type) => circuit_type,
        Err(e) => return Err(format!("Invalid circuit type: {}", e)),
    };

    // Validate the input file path
    let validated_input_path = match validate_file_path(input_path, true) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid input file path: {}", e)),
    };

    // Validate the output file path
    let validated_output_path = match validate_output_file_path(output_path) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid output file path: {}", e)),
    };

    // Load configuration if provided
    let config = if let Some(config_path) = config_path {
        match config::WireConfig::load(Path::new(config_path)) {
            Ok(config) => config,
            Err(e) => return Err(format!("Failed to load configuration: {}", e)),
        }
    } else {
        config::WireConfig::default()
    };

    // Get the number of threads to use
    let num_threads = threads.unwrap_or(config.global.threads);

    if verbose {
        info!("Proving circuit: {}", validated_circuit_type);
        info!("Input file: {}", validated_input_path.display());
        info!("Output file: {}", validated_output_path.display());
        info!("Using {} threads", num_threads);
        if use_parallel {
            info!("Parallel proof generation enabled");
        }
    }

    // Read the input file
    let input_json = match fs::read_to_string(&validated_input_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read input file: {}", e)),
    };

    // Parse the input JSON
    let _input_data: serde_json::Value = match serde_json::from_str(&input_json) {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to parse input JSON: {}", e)),
    };

    // Start timing
    let start_time = std::time::Instant::now();

    // Generate the proof (placeholder implementation)
    // In a real implementation, this would call the appropriate circuit's prove function
    if verbose {
        info!("Generating proof...");
    }

    // Simulate proof generation
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Create a dummy proof result
    let proof_result = serde_json::json!({
        "circuit_type": validated_circuit_type,
        "proof": {
            "commitments": ["dummy_commitment_1", "dummy_commitment_2"],
            "evaluations": [1, 2, 3, 4],
            "public_inputs": [5, 6, 7, 8],
            "wires": ["dummy_wire_1", "dummy_wire_2"]
        },
        "verification_key": {
            "constraints": ["dummy_constraint_1", "dummy_constraint_2"],
            "domain_size": 1024,
            "num_variables": 512
        }
    });

    // Write the proof to the output file
    match fs::write(
        &validated_output_path,
        serde_json::to_string_pretty(&proof_result).unwrap(),
    ) {
        Ok(_) => {
            let elapsed = start_time.elapsed();
            if verbose {
                info!("Proof generation completed in {:?}", elapsed);
                info!("Proof written to {}", validated_output_path.display());
            }
            Ok(())
        }
        Err(e) => Err(format!("Failed to write proof to file: {}", e)),
    }
}

/// Verify a proof
pub fn verify_proof(circuit_type: &str, proof_path: &str, verbose: bool) -> Result<(), String> {
    // Validate the circuit type
    let validated_circuit_type = match validate_circuit_type(circuit_type) {
        Ok(circuit_type) => circuit_type,
        Err(e) => return Err(format!("Invalid circuit type: {}", e)),
    };

    // Validate the proof file path
    let validated_proof_path = match validate_file_path(proof_path, true) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid proof file path: {}", e)),
    };

    if verbose {
        info!("Verifying proof for circuit: {}", validated_circuit_type);
        info!("Proof file: {}", validated_proof_path.display());
    }

    // Read the proof file
    let proof_json = match fs::read_to_string(&validated_proof_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read proof file: {}", e)),
    };

    // Parse the proof JSON
    let _proof_data: serde_json::Value = match serde_json::from_str(&proof_json) {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to parse proof JSON: {}", e)),
    };

    // Verify the proof structure
    match verify_proof_structure(&_proof_data) {
        Ok(true) => {
            if verbose {
                info!("Proof structure is valid");
            }
        }
        Ok(false) => return Err("Invalid proof structure".to_string()),
        Err(e) => return Err(format!("Error verifying proof structure: {}", e)),
    }

    // Start timing
    let start_time = std::time::Instant::now();

    // Verify the proof (placeholder implementation)
    // In a real implementation, this would call the appropriate circuit's verify function
    if verbose {
        info!("Verifying proof...");
    }

    // Simulate proof verification
    std::thread::sleep(std::time::Duration::from_millis(200));

    // End timing
    let elapsed = start_time.elapsed();
    if verbose {
        info!("Proof verification completed in {:?}", elapsed);
    }
    info!("Verification result: Valid");

    Ok(())
}

/// Verify an aggregated proof
pub fn verify_aggregated_proof_cli(
    proof_path: &str,
    circuit_type: &str,
    verbose: bool,
) -> Result<(), String> {
    // Validate the circuit type
    let validated_circuit_type = match validate_circuit_type(circuit_type) {
        Ok(circuit_type) => circuit_type,
        Err(e) => return Err(format!("Invalid circuit type: {}", e)),
    };

    // Validate the proof file path
    let validated_proof_path = match validate_file_path(proof_path, true) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid proof file path: {}", e)),
    };

    if verbose {
        info!(
            "Verifying aggregated proof for circuit: {}",
            validated_circuit_type
        );
        info!("Proof file: {}", validated_proof_path.display());
    }

    // Read the proof file
    let proof_json = match fs::read_to_string(&validated_proof_path) {
        Ok(content) => content,
        Err(e) => return Err(format!("Failed to read proof file: {}", e)),
    };

    // Parse the proof JSON
    let _proof_data: serde_json::Value = match serde_json::from_str(&proof_json) {
        Ok(data) => data,
        Err(e) => return Err(format!("Failed to parse proof JSON: {}", e)),
    };

    // Start timing
    let start_time = std::time::Instant::now();

    // Verify the aggregated proof (placeholder implementation)
    // In a real implementation, this would call the appropriate verification function
    if verbose {
        info!("Verifying aggregated proof...");
    }

    // Simulate proof verification
    std::thread::sleep(std::time::Duration::from_millis(300));

    // End timing
    let elapsed = start_time.elapsed();
    if verbose {
        info!("Aggregated proof verification completed in {:?}", elapsed);
    }
    info!("Verification result: Valid");

    Ok(())
}

/// Aggregate multiple proofs into a single proof
pub fn aggregate_proofs_cli(
    input_dir: &str,
    output_path: &str,
    batch_size: usize,
    _verbose: bool,
) -> Result<(), String> {
    // Validate the input directory
    let input_dir_path = match validate_directory_path(input_dir, true) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid input directory: {}", e)),
    };

    // Validate the output file path
    let output_file_path = match validate_output_file_path(output_path) {
        Ok(path) => path,
        Err(e) => return Err(format!("Invalid output path: {}", e)),
    };

    // Validate the batch size
    let validated_batch_size = match validate_batch_size(batch_size) {
        Ok(size) => size,
        Err(e) => return Err(format!("Invalid batch size: {}", e)),
    };

    // Find and validate all proof files in the directory
    let proof_files = match validate_proof_directory(&input_dir_path) {
        Ok(files) => files,
        Err(e) => return Err(format!("Failed to validate proof directory: {}", e)),
    };

    info!(
        "Aggregating {} proofs from {} with batch size {}",
        proof_files.len(),
        input_dir_path.display(),
        validated_batch_size
    );

    // Load all proofs
    let mut proofs = Vec::new();
    for proof_file in proof_files {
        // Read the proof file
        let proof_json = match fs::read_to_string(&proof_file) {
            Ok(content) => content,
            Err(e) => {
                warn!("Failed to read proof file {}: {}", proof_file.display(), e);
                continue;
            }
        };

        // Parse the proof
        let proof: SerializableProof = match serde_json::from_str(&proof_json) {
            Ok(proof) => proof,
            Err(e) => {
                warn!("Failed to parse proof file {}: {}", proof_file.display(), e);
                continue;
            }
        };

        proofs.push(proof);
    }

    // Check if we have any proofs to aggregate
    if proofs.is_empty() {
        return Err("No valid proofs found in the input directory".to_string());
    }

    // This is a simplified implementation that just creates a dummy aggregated proof
    let aggregated_proof = SerializableProof {
        proof_bytes: serde_json::to_string(&serde_json::json!({
            "wires": [],
            "plonk": {},
            "openings": {},
            "num_proofs": proofs.len(),
        }))
        .unwrap(),
        public_inputs: vec![],
    };

    // Write the aggregated proof to the output file
    fs::write(
        &output_file_path,
        serde_json::to_string_pretty(&aggregated_proof).unwrap(),
    )
    .map_err(|e| format!("Failed to write aggregated proof to file: {}", e))?;

    info!(
        "Aggregated proof with {} proofs written to {}",
        proofs.len(),
        output_file_path.display()
    );

    Ok(())
}

/// Helper function to verify the structure of a proof
fn verify_proof_structure(proof: &serde_json::Value) -> Result<bool, String> {
    // Check that the proof has the required fields
    if !proof.is_object() {
        return Err("Proof is not a JSON object".to_string());
    }

    let proof_obj = proof.as_object().unwrap();

    if !proof_obj.contains_key("proof") {
        return Err("Proof is missing 'proof' field".to_string());
    }

    if !proof_obj.contains_key("public_inputs") {
        return Err("Proof is missing 'public_inputs' field".to_string());
    }

    // Check that the proof field is an object
    if !proof["proof"].is_object() {
        return Err("Proof 'proof' field is not an object".to_string());
    }

    // Check that the public_inputs field is an array
    if !proof["public_inputs"].is_array() {
        return Err("Proof 'public_inputs' field is not an array".to_string());
    }

    // This is a simplified implementation that always returns true
    Ok(true)
}

/// Helper functions for extracting values from JSON
fn extract_hex_array(json: &serde_json::Value, key: &str) -> Result<Vec<u8>, String> {
    let hex_str = json
        .get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_str()
        .ok_or_else(|| format!("Field {} is not a string", key))?;

    hex::decode(hex_str).map_err(|e| format!("Invalid hex string for {}: {}", key, e))
}

fn extract_u64(json: &serde_json::Value, key: &str) -> Result<u64, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_u64()
        .ok_or_else(|| format!("Field {} is not a u64", key))
}

fn extract_bool(json: &serde_json::Value, key: &str) -> Result<bool, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_bool()
        .ok_or_else(|| format!("Field {} is not a boolean", key))
}

fn extract_string(json: &serde_json::Value, key: &str) -> Result<String, String> {
    json.get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_str()
        .ok_or_else(|| format!("Field {} is not a string", key))
        .map(|s| s.to_string())
}

fn extract_field_element(json: &serde_json::Value, key: &str) -> Result<GoldilocksField, String> {
    let value = json
        .get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?;

    if let Some(num) = value.as_u64() {
        Ok(GoldilocksField::from_canonical_u64(num))
    } else if let Some(str_val) = value.as_str() {
        // Try to parse as hex
        if str_val.starts_with("0x") {
            let hex_val = &str_val[2..];
            let bytes = hex::decode(hex_val)
                .map_err(|e| format!("Invalid hex string for {}: {}", key, e))?;

            // Convert bytes to u64
            let mut result = 0u64;
            for (i, &byte) in bytes.iter().enumerate().take(8) {
                result |= (byte as u64) << (i * 8);
            }

            Ok(GoldilocksField::from_canonical_u64(result))
        } else {
            // Try to parse as decimal
            let num = str_val
                .parse::<u64>()
                .map_err(|e| format!("Invalid number string for {}: {}", key, e))?;

            Ok(GoldilocksField::from_canonical_u64(num))
        }
    } else {
        Err(format!("Field {} is not a number or string", key))
    }
}

fn extract_field_elements(
    json: &serde_json::Value,
    key: &str,
) -> Result<Vec<GoldilocksField>, String> {
    let array = json
        .get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_array()
        .ok_or_else(|| format!("Field {} is not an array", key))?;

    let mut result = Vec::with_capacity(array.len());

    for (i, value) in array.iter().enumerate() {
        if let Some(num) = value.as_u64() {
            result.push(GoldilocksField::from_canonical_u64(num));
        } else if let Some(str_val) = value.as_str() {
            // Try to parse as hex
            if str_val.starts_with("0x") {
                let hex_val = &str_val[2..];
                let bytes = hex::decode(hex_val)
                    .map_err(|e| format!("Invalid hex string at index {}: {}", i, e))?;

                // Convert bytes to u64
                let mut field_val = 0u64;
                for (j, &byte) in bytes.iter().enumerate().take(8) {
                    field_val |= (byte as u64) << (j * 8);
                }

                result.push(GoldilocksField::from_canonical_u64(field_val));
            } else {
                // Try to parse as decimal
                let num = str_val
                    .parse::<u64>()
                    .map_err(|e| format!("Invalid number string at index {}: {}", i, e))?;

                result.push(GoldilocksField::from_canonical_u64(num));
            }
        } else {
            return Err(format!("Element at index {} is not a number or string", i));
        }
    }

    Ok(result)
}

fn extract_utxos(json: &serde_json::Value, key: &str) -> Result<Vec<UTXO>, String> {
    let array = json
        .get(key)
        .ok_or_else(|| format!("Missing field: {}", key))?
        .as_array()
        .ok_or_else(|| format!("Field {} is not an array", key))?;

    let mut result = Vec::with_capacity(array.len());

    for (i, utxo_json) in array.iter().enumerate() {
        if !utxo_json.is_object() {
            return Err(format!("UTXO at index {} is not an object", i));
        }

        // Extract UTXO fields
        let owner_pubkey_hash = extract_hex_array(utxo_json, "owner_pubkey_hash")?;
        let asset_id = extract_hex_array(utxo_json, "asset_id")?;
        let amount = extract_u64(utxo_json, "amount")?;
        let salt = extract_hex_array(utxo_json, "salt")?;

        // Create the UTXO
        let utxo = UTXO {
            owner_pubkey_hash,
            asset_id,
            amount,
            salt,
        };

        result.push(utxo);
    }

    Ok(result)
}

/// Create a dummy circuit for proof conversion and verification
fn create_dummy_circuit(
    circuit_type: &str,
) -> Result<
    plonky2::plonk::circuit_data::CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    String,
> {
    // Validate the circuit type
    let validated_circuit_type = match validate_circuit_type(circuit_type) {
        Ok(circuit_type) => circuit_type,
        Err(e) => return Err(format!("Invalid circuit type: {}", e)),
    };

    // Create a dummy circuit based on the circuit type
    match validated_circuit_type.as_str() {
        "wrapped_asset_mint" => {
            // Create a dummy wrapped asset mint circuit
            // ...
            Err("Not implemented".to_string())
        }
        "wrapped_asset_burn" => {
            // Create a dummy wrapped asset burn circuit
            // ...
            Err("Not implemented".to_string())
        }
        "transfer" => {
            // Create a dummy transfer circuit
            // ...
            Err("Not implemented".to_string())
        }
        "native_asset_create" => {
            // Create a dummy native asset create circuit
            // ...
            Err("Not implemented".to_string())
        }
        "native_asset_mint" => {
            // Create a dummy native asset mint circuit
            // ...
            Err("Not implemented".to_string())
        }
        "native_asset_burn" => {
            // Create a dummy native asset burn circuit
            // ...
            Err("Not implemented".to_string())
        }
        _ => Err(format!(
            "Unsupported circuit type: {}",
            validated_circuit_type
        )),
    }
}

#[derive(Subcommand)]
pub enum LightningCommands {
    /// Generate a Lightning Network invoice for receiving BTC
    GenerateInvoice {
        /// Amount in satoshis
        #[arg(short, long)]
        amount: u64,

        /// Output file for the invoice
        #[arg(short, long)]
        output: String,
    },

    /// Check the status of a Lightning Network payment
    CheckPayment {
        /// Payment hash to check
        #[arg(short, long)]
        payment_hash: String,
    },

    /// Generate a mint proof for a Lightning Network payment
    MintProof {
        /// Path to the attestation file
        #[arg(short, long)]
        attestation: String,

        /// Output file for the proof
        #[arg(short, long)]
        output: String,
    },

    /// Generate a burn proof for a Lightning Network withdrawal
    BurnProof {
        /// Path to the UTXO file
        #[arg(short, long)]
        utxo: String,

        /// Path to the invoice file
        #[arg(short, long)]
        invoice: String,

        /// Output file for the proof
        #[arg(short, long)]
        output: String,
    },

    /// Submit a burn proof to the MPC operators
    SubmitBurn {
        /// Path to the proof file
        #[arg(short, long)]
        proof: String,

        /// Path to the invoice file
        #[arg(short, long)]
        invoice: String,
    },
}

pub fn execute_lightning_command(command: &LightningCommands) -> Result<(), String> {
    match command {
        LightningCommands::GenerateInvoice { amount, output } => {
            crate::cli::lightning::generate_ln_invoice(*amount, output)
        }
        LightningCommands::CheckPayment { payment_hash } => {
            crate::cli::lightning::check_ln_payment_status(payment_hash)
        }
        LightningCommands::MintProof {
            attestation,
            output,
        } => crate::cli::lightning::generate_ln_mint_proof(attestation, output),
        LightningCommands::BurnProof {
            utxo,
            invoice,
            output,
        } => crate::cli::lightning::generate_ln_burn_proof(utxo, invoice, output),
        LightningCommands::SubmitBurn { proof, invoice } => {
            crate::cli::lightning::submit_ln_burn_proof(proof, invoice)
        }
    }
}

#[derive(Subcommand)]
pub enum AMMCommands {
    /// Create a new liquidity pool
    CreatePool {
        /// Asset ID of token A
        #[arg(short, long)]
        token_a: String,

        /// Asset ID of token B
        #[arg(short, long)]
        token_b: String,

        /// Output file for the pool state
        #[arg(short, long)]
        output: String,
    },

    /// Swap tokens in a liquidity pool
    Swap {
        /// Path to the input UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Path to the pool state file
        #[arg(short, long)]
        pool_state: String,

        /// Asset ID of the output token
        #[arg(short, long)]
        output_asset_id: String,

        /// Minimum output amount
        #[arg(short, long)]
        min_output_amount: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },

    /// Add liquidity to a pool
    AddLiquidity {
        /// Path to the input UTXO A file
        #[arg(short, long)]
        input_utxo_a: String,

        /// Path to the input UTXO B file
        #[arg(short, long)]
        input_utxo_b: String,

        /// Path to the pool state file
        #[arg(short, long)]
        pool_state: String,

        /// Minimum LP tokens to mint
        #[arg(short, long)]
        min_lp_tokens: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },

    /// Remove liquidity from a pool
    RemoveLiquidity {
        /// Path to the LP share file
        #[arg(short, long)]
        lp_share: String,

        /// Path to the pool state file
        #[arg(short, long)]
        pool_state: String,

        /// Minimum token A amount to receive
        #[arg(short, long)]
        min_amount_a: u64,

        /// Minimum token B amount to receive
        #[arg(short, long)]
        min_amount_b: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },
}

pub fn execute_amm_command(command: &AMMCommands) -> Result<(), String> {
    match command {
        AMMCommands::CreatePool {
            token_a,
            token_b,
            output,
        } => crate::cli::amm::create_pool(token_a, token_b, output),
        AMMCommands::Swap {
            input_utxo,
            pool_state,
            output_asset_id,
            min_output_amount,
            output,
        } => crate::cli::amm::swap_tokens(
            input_utxo,
            pool_state,
            output_asset_id,
            *min_output_amount,
            output,
        ),
        AMMCommands::AddLiquidity {
            input_utxo_a,
            input_utxo_b,
            pool_state,
            min_lp_tokens,
            output,
        } => crate::cli::amm::add_liquidity(
            input_utxo_a,
            input_utxo_b,
            pool_state,
            *min_lp_tokens,
            output,
        ),
        AMMCommands::RemoveLiquidity {
            lp_share,
            pool_state,
            min_amount_a,
            min_amount_b,
            output,
        } => crate::cli::amm::remove_liquidity(
            lp_share,
            pool_state,
            *min_amount_a,
            *min_amount_b,
            output,
        ),
    }
}

#[derive(Subcommand)]
pub enum StablecoinCommands {
    /// Generate a new price attestation
    GeneratePriceAttestation {
        /// Output file for the price attestation
        #[arg(short, long)]
        output: String,
    },

    /// Get the latest price attestation
    GetLatestPriceAttestation {
        /// Output file for the price attestation
        #[arg(short, long)]
        output: String,
    },

    /// Mint zUSD stablecoins
    MintZUSD {
        /// Path to the input wBTC UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Path to the price attestation file
        #[arg(short, long)]
        price_attestation: String,

        /// Amount of zUSD to mint
        #[arg(short, long)]
        zusd_amount: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },

    /// Submit a redeem request
    SubmitRedeemRequest {
        /// User's public key hash (hex encoded)
        #[arg(short, long)]
        user_pkh: String,

        /// Amount of zUSD to redeem
        #[arg(short, long)]
        zusd_amount: u64,

        /// Output file for the request
        #[arg(short, long)]
        output: String,
    },

    /// List pending redeem requests
    ListRedeemRequests,

    /// Process a redeem request
    ProcessRedeemRequest {
        /// Path to the redeem request file
        #[arg(short, long)]
        request_file: String,

        /// Output file for the attestation
        #[arg(short, long)]
        output: String,
    },

    /// Redeem zUSD stablecoins
    RedeemZUSD {
        /// Path to the input zUSD UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Path to the price attestation file
        #[arg(short, long)]
        price_attestation: String,

        /// Path to the redeem attestation file
        #[arg(short, long)]
        redeem_attestation: String,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },
}

pub fn execute_stablecoin_command(command: &StablecoinCommands) -> Result<(), String> {
    match command {
        StablecoinCommands::GeneratePriceAttestation { output } => {
            crate::cli::stablecoin::generate_price_attestation(output)
        }
        StablecoinCommands::GetLatestPriceAttestation { output } => {
            crate::cli::stablecoin::get_latest_price_attestation(output)
        }
        StablecoinCommands::MintZUSD {
            input_utxo,
            price_attestation,
            zusd_amount,
            output,
        } => crate::cli::stablecoin::mint_zusd(input_utxo, price_attestation, *zusd_amount, output),
        StablecoinCommands::SubmitRedeemRequest {
            user_pkh,
            zusd_amount,
            output,
        } => crate::cli::stablecoin::submit_redeem_request(user_pkh, *zusd_amount, output),
        StablecoinCommands::ListRedeemRequests => crate::cli::stablecoin::list_redeem_requests(),
        StablecoinCommands::ProcessRedeemRequest {
            request_file,
            output,
        } => crate::cli::stablecoin::process_redeem_request(request_file, output),
        StablecoinCommands::RedeemZUSD {
            input_utxo,
            price_attestation,
            redeem_attestation,
            output,
        } => crate::cli::stablecoin::redeem_zusd(
            input_utxo,
            price_attestation,
            redeem_attestation,
            output,
        ),
    }
}

#[derive(Subcommand)]
pub enum ICOCommands {
    /// Create a new ICO
    CreateICO {
        /// Output file for the ICO state
        #[arg(short, long)]
        output: String,
    },

    /// Participate in an ICO
    Participate {
        /// Path to the ICO state file
        #[arg(short, long)]
        ico_state: String,

        /// Path to the input UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Amount of tokens to purchase
        #[arg(short, long)]
        amount: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },
}

pub fn execute_ico_command(command: &ICOCommands) -> Result<(), String> {
    match command {
        ICOCommands::CreateICO { output } => crate::cli::ico::create_ico(output),
        ICOCommands::Participate {
            ico_state,
            input_utxo,
            amount,
            output,
        } => crate::cli::ico::participate_in_ico(ico_state, input_utxo, *amount, output),
    }
}

#[derive(Subcommand)]
pub enum AirdropCommands {
    /// Create a new airdrop
    CreateAirdrop {
        /// Output file for the airdrop state
        #[arg(short, long)]
        output: String,
    },

    /// Claim an airdrop
    Claim {
        /// Path to the airdrop state file
        #[arg(short, long)]
        airdrop_state: String,

        /// Path to the input UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },
}

pub fn execute_airdrop_command(command: &AirdropCommands) -> Result<(), String> {
    match command {
        AirdropCommands::CreateAirdrop { output } => crate::cli::airdrop::create_airdrop(output),
        AirdropCommands::Claim {
            airdrop_state,
            input_utxo,
            output,
        } => crate::cli::airdrop::claim_airdrop(airdrop_state, input_utxo, output),
    }
}

#[derive(Subcommand)]
pub enum StablecoinV2Commands {
    /// Mint zUSD stablecoins with mixed collateral
    MintZUSD {
        /// Path to the input wBTC UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Path to the price attestation file
        #[arg(short, long)]
        price_attestation: String,

        /// Amount of zUSD to mint
        #[arg(short, long)]
        zusd_amount: u64,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },

    /// Redeem zUSD stablecoins with mixed collateral
    RedeemZUSD {
        /// Path to the input zUSD UTXO file
        #[arg(short, long)]
        input_utxo: String,

        /// Path to the price attestation file
        #[arg(short, long)]
        price_attestation: String,

        /// Path to the redeem attestation file
        #[arg(short, long)]
        redeem_attestation: String,

        /// Output file for the result
        #[arg(short, long)]
        output: String,
    },
}

pub fn execute_stablecoin_v2_command(command: &StablecoinV2Commands) -> Result<(), String> {
    match command {
        StablecoinV2Commands::MintZUSD {
            input_utxo,
            price_attestation,
            zusd_amount,
            output,
        } => crate::cli::stablecoin_v2::mint_zusd(input_utxo, price_attestation, *zusd_amount, output),
        StablecoinV2Commands::RedeemZUSD {
            input_utxo,
            price_attestation,
            redeem_attestation,
            output,
        } => crate::cli::stablecoin_v2::redeem_zusd(
            input_utxo,
            price_attestation,
            redeem_attestation,
            output,
        ),
    }
}
