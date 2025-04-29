// CLI Demo Example for 0BTC Wire
//
// This example demonstrates how to use the CLI functionality
// including the new recursive proof aggregation feature.

use clap::{Parser, Subcommand};
use std::fs;
use std::path::Path;
use std::time::Instant;
use std::process;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use wire_lib::gadgets::hash::hash_single;
use wire_lib::utils::{
    generate_proofs_for_circuit,
    verify_proofs_in_parallel,
    ParallelProverOptions,
    aggregate_proofs,
    verify_aggregated_proof,
    RecursiveProverOptions,
};
use wire_lib::core::proof::SerializableProof;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

#[derive(Parser)]
#[command(name = "wire-demo")]
#[command(about = "0BTC Wire CLI Demo", long_about = None)]
#[command(version = "1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a batch of proofs
    Generate {
        /// Number of proofs to generate
        #[arg(short, long, default_value = "4")]
        count: usize,
        
        /// Output directory for the proofs
        #[arg(short, long, default_value = "proofs")]
        output: String,
        
        /// Whether to use parallel proof generation
        #[arg(short, long)]
        parallel: bool,
    },
    /// Verify a batch of proofs
    Verify {
        /// Input directory containing the proofs
        #[arg(short, long, default_value = "proofs")]
        input: String,
        
        /// Whether to use parallel verification
        #[arg(short, long)]
        parallel: bool,
        
        /// Whether to use recursive verification
        #[arg(short, long)]
        recursive: bool,
    },
    /// Aggregate multiple proofs into a single proof
    Aggregate {
        /// Input directory containing the proofs
        #[arg(short, long, default_value = "proofs")]
        input: String,
        
        /// Output file for the aggregated proof
        #[arg(short, long, default_value = "aggregated_proof.json")]
        output: String,
        
        /// Maximum number of proofs to aggregate in a single step
        #[arg(short, long, default_value = "4")]
        batch_size: usize,
    },
}

fn main() {
    println!("0BTC Wire CLI Demo");
    println!("=================");
    
    let cli = Cli::parse();
    
    match &cli.command {
        Commands::Generate { count, output, parallel } => {
            generate_proofs(*count, output, *parallel);
        },
        Commands::Verify { input, parallel, recursive } => {
            verify_proofs(input, *parallel, *recursive);
        },
        Commands::Aggregate { input, output, batch_size } => {
            aggregate_proof_batch(input, output, *batch_size);
        },
    }
}

fn generate_proofs(count: usize, output_dir: &str, use_parallel: bool) {
    println!("Generating {} proofs...", count);
    
    // Create output directory if it doesn't exist
    if !Path::new(output_dir).exists() {
        fs::create_dir_all(output_dir).expect("Failed to create output directory");
    }
    
    // Create a simple hash circuit for testing
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Add inputs
    let input = builder.add_virtual_target();
    let pub_output = builder.add_virtual_target();
    builder.register_public_input(pub_output);
    
    // Perform a hash operation
    let hash_result = hash_single(&mut builder, input);
    builder.connect(hash_result, pub_output);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Prepare witnesses
    let mut witnesses = Vec::with_capacity(count);
    for i in 0..count {
        let mut pw = PartialWitness::new();
        pw.set_target(input, F::from_canonical_u64(i as u64));
        witnesses.push(pw);
    }
    
    // Generate proofs
    let start = Instant::now();
    let proofs = if use_parallel {
        // Generate proofs in parallel
        let options = ParallelProverOptions {
            num_threads: None, // Use available cores
            verbose: true,
        };
        generate_proofs_for_circuit(&circuit, witnesses, options).expect("Failed to generate proofs")
    } else {
        // Generate proofs sequentially
        let mut proofs = Vec::with_capacity(count);
        for (i, witness) in witnesses.into_iter().enumerate() {
            println!("Generating proof {}/{}...", i + 1, count);
            let proof = circuit.prove(witness).expect("Failed to generate proof");
            proofs.push(proof);
        }
        proofs
    };
    let generation_time = start.elapsed();
    
    println!("Generated {} proofs in {:?}", count, generation_time);
    
    // Save proofs to files
    for (i, proof) in proofs.iter().enumerate() {
        let serializable = SerializableProof::from(proof.clone());
        let json = serde_json::to_string_pretty(&serializable).expect("Failed to serialize proof");
        let path = format!("{}/proof_{}.json", output_dir, i);
        fs::write(&path, json).expect("Failed to write proof to file");
        println!("Saved proof to {}", path);
    }
}

fn verify_proofs(input_dir: &str, use_parallel: bool, use_recursive: bool) {
    println!("Verifying proofs from {}...", input_dir);
    
    // Check if input directory exists
    if !Path::new(input_dir).exists() {
        println!("Error: Input directory does not exist");
        process::exit(1);
    }
    
    // Load proofs from files
    let mut proofs = Vec::new();
    let files = fs::read_dir(input_dir).expect("Failed to read input directory");
    
    for file in files {
        let path = file.expect("Failed to read file").path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let json = fs::read_to_string(&path).expect("Failed to read proof file");
            let serializable: SerializableProof = serde_json::from_str(&json).expect("Failed to parse proof");
            
            // Create a circuit to verify the proof
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Add inputs
            let input = builder.add_virtual_target();
            let pub_output = builder.add_virtual_target();
            builder.register_public_input(pub_output);
            
            // Perform a hash operation
            let hash_result = hash_single(&mut builder, input);
            builder.connect(hash_result, pub_output);
            
            // Build the circuit
            let circuit = builder.build::<C>();
            
            // Convert serializable proof to ProofWithPublicInputs
            let proof = serializable.to_proof::<F, C, D>(&circuit.common).expect("Failed to convert proof");
            proofs.push(proof);
            
            println!("Loaded proof from {}", path.display());
        }
    }
    
    if proofs.is_empty() {
        println!("No proofs found in the input directory");
        process::exit(1);
    }
    
    println!("Loaded {} proofs", proofs.len());
    
    // Create a circuit for verification
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Add inputs
    let input = builder.add_virtual_target();
    let pub_output = builder.add_virtual_target();
    builder.register_public_input(pub_output);
    
    // Perform a hash operation
    let hash_result = hash_single(&mut builder, input);
    builder.connect(hash_result, pub_output);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Verify proofs
    let start = Instant::now();
    
    if use_recursive {
        // Aggregate proofs and verify the aggregated proof
        println!("Using recursive verification...");
        
        let options = RecursiveProverOptions {
            verbose: true,
            max_proofs_per_step: Some(4),
        };
        
        let result = aggregate_proofs(proofs, options).expect("Failed to aggregate proofs");
        let num_verified = verify_aggregated_proof(&result.proof, &circuit).expect("Failed to verify aggregated proof");
        
        println!("Verified {} proofs with recursive verification", num_verified);
    } else if use_parallel {
        // Verify proofs in parallel
        println!("Using parallel verification...");
        
        let options = ParallelProverOptions {
            num_threads: None, // Use available cores
            verbose: true,
        };
        
        verify_proofs_in_parallel(&circuit, &proofs, options).expect("Failed to verify proofs");
        
        println!("Verified {} proofs with parallel verification", proofs.len());
    } else {
        // Verify proofs sequentially
        println!("Using sequential verification...");
        
        for (i, proof) in proofs.iter().enumerate() {
            println!("Verifying proof {}/{}...", i + 1, proofs.len());
            circuit.verify(proof).expect("Failed to verify proof");
        }
        
        println!("Verified {} proofs with sequential verification", proofs.len());
    }
    
    let verification_time = start.elapsed();
    println!("Verification completed in {:?}", verification_time);
}

fn aggregate_proof_batch(input_dir: &str, output_file: &str, batch_size: usize) {
    println!("Aggregating proofs from {}...", input_dir);
    
    // Check if input directory exists
    if !Path::new(input_dir).exists() {
        println!("Error: Input directory does not exist");
        process::exit(1);
    }
    
    // Load proofs from files
    let mut proofs = Vec::new();
    let files = fs::read_dir(input_dir).expect("Failed to read input directory");
    
    for file in files {
        let path = file.expect("Failed to read file").path();
        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            let json = fs::read_to_string(&path).expect("Failed to read proof file");
            let serializable: SerializableProof = serde_json::from_str(&json).expect("Failed to parse proof");
            
            // Create a circuit to verify the proof
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);
            
            // Add inputs
            let input = builder.add_virtual_target();
            let pub_output = builder.add_virtual_target();
            builder.register_public_input(pub_output);
            
            // Perform a hash operation
            let hash_result = hash_single(&mut builder, input);
            builder.connect(hash_result, pub_output);
            
            // Build the circuit
            let circuit = builder.build::<C>();
            
            // Convert serializable proof to ProofWithPublicInputs
            let proof = serializable.to_proof::<F, C, D>(&circuit.common).expect("Failed to convert proof");
            proofs.push(proof);
            
            println!("Loaded proof from {}", path.display());
        }
    }
    
    if proofs.is_empty() {
        println!("No proofs found in the input directory");
        process::exit(1);
    }
    
    println!("Loaded {} proofs", proofs.len());
    
    // Aggregate proofs
    println!("Aggregating proofs with batch size {}...", batch_size);
    
    let options = RecursiveProverOptions {
        verbose: true,
        max_proofs_per_step: Some(batch_size),
    };
    
    let start = Instant::now();
    let result = aggregate_proofs(proofs, options).expect("Failed to aggregate proofs");
    let aggregation_time = start.elapsed();
    
    println!("Aggregated {} proofs in {:?}", result.num_proofs, aggregation_time);
    
    // Save aggregated proof to file
    let serializable = SerializableProof::from(result.proof);
    let json = serde_json::to_string_pretty(&serializable).expect("Failed to serialize proof");
    fs::write(output_file, json).expect("Failed to write proof to file");
    
    println!("Saved aggregated proof to {}", output_file);
    
    // Create a circuit for verification
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Add inputs
    let input = builder.add_virtual_target();
    let pub_output = builder.add_virtual_target();
    builder.register_public_input(pub_output);
    
    // Perform a hash operation
    let hash_result = hash_single(&mut builder, input);
    builder.connect(hash_result, pub_output);
    
    // Build the circuit
    let circuit = builder.build::<C>();
    
    // Verify the aggregated proof
    println!("Verifying aggregated proof...");
    
    let start = Instant::now();
    let num_verified = verify_aggregated_proof(&serializable.to_proof::<F, C, D>(&circuit.common).unwrap(), &circuit)
        .expect("Failed to verify aggregated proof");
    let verification_time = start.elapsed();
    
    println!("Verified aggregated proof containing {} proofs in {:?}", num_verified, verification_time);
}
