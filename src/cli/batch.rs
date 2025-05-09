// Batch processing for the 0BTC Wire system
use log::{debug, info};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::cli::config::BatchConfig;
use wire_lib::errors::{IOError, ProofError, ValidationError, WireError, WireResult};
use wire_lib::utils::parallel_prover::{verify_proofs_in_parallel, ParallelProverOptions};

/// Batch processing options
#[derive(Debug, Clone)]
pub struct BatchOptions {
    /// Input directory containing proofs to process
    pub input_dir: PathBuf,

    /// Output directory for processed proofs
    pub output_dir: PathBuf,

    /// Maximum number of proofs to process in a single batch
    pub batch_size: usize,

    /// Whether to use parallel processing
    pub parallel: bool,

    /// Whether to enable verbose logging
    pub verbose: bool,

    /// Circuit type for the proofs
    pub circuit_type: String,
}

impl From<&BatchConfig> for BatchOptions {
    fn from(config: &BatchConfig) -> Self {
        BatchOptions {
            input_dir: PathBuf::from(&config.input_dir),
            output_dir: PathBuf::from(&config.output_dir),
            batch_size: config.batch_size,
            parallel: config.parallel,
            verbose: false,
            circuit_type: String::new(),
        }
    }
}

/// Process a batch of proofs
pub fn process_batch(options: &BatchOptions) -> WireResult<()> {
    // Validate options
    validate_batch_options(options)?;

    // Create output directory if it doesn't exist
    fs::create_dir_all(&options.output_dir).map_err(|e| {
        WireError::IOError(IOError::FileSystem(format!(
            "Failed to create output directory: {}",
            e
        )))
    })?;

    // Find all proof files in the input directory
    let proof_files = find_proof_files(&options.input_dir)?;

    if proof_files.is_empty() {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError(format!(
                "No proof files found in directory: {}",
                options.input_dir.display()
            )),
        ));
    }

    info!("Found {} proof files", proof_files.len());

    // Process proofs in batches
    let start_time = Instant::now();

    if options.parallel {
        process_batch_parallel(options, &proof_files)?;
    } else {
        process_batch_sequential(options, &proof_files)?;
    }

    let elapsed = start_time.elapsed();
    info!("Batch processing completed in {:?}", elapsed);

    Ok(())
}

/// Validate batch processing options
fn validate_batch_options(options: &BatchOptions) -> WireResult<()> {
    // Check if input directory exists
    if !options.input_dir.exists() {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError(format!(
                "Input directory does not exist: {}",
                options.input_dir.display()
            )),
        ));
    }

    // Check if input directory is a directory
    if !options.input_dir.is_dir() {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError(format!(
                "Input path is not a directory: {}",
                options.input_dir.display()
            )),
        ));
    }

    // Check batch size
    if options.batch_size == 0 {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError(
                "Batch size must be greater than zero".to_string(),
            ),
        ));
    }

    // Validate circuit type
    if options.circuit_type.is_empty() {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError("Circuit type must be specified".to_string()),
        ));
    }

    Ok(())
}

/// Find all proof files in a directory
fn find_proof_files(dir: &Path) -> WireResult<Vec<PathBuf>> {
    let entries = fs::read_dir(dir).map_err(|e| {
        WireError::IOError(IOError::FileSystem(format!(
            "Failed to read directory: {}",
            e
        )))
    })?;

    let mut proof_files = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|e| {
            WireError::IOError(IOError::FileSystem(format!(
                "Failed to read directory entry: {}",
                e
            )))
        })?;

        let path = entry.path();

        if path.is_file() && path.extension().map_or(false, |ext| ext == "json") {
            proof_files.push(path);
        }
    }

    Ok(proof_files)
}

/// Process a batch of proofs in parallel
fn process_batch_parallel(options: &BatchOptions, proof_files: &[PathBuf]) -> WireResult<()> {
    // Validate batch size
    if options.batch_size == 0 {
        return Err(WireError::ValidationError(
            ValidationError::InputValidationError("Batch size must be greater than 0".to_string()),
        ));
    }

    // Group proofs into batches
    let batches = group_into_batches(proof_files, options.batch_size);

    info!("Processing {} batches in parallel", batches.len());

    // Process batches in parallel
    let results: Arc<Mutex<Vec<WireResult<()>>>> = Arc::new(Mutex::new(Vec::new()));

    batches.iter().enumerate().for_each(|(batch_idx, batch)| {
        let output_path = options
            .output_dir
            .join(format!("batch_{}.proof", batch_idx));
        let batch_result = process_single_batch(options, batch, &output_path);

        let mut results = results.lock().unwrap();
        results.push(batch_result);
    });

    // Check for errors
    let results = results.lock().unwrap();
    let errors: Vec<String> = results
        .iter()
        .enumerate()
        .filter_map(|(batch_idx, result)| {
            result
                .as_ref()
                .err()
                .map(|e| format!("Batch {}: {}", batch_idx, e))
        })
        .collect();

    if !errors.is_empty() {
        let error_msg = errors.join("\n");
        return Err(WireError::BatchProcessingError(error_msg));
    }

    info!("All batches processed successfully");
    Ok(())
}

/// Process a batch of proofs sequentially
fn process_batch_sequential(options: &BatchOptions, proof_files: &[PathBuf]) -> WireResult<()> {
    // Group proofs into batches
    let batches = group_into_batches(proof_files, options.batch_size);

    info!("Processing {} batches sequentially", batches.len());

    // Process each batch sequentially
    for (batch_idx, batch) in batches.iter().enumerate() {
        let batch_output_path = options.output_dir.join(format!("batch_{}.json", batch_idx));

        process_single_batch(options, batch, &batch_output_path)?;
        info!("Batch {} processed successfully", batch_idx);
    }

    Ok(())
}

/// Process a single batch of proofs
fn process_single_batch(
    options: &BatchOptions,
    batch: &[PathBuf],
    _output_path: &Path,
) -> WireResult<()> {
    debug!("Processing batch with {} proofs", batch.len());

    // Load proofs from files
    let proofs = load_proofs_from_files(batch, &options.circuit_type)?;

    // Create dummy circuit data for verification
    let dummy_circuit = crate::cli::create_dummy_circuit(&options.circuit_type).map_err(|e| {
        WireError::ProofError(ProofError::VerificationError(format!(
            "Failed to create dummy circuit: {}",
            e
        )))
    })?;

    // Create references to proofs and circuits for verification
    let proof_refs: Vec<&ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> =
        proofs.iter().collect();
    let circuit_refs: Vec<
        &plonky2::plonk::circuit_data::CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    > = vec![&dummy_circuit; proof_refs.len()];

    // Set up parallel prover options
    let parallel_options = ParallelProverOptions {
        num_threads: None, // Use default (all available cores)
        verbose: options.verbose,
    };

    // Verify proofs in parallel
    let results = verify_proofs_in_parallel(circuit_refs, proof_refs, parallel_options);

    // Check verification results
    for (i, result) in results.iter().enumerate() {
        if let Err(e) = result {
            return Err(WireError::ProofError(ProofError::VerificationError(
                format!("Proof {} verification failed: {}", i, e),
            )));
        }
    }

    info!("Successfully verified {} proofs", proofs.len());

    // For now, we're just verifying proofs, not aggregating them
    // In a real implementation, we would aggregate the proofs here

    Ok(())
}

/// Group proofs into batches
fn group_into_batches<T>(items: &[T], batch_size: usize) -> Vec<Vec<T>>
where
    T: Clone,
{
    let mut batches = Vec::new();
    let mut current_batch = Vec::new();

    for item in items {
        current_batch.push(item.clone());

        if current_batch.len() >= batch_size {
            batches.push(current_batch);
            current_batch = Vec::new();
        }
    }

    if !current_batch.is_empty() {
        batches.push(current_batch);
    }

    batches
}

/// Load proofs from files
fn load_proofs_from_files(
    files: &[PathBuf],
    circuit_type: &str,
) -> WireResult<Vec<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>>> {
    let mut proofs = Vec::new();

    for file in files {
        let proof = load_proof_from_file(file, circuit_type)?;
        proofs.push(proof);
    }

    Ok(proofs)
}

/// Load a proof from a file
fn load_proof_from_file(
    _file: &Path,
    _circuit_type: &str,
) -> WireResult<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>> {
    // This is a placeholder for the actual implementation
    // In a real implementation, this would deserialize the proof from the file
    // and convert it to the appropriate type based on the circuit type

    Err(WireError::ValidationError(
        ValidationError::InputValidationError(
            "Proof loading not implemented in this example".to_string(),
        ),
    ))
}

/// Save a proof to a file
fn save_proof_to_file(
    _proof: &ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    _output_path: &Path,
) -> WireResult<()> {
    // This is a placeholder for the actual implementation
    // In a real implementation, this would serialize the proof to JSON
    // and write it to the output file

    Err(WireError::ValidationError(
        ValidationError::InputValidationError(
            "Proof saving not implemented in this example".to_string(),
        ),
    ))
}
