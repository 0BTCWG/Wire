// Parallel proof generation utilities for the 0BTC Wire system
use std::sync::{Arc, Mutex};
use std::time::Instant;

use anyhow;
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::witness::PartialWitness;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::GenericConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;

/// Result of a parallel proof generation operation
pub struct ParallelProofResult<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The generated proof
    pub proof: ProofWithPublicInputs<F, C, D>,
    /// Time taken to generate the proof
    pub generation_time: std::time::Duration,
    /// Index of the proof in the batch
    pub index: usize,
}

/// Options for parallel proof generation
pub struct ParallelProverOptions {
    /// Number of threads to use for parallel proof generation
    /// If None, will use the number of available CPU cores
    pub num_threads: Option<usize>,
    /// Whether to print progress information
    pub verbose: bool,
}

impl Default for ParallelProverOptions {
    fn default() -> Self {
        Self {
            num_threads: None,
            verbose: false,
        }
    }
}

/// Generate proofs in parallel using multiple threads
/// 
/// This function takes a vector of circuit data and witnesses and generates proofs for them in parallel.
/// It returns a vector of proofs in the same order as the input circuits.
pub fn generate_proofs_in_parallel<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    circuits: Vec<CircuitData<F, C, D>>,
    witnesses: Vec<PartialWitness<F>>,
    options: ParallelProverOptions,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    let start = Instant::now();
    
    if circuits.len() != witnesses.len() {
        panic!("Number of circuits and witnesses must be the same");
    }
    
    if circuits.is_empty() {
        return Vec::new();
    }
    
    // Determine the number of threads to use
    let num_threads = options.num_threads.unwrap_or_else(|| {
        let available_threads = num_cpus::get();
        std::cmp::min(available_threads, circuits.len())
    });
    
    if options.verbose {
        println!("Generating {} proofs using {} threads", circuits.len(), num_threads);
    }
    
    // Create a thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    
    // Create a shared results vector
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Create a shared counter for progress reporting
    let completed = Arc::new(Mutex::new(0));
    
    // Store the total count for use in the closure
    let total_count = circuits.len();
    
    // Generate proofs in parallel
    pool.scope(|s| {
        for (i, (circuit, witness)) in circuits.into_iter().zip(witnesses.into_iter()).enumerate() {
            let results = Arc::clone(&results);
            let completed = Arc::clone(&completed);
            let verbose = options.verbose;
            
            s.spawn(move |_| {
                let proof_start = Instant::now();
                
                // Generate the proof
                let proof = circuit.prove(witness).unwrap();
                
                let generation_time = proof_start.elapsed();
                
                // Store the result
                let result = ParallelProofResult {
                    proof,
                    generation_time,
                    index: i,
                };
                
                // Update the results
                let mut results = results.lock().unwrap();
                results.push(result);
                
                // Update the progress counter
                if verbose {
                    let mut completed = completed.lock().unwrap();
                    *completed += 1;
                    println!("Generated proof {}/{} in {:?}", *completed, total_count, generation_time);
                }
            });
        }
    });
    
    // Sort the results by index to maintain the original order
    let mut results = results.lock().unwrap();
    results.sort_by_key(|r| r.index);
    
    // Extract the proofs
    let proofs = results.iter().map(|r| r.proof.clone()).collect();
    
    if options.verbose {
        println!("Generated {} proofs in {:?}", results.len(), start.elapsed());
    }
    
    proofs
}

/// Generate proofs in parallel for a single circuit type with different witnesses
/// 
/// This function takes a single circuit and multiple witnesses and generates proofs for them in parallel.
/// It returns a vector of proofs in the same order as the input witnesses.
pub fn generate_proofs_for_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    circuit: &CircuitData<F, C, D>,
    witnesses: Vec<PartialWitness<F>>,
    options: ParallelProverOptions,
) -> Vec<ProofWithPublicInputs<F, C, D>> {
    let start = Instant::now();
    
    if witnesses.is_empty() {
        return Vec::new();
    }
    
    // Determine the number of threads to use
    let num_threads = options.num_threads.unwrap_or_else(|| {
        let available_threads = num_cpus::get();
        std::cmp::min(available_threads, witnesses.len())
    });
    
    if options.verbose {
        println!("Generating {} proofs using {} threads", witnesses.len(), num_threads);
    }
    
    // Create a thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    
    // Create a shared results vector
    let results = Arc::new(Mutex::new(Vec::new()));
    
    // Create a shared counter for progress reporting
    let completed = Arc::new(Mutex::new(0));
    
    // Store the total count for use in the closure
    let total_count = witnesses.len();
    
    // Use a shared reference to the circuit
    let circuit = Arc::new(circuit);
    
    // Generate proofs in parallel
    pool.scope(|s| {
        for (i, witness) in witnesses.into_iter().enumerate() {
            let results = Arc::clone(&results);
            let completed = Arc::clone(&completed);
            let verbose = options.verbose;
            let circuit = Arc::clone(&circuit);
            
            s.spawn(move |_| {
                let proof_start = Instant::now();
                
                // Generate the proof
                let proof = circuit.prove(witness).unwrap();
                
                let generation_time = proof_start.elapsed();
                
                // Store the result
                let result = ParallelProofResult {
                    proof,
                    generation_time,
                    index: i,
                };
                
                // Update the results
                let mut results = results.lock().unwrap();
                results.push(result);
                
                // Update the progress counter
                if verbose {
                    let mut completed = completed.lock().unwrap();
                    *completed += 1;
                    println!("Generated proof {}/{} in {:?}", *completed, total_count, generation_time);
                }
            });
        }
    });
    
    // Sort the results by index to maintain the original order
    let mut results = results.lock().unwrap();
    results.sort_by_key(|r| r.index);
    
    // Extract the proofs
    let proofs = results.iter().map(|r| r.proof.clone()).collect();
    
    if options.verbose {
        println!("Generated {} proofs in {:?}", results.len(), start.elapsed());
    }
    
    proofs
}

/// Verify proofs in parallel using multiple threads
/// 
/// This function takes a vector of circuit data and proofs and verifies them in parallel.
/// It returns a vector of verification results in the same order as the input proofs.
pub fn verify_proofs_in_parallel<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    circuits: Vec<&CircuitData<F, C, D>>,
    proofs: Vec<&ProofWithPublicInputs<F, C, D>>,
    options: ParallelProverOptions,
) -> Vec<Result<(), anyhow::Error>> {
    let start = Instant::now();
    
    if circuits.len() != proofs.len() {
        panic!("Number of circuits and proofs must be the same");
    }
    
    if circuits.is_empty() {
        return Vec::new();
    }
    
    // Determine the number of threads to use
    let num_threads = options.num_threads.unwrap_or_else(|| {
        let available_threads = num_cpus::get();
        std::cmp::min(available_threads, circuits.len())
    });
    
    if options.verbose {
        println!("Verifying {} proofs using {} threads", circuits.len(), num_threads);
    }
    
    // Create a thread pool
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .unwrap();
    
    // Create a shared results vector
    let results = Arc::new(Mutex::new(Vec::<(usize, Result<(), anyhow::Error>)>::with_capacity(circuits.len())));
    
    // Create a shared counter for progress reporting
    let completed = Arc::new(Mutex::new(0));
    
    // Store the circuit count for use in the closure
    let circuit_count = circuits.len();
    
    // Verify proofs in parallel
    pool.scope(|s| {
        for (i, (circuit, proof)) in circuits.iter().zip(proofs.iter()).enumerate() {
            let results = Arc::clone(&results);
            let completed = Arc::clone(&completed);
            let verbose = options.verbose;
            let proof = (*proof).clone(); // Clone the proof to avoid reference issues
            
            s.spawn(move |_| {
                let verify_start = Instant::now();
                
                // Verify the proof
                let result = match circuit.verify(proof.clone()) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(anyhow::anyhow!("{:?}", e)),
                };
                
                let verification_time = verify_start.elapsed();
                
                // Store the result
                results.lock().unwrap().push((i, result));
                
                // Update the progress counter
                if verbose {
                    let mut completed = completed.lock().unwrap();
                    *completed += 1;
                    println!("Verified proof {}/{} in {:?}", *completed, circuit_count, verification_time);
                }
            });
        }
    });
    
    // Sort the results by index to maintain the original order
    let mut results = results.lock().unwrap();
    results.sort_by_key(|r| r.0);
    
    // Extract the verification results
    let verification_results: Vec<Result<(), anyhow::Error>> = results.iter()
        .map(|r| match &r.1 {
            Ok(()) => Ok(()),
            Err(e) => Err(anyhow::anyhow!("{:?}", e)),
        })
        .collect();
    
    if options.verbose {
        println!("Verified {} proofs in {:?}", results.len(), start.elapsed());
    }
    
    verification_results
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    
    use plonky2::iop::witness::PartialWitness;
    use plonky2::iop::witness::WitnessWrite;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn test_parallel_proof_generation() {
        // Create a simple circuit for testing
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Add a public input
        let pub_input = builder.add_virtual_target();
        builder.register_public_input(pub_input);
        
        // Add a private input
        let priv_input = builder.add_virtual_target();
        
        // Connect them
        builder.connect(pub_input, priv_input);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create multiple witnesses
        let num_proofs = 4;
        let mut witnesses = Vec::with_capacity(num_proofs);
        
        for i in 0..num_proofs {
            let mut pw = PartialWitness::new();
            let _ = pw.set_target(pub_input, F::from_canonical_u64(i as u64));
            let _ = pw.set_target(priv_input, F::from_canonical_u64(i as u64));
            witnesses.push(pw);
        }
        
        // Generate proofs in parallel
        let options = ParallelProverOptions {
            num_threads: Some(2),
            verbose: true,
        };
        
        let proofs = generate_proofs_for_circuit(&circuit, witnesses, options);
        
        // Verify that we got the correct number of proofs
        assert_eq!(proofs.len(), num_proofs);
        
        // Verify all proofs
        for proof in &proofs {
            circuit.verify(proof.clone()).unwrap();
        }
    }
}
