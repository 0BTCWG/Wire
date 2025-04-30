// Comprehensive benchmarking utilities for the 0BTC Wire system
use std::time::{Duration, Instant};
use std::fmt;
use std::collections::HashMap;

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::RichField;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::utils::{
    generate_proofs_in_parallel,
    verify_proofs_in_parallel,
    ParallelProverOptions,
    aggregate_proofs,
    verify_aggregated_proof,
    RecursiveProverOptions,
};

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Result of a benchmark run
#[derive(Clone, Debug)]
pub struct BenchmarkResult {
    /// Name of the benchmark
    pub name: String,
    /// Description of the benchmark
    pub description: String,
    /// Duration of circuit creation
    pub circuit_creation_time: Duration,
    /// Duration of proof generation
    pub proof_generation_time: Duration,
    /// Duration of proof verification
    pub proof_verification_time: Duration,
    /// Number of gates in the circuit
    pub gate_count: usize,
    /// Number of constraints in the circuit
    pub constraint_count: usize,
    /// Number of public inputs in the circuit
    pub public_input_count: usize,
    /// Number of proofs generated
    pub proof_count: usize,
    /// Additional metrics
    pub metrics: HashMap<String, f64>,
}

impl BenchmarkResult {
    /// Create a new benchmark result
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            circuit_creation_time: Duration::default(),
            proof_generation_time: Duration::default(),
            proof_verification_time: Duration::default(),
            gate_count: 0,
            constraint_count: 0,
            public_input_count: 0,
            proof_count: 0,
            metrics: HashMap::new(),
        }
    }

    /// Add a metric to the benchmark result
    pub fn add_metric(&mut self, name: &str, value: f64) {
        self.metrics.insert(name.to_string(), value);
    }

    /// Get a metric from the benchmark result
    pub fn get_metric(&self, name: &str) -> Option<f64> {
        self.metrics.get(name).copied()
    }

    /// Calculate throughput (proofs per second)
    pub fn proof_generation_throughput(&self) -> f64 {
        if self.proof_generation_time.as_secs_f64() > 0.0 {
            self.proof_count as f64 / self.proof_generation_time.as_secs_f64()
        } else {
            0.0
        }
    }

    /// Calculate verification throughput (proofs per second)
    pub fn proof_verification_throughput(&self) -> f64 {
        if self.proof_verification_time.as_secs_f64() > 0.0 {
            self.proof_count as f64 / self.proof_verification_time.as_secs_f64()
        } else {
            0.0
        }
    }
}

impl fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Benchmark: {}", self.name)?;
        writeln!(f, "Description: {}", self.description)?;
        writeln!(f, "Circuit creation time: {:?}", self.circuit_creation_time)?;
        writeln!(f, "Proof generation time: {:?}", self.proof_generation_time)?;
        writeln!(f, "Proof verification time: {:?}", self.proof_verification_time)?;
        writeln!(f, "Gate count: {}", self.gate_count)?;
        writeln!(f, "Constraint count: {}", self.constraint_count)?;
        writeln!(f, "Public input count: {}", self.public_input_count)?;
        writeln!(f, "Proof count: {}", self.proof_count)?;
        writeln!(f, "Proof generation throughput: {:.2} proofs/second", self.proof_generation_throughput())?;
        writeln!(f, "Proof verification throughput: {:.2} proofs/second", self.proof_verification_throughput())?;
        
        if !self.metrics.is_empty() {
            writeln!(f, "Additional metrics:")?;
            let mut metrics: Vec<_> = self.metrics.iter().collect();
            metrics.sort_by(|a, b| a.0.cmp(b.0));
            for (name, value) in metrics {
                writeln!(f, "  {}: {:.2}", name, value)?;
            }
        }
        
        Ok(())
    }
}

/// Benchmark configuration
#[derive(Clone, Debug)]
pub struct BenchmarkConfig {
    /// Number of proofs to generate
    pub proof_count: usize,
    /// Whether to use parallel proof generation
    pub use_parallel: bool,
    /// Number of threads to use for parallel proof generation
    pub thread_count: Option<usize>,
    /// Whether to use recursive proof aggregation
    pub use_recursive: bool,
    /// Maximum number of proofs to aggregate in a single step
    pub max_proofs_per_step: Option<usize>,
    /// Whether to print verbose output
    pub verbose: bool,
    /// Number of warmup runs to perform
    pub warmup_runs: usize,
    /// Number of measurement runs to perform
    pub measurement_runs: usize,
    /// Whether to skip proof generation
    pub skip_proofs: bool,
}

impl Default for BenchmarkConfig {
    fn default() -> Self {
        Self {
            proof_count: 1,
            use_parallel: false,
            thread_count: None,
            use_recursive: false,
            max_proofs_per_step: None,
            verbose: false,
            warmup_runs: 1,
            measurement_runs: 3,
            skip_proofs: false,
        }
    }
}

/// Benchmark a circuit
pub fn benchmark_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    name: &str,
    description: &str,
    circuit: &CircuitData<F, C, D>,
    witnesses: Vec<plonky2::iop::witness::PartialWitness<F>>,
    config: &BenchmarkConfig,
) -> BenchmarkResult {
    let mut result = BenchmarkResult::new(name, description);
    
    // Record circuit metrics
    result.gate_count = circuit.common.gates.len();
    result.constraint_count = circuit.common.num_constraints;
    result.public_input_count = circuit.common.num_public_inputs;
    result.proof_count = witnesses.len();
    
    // Warmup runs
    if config.verbose {
        println!("Performing {} warmup runs...", config.warmup_runs);
    }
    
    for _ in 0..config.warmup_runs {
        if witnesses.len() == 1 {
            let _ = circuit.prove(witnesses[0].clone());
        } else if config.use_parallel {
            let parallel_options = ParallelProverOptions {
                num_threads: config.thread_count,
                verbose: false,
            };
            let _ = generate_proofs_in_parallel(circuit, witnesses.clone(), parallel_options);
        }
    }
    
    // Measurement runs
    if config.verbose {
        println!("Performing {} measurement runs...", config.measurement_runs);
    }
    
    let mut total_proof_generation_time = Duration::default();
    let mut total_proof_verification_time = Duration::default();
    let mut proofs = Vec::new();
    
    for i in 0..config.measurement_runs {
        if config.verbose {
            println!("Measurement run {}/{}...", i + 1, config.measurement_runs);
        }
        
        // Generate proofs
        let proof_start = Instant::now();
        
        if witnesses.len() == 1 {
            let proof = circuit.prove(witnesses[0].clone()).expect("Failed to generate proof");
            proofs = vec![proof];
        } else if config.use_parallel {
            let parallel_options = ParallelProverOptions {
                num_threads: config.thread_count,
                verbose: config.verbose,
            };
            proofs = generate_proofs_in_parallel(circuit, witnesses.clone(), parallel_options)
                .expect("Failed to generate proofs in parallel");
        } else {
            proofs = witnesses.iter().map(|w| {
                circuit.prove(w.clone()).expect("Failed to generate proof")
            }).collect();
        }
        
        let proof_generation_time = proof_start.elapsed();
        total_proof_generation_time += proof_generation_time;
        
        if config.verbose {
            println!("Generated {} proofs in {:?}", proofs.len(), proof_generation_time);
        }
        
        // Verify proofs
        let verify_start = Instant::now();
        
        if config.use_parallel && proofs.len() > 1 {
            // Convert proofs to a Vec of references
            let proof_refs: Vec<&ProofWithPublicInputs<F, C, D>> = proofs.iter().collect();
            
            // Convert circuit to a Vec of references
            let circuit_refs = vec![&circuit];
            
            // Verify proofs in parallel
            let results = verify_proofs_in_parallel(circuit_refs, proof_refs, config.thread_count);
            
            // Check all results
            for result in results {
                if let Err(e) = result {
                    panic!("Failed to verify proof in parallel: {}", e);
                }
            }
        } else if config.use_recursive && proofs.len() > 1 {
            // Aggregate proofs
            let recursive_options = RecursiveProverOptions {
                verbose: config.verbose,
                max_proofs_per_step: config.max_proofs_per_step,
            };
            
            let aggregation_result = aggregate_proofs(proofs.clone(), recursive_options)
                .expect("Failed to aggregate proofs");
            
            // Verify aggregated proof
            let _ = verify_aggregated_proof(&aggregation_result.proof, circuit)
                .expect("Failed to verify aggregated proof");
            
            if i == config.measurement_runs - 1 {
                // Record aggregation metrics for the last run
                result.add_metric("aggregation_time", aggregation_result.generation_time.as_secs_f64());
                result.add_metric("aggregation_throughput", 
                    aggregation_result.num_proofs as f64 / aggregation_result.generation_time.as_secs_f64());
            }
        } else {
            // Verify proofs sequentially
            for proof in &proofs {
                circuit.verify(proof.clone()).expect("Failed to verify proof");
            }
        }
        
        let proof_verification_time = verify_start.elapsed();
        total_proof_verification_time += proof_verification_time;
        
        if config.verbose {
            println!("Verified {} proofs in {:?}", proofs.len(), proof_verification_time);
        }
    }
    
    // Calculate average times
    result.proof_generation_time = total_proof_generation_time / config.measurement_runs as u32;
    result.proof_verification_time = total_proof_verification_time / config.measurement_runs as u32;
    
    // Calculate throughput metrics
    let generation_throughput = result.proof_count as f64 / result.proof_generation_time.as_secs_f64();
    let verification_throughput = result.proof_count as f64 / result.proof_verification_time.as_secs_f64();
    
    result.add_metric("generation_throughput", generation_throughput);
    result.add_metric("verification_throughput", verification_throughput);
    
    if config.use_parallel {
        result.add_metric("thread_count", config.thread_count.unwrap_or_else(num_cpus::get) as f64);
    }
    
    if config.verbose {
        println!("{}", result);
    }
    
    result
}

/// Benchmark a circuit builder function
pub fn benchmark_circuit_builder<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    name: &str,
    description: &str,
    build_circuit: impl Fn() -> (CircuitBuilder<F, D>, Vec<plonky2::iop::witness::PartialWitness<F>>),
    config: &BenchmarkConfig,
) -> BenchmarkResult {
    let mut result = BenchmarkResult::new(name, description);
    
    // Build the circuit and measure creation time
    let circuit_start = Instant::now();
    let (builder, witnesses) = build_circuit();
    let circuit_data = builder.build::<C>();
    let circuit_creation_time = circuit_start.elapsed();
    
    result.circuit_creation_time = circuit_creation_time;
    
    if config.verbose {
        println!("Circuit creation time: {:?}", circuit_creation_time);
    }
    
    // Benchmark the circuit
    let circuit_result = benchmark_circuit(name, description, &circuit_data, witnesses, config);
    
    // Combine results
    result.proof_generation_time = circuit_result.proof_generation_time;
    result.proof_verification_time = circuit_result.proof_verification_time;
    result.gate_count = circuit_result.gate_count;
    result.constraint_count = circuit_result.constraint_count;
    result.public_input_count = circuit_result.public_input_count;
    result.proof_count = circuit_result.proof_count;
    result.metrics = circuit_result.metrics;
    
    if config.verbose {
        println!("{}", result);
    }
    
    result
}

/// Run a suite of benchmarks
pub fn run_benchmark_suite(
    benchmarks: Vec<BenchmarkResult>,
    name: &str,
    description: &str,
) -> BenchmarkSuiteResult {
    BenchmarkSuiteResult {
        name: name.to_string(),
        description: description.to_string(),
        benchmarks,
    }
}

/// Result of a benchmark suite
#[derive(Clone, Debug)]
pub struct BenchmarkSuiteResult {
    /// Name of the benchmark suite
    pub name: String,
    /// Description of the benchmark suite
    pub description: String,
    /// Results of individual benchmarks
    pub benchmarks: Vec<BenchmarkResult>,
}

impl fmt::Display for BenchmarkSuiteResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "\n{}", self.name)?;
        writeln!(f, "{}", "=".repeat(self.name.len()))?;
        writeln!(f, "\n{}\n", self.description)?;
        
        writeln!(f, "+-{:-<30}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}-+", 
            "", "", "", "", "")?;
        writeln!(f, "| {:<30} | {:<15} | {:<15} | {:<15} | {:<10} |", 
            "Benchmark", "Circuit Gates", "Proof Time (s)", "Verify Time (s)", "Throughput")?;
        writeln!(f, "+-{:-<30}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}-+", 
            "", "", "", "", "")?;
        
        for result in &self.benchmarks {
            let throughput = if result.proof_generation_time.as_secs_f64() > 0.0 {
                format!("{:.2}/s", result.proof_count as f64 / result.proof_generation_time.as_secs_f64())
            } else {
                "N/A".to_string()
            };
            
            writeln!(f, "| {:<30} | {:<15} | {:<15.3} | {:<15.3} | {:<10} |", 
                result.name, result.gate_count, result.proof_generation_time.as_secs_f64(), result.proof_verification_time.as_secs_f64(), throughput)?;
        }
        
        writeln!(f, "+-{:-<30}-+-{:-<15}-+-{:-<15}-+-{:-<15}-+-{:-<10}-+", 
            "", "", "", "", "")?;
        
        // Print summary statistics
        let avg_gate_count = self.benchmarks.iter().map(|r| r.gate_count).sum::<usize>() as f64 / self.benchmarks.len() as f64;
        let avg_proof_time = self.benchmarks.iter().map(|r| r.proof_generation_time.as_secs_f64()).sum::<f64>() / self.benchmarks.len() as f64;
        let avg_verify_time = self.benchmarks.iter().map(|r| r.proof_verification_time.as_secs_f64()).sum::<f64>() / self.benchmarks.len() as f64;
        
        writeln!(f, "\nSummary Statistics:")?;
        writeln!(f, "- Average Gate Count: {:.2}", avg_gate_count)?;
        writeln!(f, "- Average Proof Time: {:.3} seconds", avg_proof_time)?;
        writeln!(f, "- Average Verify Time: {:.3} seconds", avg_verify_time)?;
        
        Ok(())
    }
}

/// Save benchmark results to a file
pub fn save_benchmark_results(
    results: &BenchmarkSuiteResult,
    file_path: &str,
) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create(file_path)?;
    write!(file, "{}", results)?;
    Ok(())
}

/// Save benchmark results to a CSV file
pub fn save_benchmark_results_csv(
    results: &BenchmarkSuiteResult,
    file_path: &str,
) -> std::io::Result<()> {
    use std::fs::File;
    use std::io::Write;
    
    let mut file = File::create(file_path)?;
    
    // Write header
    writeln!(file, "Benchmark,Gates,Constraints,Public Inputs,Proof Count,Circuit Creation Time (ms),Proof Generation Time (ms),Proof Verification Time (ms),Generation Throughput,Verification Throughput")?;
    
    // Write data
    for benchmark in &results.benchmarks {
        writeln!(file, "{},{},{},{},{},{},{},{},{:.2},{:.2}",
            benchmark.name,
            benchmark.gate_count,
            benchmark.constraint_count,
            benchmark.public_input_count,
            benchmark.proof_count,
            benchmark.circuit_creation_time.as_millis(),
            benchmark.proof_generation_time.as_millis(),
            benchmark.proof_verification_time.as_millis(),
            benchmark.proof_generation_throughput(),
            benchmark.proof_verification_throughput())?;
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    
    #[test]
    fn test_benchmark_simple_circuit() {
        // Create a simple circuit
        let mut builder = CircuitBuilder::<F, D>::new(Default::default());
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        let z = builder.add_virtual_target();
        
        builder.connect(x, y);
        builder.connect(y, z);
        
        builder.register_public_input(z);
        
        let circuit = builder.build::<C>();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        pw.set_target(x, F::ONE);
        
        // Configure the benchmark
        let config = BenchmarkConfig {
            proof_count: 1,
            use_parallel: false,
            thread_count: None,
            use_recursive: false,
            max_proofs_per_step: None,
            verbose: true,
            warmup_runs: 1,
            measurement_runs: 1,
            skip_proofs: false,
        };
        
        // Run the benchmark
        let result = benchmark_circuit("Simple Circuit", "A simple circuit with 3 targets", &circuit, vec![pw], &config);
        
        // Check the results
        assert_eq!(result.name, "Simple Circuit");
        assert_eq!(result.description, "A simple circuit with 3 targets");
        assert!(result.gate_count > 0);
        assert!(result.constraint_count > 0);
        assert_eq!(result.public_input_count, 1);
        assert_eq!(result.proof_count, 1);
        assert!(result.circuit_creation_time.as_nanos() == 0); // Not measured in benchmark_circuit
        assert!(result.proof_generation_time.as_nanos() > 0);
        assert!(result.proof_verification_time.as_nanos() > 0);
    }
}
