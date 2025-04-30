use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::errors::{IOError, ValidationError, WireError, WireResult};

/// Configuration for the Wire CLI
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WireConfig {
    /// Global configuration options
    #[serde(default)]
    pub global: GlobalConfig,
    
    /// Circuit-specific configurations
    #[serde(default)]
    pub circuits: CircuitConfigs,
    
    /// Batch processing configurations
    #[serde(default)]
    pub batch: BatchConfig,
    
    /// Workflow configurations
    #[serde(default)]
    pub workflows: HashMap<String, Workflow>,
}

/// Global configuration options
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct GlobalConfig {
    /// Default output directory for proofs
    #[serde(default = "default_output_dir")]
    pub output_dir: String,
    
    /// Whether to enable verbose logging
    #[serde(default)]
    pub verbose: bool,
    
    /// Number of threads to use for parallel operations
    #[serde(default = "default_threads")]
    pub threads: usize,
    
    /// Default key file path
    #[serde(default = "default_key_file")]
    pub key_file: String,
}

/// Circuit-specific configurations
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CircuitConfigs {
    /// Wrapped asset mint circuit configuration
    #[serde(default)]
    pub wrapped_mint: CircuitConfig,
    
    /// Wrapped asset burn circuit configuration
    #[serde(default)]
    pub wrapped_burn: CircuitConfig,
    
    /// Transfer circuit configuration
    #[serde(default)]
    pub transfer: CircuitConfig,
    
    /// Native asset create circuit configuration
    #[serde(default)]
    pub native_create: CircuitConfig,
    
    /// Native asset mint circuit configuration
    #[serde(default)]
    pub native_mint: CircuitConfig,
    
    /// Native asset burn circuit configuration
    #[serde(default)]
    pub native_burn: CircuitConfig,
}

/// Configuration for a specific circuit
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct CircuitConfig {
    /// Default input file path template
    #[serde(default = "default_input_template")]
    pub input_template: String,
    
    /// Default output file path template
    #[serde(default = "default_output_template")]
    pub output_template: String,
    
    /// Circuit-specific optimization level
    #[serde(default = "default_optimization_level")]
    pub optimization_level: usize,
}

/// Batch processing configuration
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct BatchConfig {
    /// Maximum number of proofs to process in a single batch
    #[serde(default = "default_batch_size")]
    pub batch_size: usize,
    
    /// Whether to use parallel processing for batches
    #[serde(default = "default_parallel")]
    pub parallel: bool,
    
    /// Input directory for batch processing
    #[serde(default = "default_batch_input_dir")]
    pub input_dir: String,
    
    /// Output directory for batch processing
    #[serde(default = "default_batch_output_dir")]
    pub output_dir: String,
}

/// Workflow configuration
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Workflow {
    /// Description of the workflow
    pub description: String,
    
    /// Steps in the workflow
    pub steps: Vec<WorkflowStep>,
}

/// Step in a workflow
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WorkflowStep {
    /// Name of the step
    pub name: String,
    
    /// Command to execute
    pub command: String,
    
    /// Arguments for the command
    #[serde(default)]
    pub args: Vec<String>,
    
    /// Whether to continue if this step fails
    #[serde(default)]
    pub continue_on_error: bool,
}

/// Default functions for configuration options
fn default_output_dir() -> String {
    "proofs".to_string()
}

fn default_threads() -> usize {
    num_cpus::get()
}

fn default_key_file() -> String {
    "keys.json".to_string()
}

fn default_input_template() -> String {
    "{circuit_type}_input.json".to_string()
}

fn default_output_template() -> String {
    "{circuit_type}_proof.json".to_string()
}

fn default_optimization_level() -> usize {
    2
}

fn default_batch_size() -> usize {
    8
}

fn default_parallel() -> bool {
    true
}

fn default_batch_input_dir() -> String {
    "batch_inputs".to_string()
}

fn default_batch_output_dir() -> String {
    "batch_outputs".to_string()
}

impl Default for WireConfig {
    fn default() -> Self {
        WireConfig {
            global: GlobalConfig::default(),
            circuits: CircuitConfigs::default(),
            batch: BatchConfig::default(),
            workflows: HashMap::new(),
        }
    }
}

impl WireConfig {
    /// Load configuration from a file
    pub fn load<P: AsRef<Path>>(path: P) -> WireResult<Self> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(WireError::IOError(IOError::FileSystem(format!(
                "Configuration file not found: {}",
                path.display()
            ))));
        }
        
        let content = fs::read_to_string(path).map_err(|e| {
            WireError::IOError(IOError::FileSystem(format!(
                "Failed to read configuration file: {}",
                e
            )))
        })?;
        
        let config: WireConfig = serde_json::from_str(&content).map_err(|e| {
            WireError::IOError(IOError::Deserialization(format!(
                "Failed to parse configuration file: {}",
                e
            )))
        })?;
        
        Ok(config)
    }
    
    /// Save configuration to a file
    pub fn save<P: AsRef<Path>>(&self, path: P) -> WireResult<()> {
        let path = path.as_ref();
        
        // Create parent directories if they don't exist
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                WireError::IOError(IOError::FileSystem(format!(
                    "Failed to create directory: {}",
                    e
                )))
            })?;
        }
        
        let content = serde_json::to_string_pretty(self).map_err(|e| {
            WireError::IOError(IOError::Serialization(format!(
                "Failed to serialize configuration: {}",
                e
            )))
        })?;
        
        fs::write(path, content).map_err(|e| {
            WireError::IOError(IOError::FileSystem(format!(
                "Failed to write configuration file: {}",
                e
            )))
        })?;
        
        Ok(())
    }
    
    /// Create a default configuration file if it doesn't exist
    pub fn create_default<P: AsRef<Path>>(path: P) -> WireResult<()> {
        let path = path.as_ref();
        
        if path.exists() {
            return Err(WireError::ValidationError(ValidationError::FormatError(
                format!("Configuration file already exists: {}", path.display())
            )));
        }
        
        let config = WireConfig::default();
        config.save(path)?;
        
        Ok(())
    }
    
    /// Get circuit configuration by name
    pub fn get_circuit_config(&self, circuit_type: &str) -> WireResult<&CircuitConfig> {
        match circuit_type {
            "wrapped_mint" => Ok(&self.circuits.wrapped_mint),
            "wrapped_burn" => Ok(&self.circuits.wrapped_burn),
            "transfer" => Ok(&self.circuits.transfer),
            "native_create" => Ok(&self.circuits.native_create),
            "native_mint" => Ok(&self.circuits.native_mint),
            "native_burn" => Ok(&self.circuits.native_burn),
            _ => Err(WireError::ValidationError(ValidationError::InputValidationError(
                format!("Unknown circuit type: {}", circuit_type)
            ))),
        }
    }
    
    /// Get workflow by name
    pub fn get_workflow(&self, name: &str) -> WireResult<&Workflow> {
        self.workflows.get(name).ok_or_else(|| {
            WireError::ValidationError(ValidationError::InputValidationError(
                format!("Workflow not found: {}", name)
            ))
        })
    }
}

/// Example configuration
pub fn example_config() -> WireConfig {
    let mut config = WireConfig::default();
    
    // Add an example workflow
    let transfer_workflow = Workflow {
        description: "Generate and verify a transfer proof".to_string(),
        steps: vec![
            WorkflowStep {
                name: "Generate transfer proof".to_string(),
                command: "prove".to_string(),
                args: vec![
                    "transfer".to_string(),
                    "--input".to_string(),
                    "transfer_input.json".to_string(),
                    "--output".to_string(),
                    "transfer_proof.json".to_string(),
                ],
                continue_on_error: false,
            },
            WorkflowStep {
                name: "Verify transfer proof".to_string(),
                command: "verify".to_string(),
                args: vec![
                    "transfer".to_string(),
                    "--proof".to_string(),
                    "transfer_proof.json".to_string(),
                ],
                continue_on_error: false,
            },
        ],
    };
    
    config.workflows.insert("transfer".to_string(), transfer_workflow);
    
    config
}
