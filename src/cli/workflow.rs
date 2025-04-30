use std::process::{Command, Stdio};
use std::time::Instant;
use log::{debug, info, warn, error};

use crate::cli::config::{Workflow, WorkflowStep};
use crate::errors::{IOError, ValidationError, WireError, WireResult};

/// Execute a workflow
pub fn execute_workflow(workflow: &Workflow, verbose: bool) -> WireResult<()> {
    info!("Executing workflow: {}", workflow.description);
    
    let start_time = Instant::now();
    
    for (step_idx, step) in workflow.steps.iter().enumerate() {
        info!("Step {}/{}: {}", step_idx + 1, workflow.steps.len(), step.name);
        
        let step_start_time = Instant::now();
        let result = execute_workflow_step(step, verbose);
        let step_elapsed = step_start_time.elapsed();
        
        match result {
            Ok(_) => {
                info!("Step completed successfully in {:?}", step_elapsed);
            }
            Err(e) => {
                error!("Step failed: {}", e);
                
                if !step.continue_on_error {
                    return Err(WireError::ValidationError(ValidationError::InputValidationError(
                        format!("Workflow step failed: {}", e)
                    )));
                } else {
                    warn!("Continuing workflow despite error (continue_on_error=true)");
                }
            }
        }
    }
    
    let elapsed = start_time.elapsed();
    info!("Workflow completed in {:?}", elapsed);
    
    Ok(())
}

/// Execute a single workflow step
fn execute_workflow_step(step: &WorkflowStep, verbose: bool) -> WireResult<()> {
    debug!("Executing command: {} {}", step.command, step.args.join(" "));
    
    // Build the command
    let mut command = if cfg!(target_os = "windows") {
        let mut cmd = Command::new("cmd");
        cmd.args(&["/C", &step.command]);
        cmd
    } else {
        Command::new(&step.command)
    };
    
    // Add arguments
    command.args(&step.args);
    
    // Configure stdio
    if verbose {
        command.stdout(Stdio::inherit());
        command.stderr(Stdio::inherit());
    } else {
        command.stdout(Stdio::null());
        command.stderr(Stdio::piped());
    }
    
    // Execute the command
    let output = command.output().map_err(|e| {
        WireError::IOError(IOError::FileSystem(format!(
            "Failed to execute command: {}",
            e
        )))
    })?;
    
    // Check if the command succeeded
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        
        return Err(WireError::ValidationError(ValidationError::InputValidationError(
            format!(
                "Command failed with exit code {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            )
        )));
    }
    
    Ok(())
}

/// Create an example workflow for demonstration purposes
pub fn create_example_workflow() -> Workflow {
    Workflow {
        description: "Complete asset transfer workflow".to_string(),
        steps: vec![
            WorkflowStep {
                name: "Generate key pair".to_string(),
                command: "wire".to_string(),
                args: vec![
                    "keygen".to_string(),
                    "--output".to_string(),
                    "transfer_keys.json".to_string(),
                ],
                continue_on_error: false,
            },
            WorkflowStep {
                name: "Generate wrapped asset mint proof".to_string(),
                command: "wire".to_string(),
                args: vec![
                    "prove".to_string(),
                    "wrapped_mint".to_string(),
                    "--input".to_string(),
                    "mint_input.json".to_string(),
                    "--output".to_string(),
                    "mint_proof.json".to_string(),
                ],
                continue_on_error: false,
            },
            WorkflowStep {
                name: "Verify wrapped asset mint proof".to_string(),
                command: "wire".to_string(),
                args: vec![
                    "verify".to_string(),
                    "wrapped_mint".to_string(),
                    "--proof".to_string(),
                    "mint_proof.json".to_string(),
                ],
                continue_on_error: true,
            },
            WorkflowStep {
                name: "Generate transfer proof".to_string(),
                command: "wire".to_string(),
                args: vec![
                    "prove".to_string(),
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
                command: "wire".to_string(),
                args: vec![
                    "verify".to_string(),
                    "transfer".to_string(),
                    "--proof".to_string(),
                    "transfer_proof.json".to_string(),
                ],
                continue_on_error: false,
            },
        ],
    }
}
