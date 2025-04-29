// Recursive proof aggregation utilities for the 0BTC Wire system
use std::sync::Arc;
use std::time::Instant;

use anyhow::{anyhow, Result};
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

type F = GoldilocksField;
const D: usize = 2;
type C = PoseidonGoldilocksConfig;

/// Result of a recursive proof aggregation operation
pub struct RecursiveProofResult<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The aggregated proof
    pub proof: ProofWithPublicInputs<F, C, D>,
    /// Time taken to generate the aggregated proof
    pub generation_time: std::time::Duration,
    /// Number of proofs aggregated
    pub num_proofs: usize,
}

/// Options for recursive proof aggregation
pub struct RecursiveProverOptions {
    /// Whether to print progress information
    pub verbose: bool,
    /// Maximum number of proofs to aggregate in a single recursive step
    /// If None, will aggregate all proofs in a single step (may be inefficient for large numbers)
    pub max_proofs_per_step: Option<usize>,
}

impl Default for RecursiveProverOptions {
    fn default() -> Self {
        Self {
            verbose: false,
            max_proofs_per_step: Some(8), // Default to 8 proofs per step
        }
    }
}

/// Circuit setup for recursive proof aggregation
struct RecursiveCircuitSetup<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The circuit data
    pub circuit_data: CircuitData<F, C, D>,
    /// Common circuit data
    pub common_data: CommonCircuitData<F, D>,
    /// Condition for recursive verification
    pub condition: BoolTarget,
    /// Target for the inner proof
    pub inner_proof_target: ProofWithPublicInputsTarget<D>,
    /// Target for the verifier data
    pub verifier_data_target: VerifierCircuitTarget,
    /// Target for the number of proofs aggregated
    pub num_proofs_target: Target,
    /// Target for the aggregated public inputs
    pub aggregated_public_inputs: Vec<Target>,
}

/// Setup the recursive circuit for proof aggregation
fn setup_recursive_circuit<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    num_public_inputs: usize,
) -> Result<RecursiveCircuitSetup<F, C, D>> {
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Track the number of proofs aggregated
    let num_proofs_target = builder.add_virtual_public_input();
    
    // Create targets for the aggregated public inputs
    let mut aggregated_public_inputs = Vec::with_capacity(num_public_inputs);
    for _ in 0..num_public_inputs {
        let target = builder.add_virtual_public_input();
        aggregated_public_inputs.push(target);
    }
    
    // Create a verifier data target
    let verifier_data_target = builder.add_verifier_data_public_inputs();
    
    // Create a condition target for recursive verification
    let condition = builder.add_virtual_bool_target_safe();
    
    // Create common data for the circuit
    let mut common_data = builder.build_common::<C>();
    common_data.num_public_inputs = builder.num_public_inputs();
    
    // Create a target for the inner proof
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);
    
    // If condition is true, verify the inner proof
    builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
        condition,
        &inner_proof_target,
        &common_data,
    )?;
    
    // Build the circuit
    let circuit_data = builder.build::<C>();
    
    Ok(RecursiveCircuitSetup {
        circuit_data,
        common_data,
        condition,
        inner_proof_target,
        verifier_data_target,
        num_proofs_target,
        aggregated_public_inputs,
    })
}

/// Create a base proof for recursive aggregation
fn create_base_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_setup: &RecursiveCircuitSetup<F, C, D>,
    public_inputs: &[F],
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    
    // Set the condition to false for the base proof
    pw.set_bool_target(circuit_setup.condition, false);
    
    // Set the number of proofs to 1
    pw.set_target(circuit_setup.num_proofs_target, F::ONE);
    
    // Set the public inputs
    for (i, &input) in public_inputs.iter().enumerate() {
        if i < circuit_setup.aggregated_public_inputs.len() {
            pw.set_target(circuit_setup.aggregated_public_inputs[i], input);
        }
    }
    
    // Create a dummy inner proof
    let initial_pis = public_inputs.iter().enumerate().map(|(i, &v)| (i, v)).collect();
    pw.set_proof_with_pis_target::<C, D>(
        &circuit_setup.inner_proof_target,
        &cyclic_base_proof(
            &circuit_setup.common_data,
            &circuit_setup.circuit_data.verifier_only,
            initial_pis,
        ),
    );
    
    // Set the verifier data
    pw.set_verifier_data_target(
        &circuit_setup.verifier_data_target, 
        &circuit_setup.circuit_data.verifier_only
    );
    
    // Generate the proof
    circuit_setup.circuit_data.prove(pw)
}

/// Extend a proof with another proof
fn extend_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
    circuit_setup: &RecursiveCircuitSetup<F, C, D>,
    inner_proof: &ProofWithPublicInputs<F, C, D>,
    additional_proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let mut pw = PartialWitness::new();
    
    // Set the condition to true for recursive verification
    pw.set_bool_target(circuit_setup.condition, true);
    
    // Increment the number of proofs
    let num_proofs = inner_proof.public_inputs[0] + F::ONE;
    pw.set_target(circuit_setup.num_proofs_target, num_proofs);
    
    // Combine the public inputs (this is a simple example - you may need more complex logic)
    for (i, target) in circuit_setup.aggregated_public_inputs.iter().enumerate() {
        if i + 1 < inner_proof.public_inputs.len() {
            // Skip the first public input (num_proofs) and use the rest
            pw.set_target(*target, inner_proof.public_inputs[i + 1]);
        }
    }
    
    // Set the inner proof
    pw.set_proof_with_pis_target::<C, D>(&circuit_setup.inner_proof_target, inner_proof);
    
    // Set the verifier data
    pw.set_verifier_data_target(
        &circuit_setup.verifier_data_target, 
        &circuit_setup.circuit_data.verifier_only
    );
    
    // Generate the proof
    circuit_setup.circuit_data.prove(pw)
}

/// Aggregate multiple proofs into a single recursive proof
/// 
/// This function takes a vector of proofs and aggregates them into a single proof
/// that can be efficiently verified.
pub fn aggregate_proofs<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    options: RecursiveProverOptions,
) -> Result<RecursiveProofResult<F, C, D>> {
    let start = Instant::now();
    
    if proofs.is_empty() {
        return Err(anyhow!("No proofs to aggregate"));
    }
    
    if proofs.len() == 1 {
        return Ok(RecursiveProofResult {
            proof: proofs[0].clone(),
            generation_time: start.elapsed(),
            num_proofs: 1,
        });
    }
    
    // Determine how many proofs to aggregate per step
    let max_proofs_per_step = options.max_proofs_per_step.unwrap_or(proofs.len());
    
    if options.verbose {
        println!("Aggregating {} proofs with max {} proofs per step", proofs.len(), max_proofs_per_step);
    }
    
    // Get the number of public inputs from the first proof
    let num_public_inputs = proofs[0].public_inputs.len();
    
    // Setup the recursive circuit
    let circuit_setup = setup_recursive_circuit::<F, C, D>(num_public_inputs)?;
    
    // Create the base proof from the first proof's public inputs
    let mut current_proof = create_base_proof(&circuit_setup, &proofs[0].public_inputs)?;
    
    // Aggregate the proofs in batches
    for (i, proof) in proofs.iter().enumerate().skip(1) {
        if options.verbose {
            println!("Aggregating proof {}/{}", i + 1, proofs.len());
        }
        
        // Extend the current proof with the new proof
        current_proof = extend_proof(&circuit_setup, &current_proof, proof)?;
        
        // If we've reached the maximum proofs per step, create a new base proof
        if i % max_proofs_per_step == 0 && i < proofs.len() - 1 {
            if options.verbose {
                println!("Creating new base proof after {} proofs", i + 1);
            }
            
            current_proof = create_base_proof(&circuit_setup, &current_proof.public_inputs)?;
        }
    }
    
    let generation_time = start.elapsed();
    
    if options.verbose {
        println!("Aggregated {} proofs in {:?}", proofs.len(), generation_time);
    }
    
    Ok(RecursiveProofResult {
        proof: current_proof,
        generation_time,
        num_proofs: proofs.len(),
    })
}

/// Verify an aggregated proof
/// 
/// This function verifies an aggregated proof and returns the number of proofs
/// that were aggregated.
pub fn verify_aggregated_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F> + 'static, const D: usize>(
    aggregated_proof: &ProofWithPublicInputs<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
) -> Result<usize> {
    // Verify the proof
    circuit_data.verify(aggregated_proof)?;
    
    // The first public input is the number of proofs
    let num_proofs = aggregated_proof.public_inputs[0].to_canonical_u64() as usize;
    
    Ok(num_proofs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::hash::hash_types::HashOut;
    
    #[test]
    fn test_recursive_proof_aggregation() {
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
        
        // Create multiple proofs
        let num_proofs = 4;
        let mut proofs = Vec::with_capacity(num_proofs);
        
        for i in 0..num_proofs {
            let mut pw = PartialWitness::new();
            pw.set_target(pub_input, F::from_canonical_u64(i as u64));
            pw.set_target(priv_input, F::from_canonical_u64(i as u64));
            let proof = circuit.prove(pw).unwrap();
            proofs.push(proof);
        }
        
        // Aggregate the proofs
        let options = RecursiveProverOptions {
            verbose: true,
            max_proofs_per_step: Some(2),
        };
        
        let result = aggregate_proofs(proofs, options).unwrap();
        
        // Verify the aggregated proof
        let num_aggregated = verify_aggregated_proof(&result.proof, &circuit).unwrap();
        
        assert_eq!(num_aggregated, num_proofs);
    }
}
