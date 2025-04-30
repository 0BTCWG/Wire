// Recursive proof aggregation utilities for the 0BTC Wire system
use std::sync::Arc;
use std::time::Instant;

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

use crate::errors::{WireError, ProofError, WireResult};

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
pub struct RecursiveCircuitSetup<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize> {
    /// The circuit data for the recursive circuit
    pub circuit_data: CircuitData<F, C, D>,
    
    /// The verifier circuit target for the inner proof
    pub verifier_circuit_target: VerifierCircuitTarget,
    
    /// The proof target for the inner proof
    pub proof_target: ProofWithPublicInputsTarget<D>,
    
    /// The number of public inputs in the circuit
    pub num_public_inputs: usize,
}

/// Setup the recursive circuit for proof aggregation
pub fn setup_recursive_circuit(
    num_public_inputs: usize,
) -> WireResult<RecursiveCircuitSetup<F, C, D>> {
    // Validate input
    if num_public_inputs == 0 {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Number of public inputs must be greater than zero".to_string()
        )));
    }
    
    if num_public_inputs > 256 {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Number of public inputs exceeds maximum allowed (256)".to_string()
        )));
    }
    
    // Create a circuit configuration suitable for recursion
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    
    // Create targets for the inner proof's verifier data
    let verifier_circuit_target = builder.add_virtual_verifier_data(num_public_inputs);
    
    // Create a target for the inner proof
    let proof_target = builder.add_virtual_proof_with_pis(&verifier_circuit_target.common_data);
    
    // Verify the inner proof
    builder.verify_proof::<C>(&proof_target, &verifier_circuit_target, &[]);
    
    // Build the circuit
    let circuit_data = builder.build::<C>();
    
    // Check that the circuit is suitable for cyclic recursion
    match check_cyclic_proof_verifier_data(&circuit_data.verifier_only, &circuit_data.common) {
        Ok(_) => {},
        Err(err) => {
            return Err(WireError::ProofError(ProofError::RecursionError(
                format!("Failed to verify cyclic proof verifier data: {}", err)
            )));
        }
    }
    
    Ok(RecursiveCircuitSetup {
        circuit_data,
        verifier_circuit_target,
        proof_target,
        num_public_inputs,
    })
}

/// Validate that proofs are compatible for aggregation
///
/// This function checks that all proofs have the same circuit type and compatible public inputs.
/// Returns an error if the proofs are not compatible.
pub fn validate_proof_compatibility(
    proofs: &[ProofWithPublicInputs<F, C, D>],
) -> WireResult<()> {
    // Check if there are any proofs to validate
    if proofs.is_empty() {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "No proofs provided for aggregation".to_string()
        )));
    }
    
    // Check for maximum number of proofs to prevent DoS
    if proofs.len() > 1024 {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Too many proofs for aggregation (maximum 1024)".to_string()
        )));
    }
    
    // Get the common data from the first proof
    let first_common = &proofs[0].proof.circuit_digest;
    let first_num_public_inputs = proofs[0].public_inputs.len();
    
    // Check that all proofs have the same circuit type and number of public inputs
    for (i, proof) in proofs.iter().enumerate().skip(1) {
        // Check circuit type
        if proof.proof.circuit_digest != *first_common {
            return Err(WireError::ProofError(ProofError::IncompatibleProofs(
                format!("Proof at index {} has a different circuit type", i)
            )));
        }
        
        // Check number of public inputs
        if proof.public_inputs.len() != first_num_public_inputs {
            return Err(WireError::ProofError(ProofError::IncompatibleProofs(
                format!("Proof at index {} has a different number of public inputs", i)
            )));
        }
    }
    
    Ok(())
}

/// Create a base proof for recursive aggregation
pub fn create_base_proof(
    circuit_setup: &RecursiveCircuitSetup<F, C, D>,
    public_inputs: &[F],
) -> WireResult<ProofWithPublicInputs<F, C, D>> {
    // Validate inputs
    if public_inputs.is_empty() {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "No public inputs provided for base proof".to_string()
        )));
    }
    
    if public_inputs.len() != circuit_setup.num_public_inputs {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            format!("Expected {} public inputs, got {}", 
                    circuit_setup.num_public_inputs, 
                    public_inputs.len())
        )));
    }
    
    // Create a base proof using the cyclic_base_proof function
    match cyclic_base_proof::<F, C, D>(
        &circuit_setup.circuit_data.common,
        &circuit_setup.circuit_data.verifier_only,
        public_inputs,
    ) {
        Ok(proof) => Ok(proof),
        Err(err) => Err(WireError::ProofError(ProofError::ProofGenerationError(
            format!("Failed to create base proof: {}", err)
        ))),
    }
}

/// Aggregate multiple proofs into a single recursive proof
///
/// This function takes a vector of proofs and aggregates them into a single proof
/// that can be efficiently verified.
pub fn aggregate_proofs(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    options: RecursiveProverOptions,
) -> WireResult<RecursiveProofResult<F, C, D>> {
    // Start the timer
    let start_time = Instant::now();
    
    // Validate that the proofs are compatible
    validate_proof_compatibility(&proofs)?;
    
    // If there are no proofs, return an error
    if proofs.is_empty() {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "No proofs provided for aggregation".to_string()
        )));
    }
    
    // If there's only one proof, return it directly
    if proofs.len() == 1 {
        return Ok(RecursiveProofResult {
            proof: proofs.into_iter().next().unwrap(),
            generation_time: start_time.elapsed(),
            num_proofs: 1,
        });
    }
    
    // Determine the batch size for aggregation
    let batch_size = options.max_proofs_per_step.unwrap_or(proofs.len());
    
    if batch_size == 0 {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Batch size must be greater than zero".to_string()
        )));
    }
    
    if batch_size > 256 {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Batch size exceeds maximum allowed (256)".to_string()
        )));
    }
    
    // Setup the recursive circuit
    let circuit_setup = setup_recursive_circuit(proofs[0].public_inputs.len())?;
    
    // Perform hierarchical aggregation
    let mut current_level = proofs;
    let mut next_level = Vec::new();
    
    while current_level.len() > 1 {
        if options.verbose {
            println!("Aggregating {} proofs...", current_level.len());
        }
        
        // Process the current level in batches
        for chunk in current_level.chunks(batch_size) {
            if chunk.len() == 1 {
                // If there's only one proof in the chunk, pass it through
                next_level.push(chunk[0].clone());
            } else {
                // Aggregate the proofs in the chunk
                let mut aggregated_proof = chunk[0].clone();
                
                for proof in chunk.iter().skip(1) {
                    // Extend the aggregated proof with the next proof
                    aggregated_proof = extend_proof(&circuit_setup, &aggregated_proof, proof)?;
                }
                
                next_level.push(aggregated_proof);
            }
        }
        
        // Move to the next level
        current_level = next_level;
        next_level = Vec::new();
    }
    
    // The final aggregated proof is the only one left in current_level
    let aggregated_proof = current_level.into_iter().next().unwrap();
    
    Ok(RecursiveProofResult {
        proof: aggregated_proof,
        generation_time: start_time.elapsed(),
        num_proofs: proofs.len(),
    })
}

/// Verify an aggregated proof
///
/// This function verifies an aggregated proof and returns the number of proofs
/// that were aggregated.
pub fn verify_aggregated_proof(
    aggregated_proof: &ProofWithPublicInputs<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
) -> WireResult<usize> {
    // Validate input
    if aggregated_proof.public_inputs.is_empty() {
        return Err(WireError::ProofError(ProofError::InvalidInput(
            "Aggregated proof has no public inputs".to_string()
        )));
    }
    
    // The last public input is the number of proofs aggregated
    let num_proofs = aggregated_proof.public_inputs[aggregated_proof.public_inputs.len() - 1].to_canonical_u64();
    
    // Verify the proof
    match circuit_data.verify(aggregated_proof) {
        Ok(true) => Ok(num_proofs as usize),
        Ok(false) => Err(WireError::ProofError(ProofError::InvalidProof(
            "Aggregated proof verification failed".to_string()
        ))),
        Err(err) => Err(WireError::ProofError(ProofError::VerificationError(
            format!("Error during proof verification: {}", err)
        ))),
    }
}

/// Extend a proof with another proof
///
/// This function extends a proof with another proof, creating a new proof that
/// verifies both the inner proof and the additional proof.
pub fn extend_proof(
    circuit_setup: &RecursiveCircuitSetup<F, C, D>,
    inner_proof: &ProofWithPublicInputs<F, C, D>,
    additional_proof: &ProofWithPublicInputs<F, C, D>,
) -> WireResult<ProofWithPublicInputs<F, C, D>> {
    // Validate inputs
    if inner_proof.public_inputs.len() != additional_proof.public_inputs.len() {
        return Err(WireError::ProofError(ProofError::IncompatibleProofs(
            format!("Proofs have different numbers of public inputs: {} vs {}", 
                    inner_proof.public_inputs.len(), 
                    additional_proof.public_inputs.len())
        )));
    }
    
    if inner_proof.proof.circuit_digest != additional_proof.proof.circuit_digest {
        return Err(WireError::ProofError(ProofError::IncompatibleProofs(
            "Proofs have different circuit types".to_string()
        )));
    }
    
    // Create a partial witness for the recursive proof
    let mut pw = PartialWitness::new();
    
    // Set the inner proof
    pw.set_proof_with_pis_target(&circuit_setup.proof_target, inner_proof);
    
    // Set the verifier data
    pw.set_verifier_data_target(
        &circuit_setup.verifier_circuit_target,
        &additional_proof.proof.verifier_data,
    );
    
    // Generate the extended proof
    match circuit_setup.circuit_data.prove(pw) {
        Ok(extended_proof) => Ok(extended_proof),
        Err(err) => Err(WireError::ProofError(ProofError::ProofGenerationError(
            format!("Failed to generate extended proof: {}", err)
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::types::Field;
    use plonky2::plonk::config::GenericConfig;
    
    #[test]
    fn test_recursive_proof_aggregation() {
        // Create a simple circuit for testing
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Add a simple constraint: a + b = c
        let a = builder.add_virtual_target();
        let b = builder.add_virtual_target();
        let c = builder.add(a, b);
        
        // Make all targets public inputs
        builder.register_public_input(a);
        builder.register_public_input(b);
        builder.register_public_input(c);
        
        // Build the circuit
        let circuit_data = builder.build::<C>();
        
        // Generate some proofs
        let mut proofs = Vec::new();
        
        for i in 0..5 {
            let mut pw = PartialWitness::new();
            let a_val = F::from_canonical_u64(i);
            let b_val = F::from_canonical_u64(i + 1);
            let c_val = a_val + b_val;
            
            pw.set_target(a, a_val);
            pw.set_target(b, b_val);
            pw.set_target(c, c_val);
            
            let proof = circuit_data.prove(pw).expect("Failed to generate proof");
            proofs.push(proof);
        }
        
        // Setup the recursive circuit
        let circuit_setup = setup_recursive_circuit(3).expect("Failed to setup recursive circuit");
        
        // Aggregate the proofs
        let options = RecursiveProverOptions {
            verbose: true,
            max_proofs_per_step: Some(2),
        };
        
        let result = aggregate_proofs(proofs, options).expect("Failed to aggregate proofs");
        
        // Verify the aggregated proof
        let num_proofs = verify_aggregated_proof(&result.proof, &circuit_setup.circuit_data)
            .expect("Failed to verify aggregated proof");
        
        assert_eq!(num_proofs, 5, "Expected 5 proofs to be aggregated");
        
        println!("Successfully aggregated and verified {} proofs", num_proofs);
        println!("Aggregation time: {:?}", result.generation_time);
    }
    
    #[test]
    fn test_empty_proofs_error() {
        // Try to aggregate an empty vector of proofs
        let proofs: Vec<ProofWithPublicInputs<F, C, D>> = Vec::new();
        let options = RecursiveProverOptions::default();
        
        let result = aggregate_proofs(proofs, options);
        assert!(result.is_err());
        
        if let Err(WireError::ProofError(ProofError::InvalidInput(msg))) = result {
            assert!(msg.contains("No proofs provided"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }
    
    #[test]
    fn test_incompatible_proofs_error() {
        // Create two different circuits
        let config = CircuitConfig::standard_recursion_config();
        
        // First circuit: a + b = c
        let mut builder1 = CircuitBuilder::<F, D>::new(config.clone());
        let a1 = builder1.add_virtual_target();
        let b1 = builder1.add_virtual_target();
        let c1 = builder1.add(a1, b1);
        builder1.register_public_input(a1);
        builder1.register_public_input(b1);
        builder1.register_public_input(c1);
        let circuit_data1 = builder1.build::<C>();
        
        // Second circuit: a * b = c
        let mut builder2 = CircuitBuilder::<F, D>::new(config);
        let a2 = builder2.add_virtual_target();
        let b2 = builder2.add_virtual_target();
        let c2 = builder2.mul(a2, b2);
        builder2.register_public_input(a2);
        builder2.register_public_input(b2);
        builder2.register_public_input(c2);
        let circuit_data2 = builder2.build::<C>();
        
        // Generate one proof from each circuit
        let mut pw1 = PartialWitness::new();
        pw1.set_target(a1, F::from_canonical_u64(2));
        pw1.set_target(b1, F::from_canonical_u64(3));
        pw1.set_target(c1, F::from_canonical_u64(5));
        let proof1 = circuit_data1.prove(pw1).expect("Failed to generate proof");
        
        let mut pw2 = PartialWitness::new();
        pw2.set_target(a2, F::from_canonical_u64(2));
        pw2.set_target(b2, F::from_canonical_u64(3));
        pw2.set_target(c2, F::from_canonical_u64(6));
        let proof2 = circuit_data2.prove(pw2).expect("Failed to generate proof");
        
        // Try to aggregate incompatible proofs
        let proofs = vec![proof1, proof2];
        let options = RecursiveProverOptions::default();
        
        let result = aggregate_proofs(proofs, options);
        assert!(result.is_err());
        
        if let Err(WireError::ProofError(ProofError::IncompatibleProofs(_))) = result {
            // Expected error
        } else {
            panic!("Expected IncompatibleProofs error");
        }
    }
}
