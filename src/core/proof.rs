// Proof utilities for the 0BTC Wire system
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::PartialWitness;
use plonky2_field::types::PrimeField64;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::fmt;

/// Error type for proof operations
#[derive(Debug)]
pub enum ProofError {
    ProofGenerationError(String),
    ProofVerificationError(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProofError::ProofGenerationError(msg) => write!(f, "Proof generation error: {}", msg),
            ProofError::ProofVerificationError(msg) => write!(f, "Proof verification error: {}", msg),
            ProofError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            ProofError::DeserializationError(msg) => write!(f, "Deserialization error: {}", msg),
        }
    }
}

impl Error for ProofError {}

/// Serializable representation of a proof
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SerializableProof {
    pub public_inputs: Vec<String>,
    pub proof_bytes: String,
}

/// Generate a proof using the given circuit data and witness
pub fn generate_proof(
    circuit_data: &CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    witness: PartialWitness<GoldilocksField>,
) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>, ProofError> {
    circuit_data.prove(witness)
        .map_err(|e| ProofError::ProofGenerationError(format!("Failed to generate proof: {}", e)))
}

/// Verify a proof using the given circuit data
pub fn verify_proof(
    circuit_data: &CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
    proof: &ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) -> Result<(), ProofError> {
    circuit_data.verify(proof.clone())
        .map_err(|e| ProofError::ProofVerificationError(format!("Failed to verify proof: {}", e)))
}

/// Serialize a proof to a format suitable for JSON
pub fn serialize_proof(
    proof: &ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) -> Result<SerializableProof, ProofError> {
    // Serialize the proof to bytes
    let proof_bytes = bincode::serialize(proof)
        .map_err(|e| ProofError::SerializationError(format!("Failed to serialize proof: {}", e)))?;
    
    // Convert to hex string for JSON compatibility
    let proof_hex = hex::encode(proof_bytes);
    
    // Convert public inputs to strings
    let public_inputs = proof.public_inputs
        .iter()
        .map(|input| format!("0x{}", hex::encode(input.to_canonical_u64().to_le_bytes())))
        .collect();
    
    Ok(SerializableProof {
        public_inputs,
        proof_bytes: format!("0x{}", proof_hex),
    })
}

/// Deserialize a proof from its serialized format
pub fn deserialize_proof(
    serialized: &SerializableProof,
) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>, ProofError> {
    // Decode the hex string
    let proof_bytes = hex::decode(serialized.proof_bytes.trim_start_matches("0x"))
        .map_err(|e| ProofError::DeserializationError(format!("Failed to decode hex: {}", e)))?;
    
    // Deserialize the proof
    bincode::deserialize(&proof_bytes)
        .map_err(|e| ProofError::DeserializationError(format!("Failed to deserialize proof: {}", e)))
}
