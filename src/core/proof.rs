// Proof utilities for the 0BTC Wire system
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::PrimeField64;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::plonk::circuit_data::{CircuitData, CommonCircuitData};
use plonky2::plonk::config::{PoseidonGoldilocksConfig, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::iop::witness::PartialWitness;
use serde::{Serialize, Deserialize};
use std::error::Error;
use std::fmt;

/// Error type for proof operations
#[derive(Debug)]
pub enum ProofError {
    ProofGenerationError(String),
    VerificationError(String),
    SerializationError(String),
    DeserializationError(String),
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ProofError::ProofGenerationError(msg) => write!(f, "Proof generation error: {}", msg),
            ProofError::VerificationError(msg) => write!(f, "Proof verification error: {}", msg),
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

impl SerializableProof {
    /// Convert the serializable proof back to a Plonky2 proof
    pub fn to_proof<F: PrimeField64 + RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        common_data: &CommonCircuitData<F, D>,
    ) -> Result<ProofWithPublicInputs<F, C, D>, ProofError> {
        let proof_bytes = hex::decode(&self.proof_bytes)
            .map_err(|e| ProofError::DeserializationError(format!("Failed to decode proof bytes: {}", e)))?;
        
        let proof = ProofWithPublicInputs::from_bytes(proof_bytes, common_data)
            .map_err(|e| ProofError::DeserializationError(format!("Failed to deserialize proof: {}", e)))?;
        
        Ok(proof)
    }
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
    proof: ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) -> Result<(), ProofError> {
    circuit_data.verify(proof)
        .map_err(|e| ProofError::VerificationError(format!("Failed to verify proof: {}", e)))
}

/// Serialize a proof to a format suitable for JSON
pub fn serialize_proof(
    proof: &ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>,
) -> Result<SerializableProof, ProofError> {
    let proof_bytes = proof.to_bytes();
    
    let proof_hex = hex::encode(proof_bytes);
    
    let public_inputs: Vec<String> = proof.public_inputs
        .iter()
        .map(|input| input.to_canonical_u64().to_string())
        .collect();
    
    Ok(SerializableProof {
        public_inputs,
        proof_bytes: proof_hex,
    })
}

/// Deserialize a proof from its serialized format
pub fn deserialize_proof(
    serialized: &SerializableProof,
    common_data: &CommonCircuitData<GoldilocksField, 2>,
) -> Result<ProofWithPublicInputs<GoldilocksField, PoseidonGoldilocksConfig, 2>, ProofError> {
    serialized.to_proof(common_data)
}
