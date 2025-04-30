// Transfer Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, VerifierCircuitData};
use plonky2::plonk::config::{GenericConfig, GenericHashOut, Hasher, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::dummy_circuit::DummyCircuitData;
use plonky2::iop::generator::{SimpleGenerator, WitnessGenerator, WitnessGeneratorRef};

use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::core::proof::{generate_proof, verify_proof, serialize_proof, SerializableProof, ProofError};
use crate::gadgets::comparison::is_less_than_or_equal;
use crate::gadgets::{calculate_and_register_nullifier, enforce_fee_payment, sum, verify_message_signature};
use crate::errors::{WireError, WireResult};

/// Circuit for transferring assets between UTXOs
///
/// This circuit verifies ownership of input UTXOs, ensures conservation of value,
/// handles fee payment, and creates output UTXOs for recipients and change.
#[derive(Clone)]
pub struct TransferCircuit {
    /// The input UTXOs to spend
    pub input_utxos: Vec<UTXOTarget>,
    
    /// The recipient public key hashes
    pub recipient_pk_hashes: Vec<Vec<Target>>,
    
    /// The output amounts for each recipient
    pub output_amounts: Vec<Target>,
    
    /// The sender's public key
    pub sender_pk: PublicKeyTarget,
    
    /// The sender's signature
    pub sender_sig: SignatureTarget,
    
    /// The fee input UTXO (must be wBTC)
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee amount
    pub fee_amount: Target,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<Target>,
}

impl TransferCircuit {
    /// Build the transfer circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        sender_sk: Target,
        nonce: Target,
    ) -> Vec<UTXOTarget> {
        // Verify the sender's signature on the transfer request
        let mut message = Vec::new();
        
        // Add input UTXOs to the message
        for input_utxo in &self.input_utxos {
            message.extend_from_slice(&input_utxo.owner_pubkey_hash_target);
            message.extend_from_slice(&input_utxo.asset_id_target);
            message.push(input_utxo.amount_target);
            message.extend_from_slice(&input_utxo.salt_target);
        }
        
        // Add fee input UTXO to the message
        message.extend_from_slice(&self.fee_input_utxo.owner_pubkey_hash_target);
        message.extend_from_slice(&self.fee_input_utxo.asset_id_target);
        message.push(self.fee_input_utxo.amount_target);
        message.extend_from_slice(&self.fee_input_utxo.salt_target);
        
        // Add recipients and amounts to the message
        for (recipient_pk_hash, amount) in self.recipient_pk_hashes.iter().zip(self.output_amounts.iter()) {
            message.extend_from_slice(recipient_pk_hash);
            message.push(*amount);
        }
        
        // Add fee amount and reservoir address to the message
        message.push(self.fee_amount);
        message.extend_from_slice(&self.fee_reservoir_address_hash);
        
        // Add nonce to prevent replay attacks
        message.push(nonce);
        
        let is_valid = verify_message_signature(
            builder,
            &message,
            &self.sender_sig,
            &self.sender_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_valid);
        
        // Calculate and register nullifiers for all input UTXOs
        let mut nullifiers = Vec::new();
        for input_utxo in &self.input_utxos {
            let nullifier = calculate_and_register_nullifier(
                builder,
                input_utxo,
                sender_sk,
            );
            nullifiers.push(nullifier);
        }
        
        // Calculate and register nullifier for fee input UTXO
        let fee_nullifier = calculate_and_register_nullifier(
            builder,
            &self.fee_input_utxo,
            sender_sk,
        );
        nullifiers.push(fee_nullifier);
        
        // Ensure conservation of value for each asset type
        let mut asset_groups: std::collections::HashMap<Vec<Target>, (Vec<Target>, Vec<Target>)> = std::collections::HashMap::new();
        
        // Group input UTXOs by asset ID
        for input_utxo in &self.input_utxos {
            let asset_id = input_utxo.asset_id_target.clone();
            let entry = asset_groups.entry(asset_id).or_insert((Vec::new(), Vec::new()));
            entry.0.push(input_utxo.amount_target);
        }
        
        // Create output UTXOs for each recipient
        let mut output_utxos = Vec::new();
        
        for (i, (recipient_pk_hash, amount)) in self.recipient_pk_hashes.iter().zip(self.output_amounts.iter()).enumerate() {
            // Determine the asset ID from the corresponding input UTXO
            // Assuming the asset ID is the same for all inputs in this simplified example
            let asset_id = self.input_utxos[0].asset_id_target.clone();
            
            // Create a salt for the output UTXO
            let salt = builder.add_virtual_target();
            
            // Create the output UTXO
            let output_utxo = UTXOTarget {
                owner_pubkey_hash_target: recipient_pk_hash.clone(),
                asset_id_target: asset_id.clone(),
                amount_target: *amount,
                salt_target: vec![salt],
            };
            
            // Add to output UTXOs
            output_utxos.push(output_utxo);
            
            // Group output amounts by asset ID
            let entry = asset_groups.entry(asset_id).or_insert((Vec::new(), Vec::new()));
            entry.1.push(*amount);
        }
        
        // Calculate change amounts and create change UTXOs
        for (asset_id, (input_amounts, output_amounts)) in asset_groups.iter() {
            // Sum input and output amounts
            let total_input = sum(builder, input_amounts);
            let total_output = sum(builder, output_amounts);
            
            // Calculate change amount
            let change_amount = builder.sub(total_input, total_output);
            
            // Create a change UTXO if change amount is positive
            let is_positive = builder.add_virtual_bool_target_safe();
            builder.connect(is_positive.target, builder.is_equal(change_amount, builder.zero()).target);
            
            // If change amount is positive, create a change UTXO
            let salt = builder.add_virtual_target();
            
            let change_utxo = UTXOTarget {
                owner_pubkey_hash_target: self.sender_pk.to_hash_target(builder),
                asset_id_target: asset_id.clone(),
                amount_target: change_amount,
                salt_target: vec![salt],
            };
            
            // Add to output UTXOs
            output_utxos.push(change_utxo);
        }
        
        // Handle fee payment
        enforce_fee_payment(
            builder,
            self.fee_amount,
            &self.fee_input_utxo,
            &self.fee_reservoir_address_hash,
        );
        
        // Register public inputs for verification
        // Register nullifiers as public inputs
        for nullifier in &nullifiers {
            builder.register_public_input(*nullifier);
        }
        
        // Register output UTXOs as public inputs
        for output_utxo in &output_utxos {
            for target in &output_utxo.owner_pubkey_hash_target {
                builder.register_public_input(*target);
            }
            for target in &output_utxo.asset_id_target {
                builder.register_public_input(*target);
            }
            builder.register_public_input(output_utxo.amount_target);
            for target in &output_utxo.salt_target {
                builder.register_public_input(*target);
            }
        }
        
        // Return the output UTXOs
        output_utxos
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a sender secret key
        let sender_sk = builder.add_virtual_target();
        
        // Create a nonce
        let nonce = builder.add_virtual_target();
        
        // Create a sender public key
        let sender_pk = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Create a signature
        let signature = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create input UTXOs (just one for simplicity)
        let input_utxo = UTXOTarget::new_virtual(&mut builder);
        
        // Create a fee input UTXO
        let fee_input_utxo = UTXOTarget::new_virtual(&mut builder);
        
        // Create recipient public key hash (just one for simplicity)
        let recipient_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create output amount
        let output_amount = builder.add_virtual_target();
        
        // Create fee amount
        let fee_amount = builder.add_virtual_target();
        
        // Create fee reservoir address hash
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create the circuit
        let circuit = TransferCircuit {
            input_utxos: vec![input_utxo],
            recipient_pk_hashes: vec![recipient_pk_hash],
            output_amounts: vec![output_amount],
            sender_pk,
            sender_sig: signature,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
        };
        
        // Build the circuit
        circuit.build(&mut builder, sender_sk, nonce);
        
        // Build the circuit data
        builder.build()
    }
    
    /// Generate a proof for the transfer circuit
    pub fn generate_proof(
        &self,
        input_utxos_data: Vec<(Vec<u8>, Vec<u8>, u64, Vec<u8>)>, // (owner_pubkey_hash, asset_id, amount, salt)
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        sender_sk: u64,
        sender_pk_x: u64,
        sender_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        fee_input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
        nonce: u64,
    ) -> WireResult<SerializableProof> {
        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a sender secret key
        let sender_sk_target = builder.add_virtual_target();
        
        // Create a nonce
        let nonce_target = builder.add_virtual_target();
        
        // Create a sender public key
        let sender_pk_target = PublicKeyTarget {
            point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Create a signature
        let signature_target = SignatureTarget {
            r_point: PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create input UTXOs
        let mut input_utxos_targets = Vec::new();
        for (owner_pubkey_hash, asset_id, _, salt) in &input_utxos_data {
            let input_utxo = UTXOTarget {
                owner_pubkey_hash_target: owner_pubkey_hash.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                asset_id_target: asset_id.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: salt.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };
            input_utxos_targets.push(input_utxo);
        }
        
        // Create fee input UTXO
        let (fee_owner_pubkey_hash, fee_asset_id, _, fee_salt) = &fee_input_utxo_data;
        let fee_input_utxo_target = UTXOTarget {
            owner_pubkey_hash_target: fee_owner_pubkey_hash.iter()
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: fee_asset_id.iter()
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: fee_salt.iter()
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Create recipient public key hashes
        let mut recipient_pk_hashes_targets = Vec::new();
        for pk_hash in &recipient_pk_hashes {
            let pk_hash_targets: Vec<Target> = pk_hash.iter()
                .map(|_| builder.add_virtual_target())
                .collect();
            recipient_pk_hashes_targets.push(pk_hash_targets);
        }
        
        // Create output amounts
        let output_amounts_targets: Vec<Target> = output_amounts.iter()
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create fee amount
        let fee_amount_target = builder.add_virtual_target();
        
        // Create fee reservoir address hash
        let fee_reservoir_address_hash_targets: Vec<Target> = fee_reservoir_address_hash.iter()
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create the circuit
        let circuit = TransferCircuit {
            input_utxos: input_utxos_targets.clone(),
            recipient_pk_hashes: recipient_pk_hashes_targets.clone(),
            output_amounts: output_amounts_targets.clone(),
            sender_pk: sender_pk_target.clone(),
            sender_sig: signature_target.clone(),
            fee_input_utxo: fee_input_utxo_target.clone(),
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets.clone(),
        };
        
        // Build the circuit
        circuit.build(&mut builder, sender_sk_target, nonce_target);
        
        // Build the circuit data
        let circuit_data = builder.build();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Set the witness values
        pw.set_target(sender_sk_target, GoldilocksField::from_canonical_u64(sender_sk));
        pw.set_target(nonce_target, GoldilocksField::from_canonical_u64(nonce));
        
        pw.set_target(sender_pk_target.point.x, GoldilocksField::from_canonical_u64(sender_pk_x));
        pw.set_target(sender_pk_target.point.y, GoldilocksField::from_canonical_u64(sender_pk_y));
        
        pw.set_target(signature_target.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x));
        pw.set_target(signature_target.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y));
        pw.set_target(signature_target.s_scalar, GoldilocksField::from_canonical_u64(signature_s));
        
        // Set input UTXOs
        for (i, ((owner_pubkey_hash, asset_id, amount, salt), input_utxo)) in 
            input_utxos_data.iter().zip(input_utxos_targets.iter()).enumerate() {
            
            for (j, (byte, target)) in owner_pubkey_hash.iter().zip(input_utxo.owner_pubkey_hash_target.iter()).enumerate() {
                pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
            }
            
            for (j, (byte, target)) in asset_id.iter().zip(input_utxo.asset_id_target.iter()).enumerate() {
                pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
            }
            
            pw.set_target(input_utxo.amount_target, GoldilocksField::from_canonical_u64(*amount));
            
            for (j, (byte, target)) in salt.iter().zip(input_utxo.salt_target.iter()).enumerate() {
                pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
            }
        }
        
        // Set fee input UTXO
        let (fee_owner_pubkey_hash, fee_asset_id, fee_utxo_amount, fee_salt) = &fee_input_utxo_data;
        
        for (j, (byte, target)) in fee_owner_pubkey_hash.iter().zip(fee_input_utxo_target.owner_pubkey_hash_target.iter()).enumerate() {
            pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
        }
        
        for (j, (byte, target)) in fee_asset_id.iter().zip(fee_input_utxo_target.asset_id_target.iter()).enumerate() {
            pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
        }
        
        pw.set_target(fee_input_utxo_target.amount_target, GoldilocksField::from_canonical_u64(*fee_utxo_amount));
        
        for (j, (byte, target)) in fee_salt.iter().zip(fee_input_utxo_target.salt_target.iter()).enumerate() {
            pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
        }
        
        // Set recipient public key hashes
        for (i, (pk_hash, pk_hash_targets)) in recipient_pk_hashes.iter().zip(recipient_pk_hashes_targets.iter()).enumerate() {
            for (j, (byte, target)) in pk_hash.iter().zip(pk_hash_targets.iter()).enumerate() {
                pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
            }
        }
        
        // Set output amounts
        for (i, (amount, target)) in output_amounts.iter().zip(output_amounts_targets.iter()).enumerate() {
            pw.set_target(*target, GoldilocksField::from_canonical_u64(*amount));
        }
        
        // Set fee amount
        pw.set_target(fee_amount_target, GoldilocksField::from_canonical_u64(fee_amount));
        
        // Set fee reservoir address hash
        for (i, (byte, target)) in fee_reservoir_address_hash.iter().zip(fee_reservoir_address_hash_targets.iter()).enumerate() {
            pw.set_target(*target, GoldilocksField::from_canonical_u64(*byte as u64));
        }
        
        // Generate the proof
        let proof = circuit_data.prove(pw)
            .map_err(|e| WireError::ProofError(ProofError::ProofGenerationError(format!("Failed to generate proof: {}", e))))?;
        
        // Serialize the proof
        serialize_proof(&proof)
            .map_err(|e| WireError::ProofError(e))
    }
    
    /// Generate a proof for the transfer circuit (static method)
    pub fn generate_proof_static(
        input_utxos_data: Vec<(Vec<u8>, Vec<u8>, u64, Vec<u8>)>, // (owner_pubkey_hash, asset_id, amount, salt)
        recipient_pk_hashes: Vec<Vec<u8>>,
        output_amounts: Vec<u64>,
        sender_sk: u64,
        sender_pk_x: u64,
        sender_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        fee_input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
        nonce: u64,
    ) -> WireResult<SerializableProof> {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create input UTXOs
        let mut input_utxos = Vec::new();
        for (owner_pubkey_hash, asset_id, _, salt) in &input_utxos_data {
            let input_utxo = UTXOTarget {
                owner_pubkey_hash_target: owner_pubkey_hash.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                asset_id_target: asset_id.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: salt.iter()
                    .map(|_| builder.add_virtual_target())
                    .collect(),
            };
            input_utxos.push(input_utxo);
        }
        
        // Create the circuit instance
        let circuit = TransferCircuit {
            input_utxos,
            recipient_pk_hashes: Vec::new(), // Will be populated in generate_proof
            output_amounts: Vec::new(),      // Will be populated in generate_proof
            sender_pk: PublicKeyTarget {
                point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
            },
            sender_sig: SignatureTarget {
                r_point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
                s_scalar: builder.add_virtual_target(),
            },
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: Vec::new(),
                asset_id_target: Vec::new(),
                amount_target: builder.add_virtual_target(),
                salt_target: Vec::new(),
            },
            fee_amount: builder.add_virtual_target(),
            fee_reservoir_address_hash: Vec::new(),
        };
        
        // Generate the proof
        circuit.generate_proof(
            input_utxos_data,
            recipient_pk_hashes,
            output_amounts,
            sender_sk,
            sender_pk_x,
            sender_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            fee_input_utxo_data,
            fee_amount,
            fee_reservoir_address_hash,
            nonce,
        )
    }
    
    /// Verify a proof for this circuit
    pub fn verify_proof(serializable_proof: &SerializableProof) -> WireResult<()> {
        let circuit_data = Self::create_circuit();
        let proof = serializable_proof.to_proof::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&circuit_data.common)
            .map_err(|e| WireError::ProofError(ProofError::VerificationError(format!("Failed to deserialize proof: {}", e))))?;
        
        circuit_data.verify(proof)
            .map_err(|e| WireError::ProofError(ProofError::VerificationError(format!("Failed to verify proof: {}", e))))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transfer() {
        // This is a placeholder test
        // In a real implementation, this would test the circuit with actual inputs
        let circuit_data = TransferCircuit::create_circuit();
        assert!(circuit_data.common.num_public_inputs > 0);
    }
}
