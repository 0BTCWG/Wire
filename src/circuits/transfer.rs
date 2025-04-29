// Transfer Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::plonk::prover::prove;

use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::core::proof::{generate_proof, verify_proof, serialize_proof, SerializableProof, ProofError};
use crate::gadgets::comparison::is_less_than_or_equal;
use crate::gadgets::{calculate_and_register_nullifier, enforce_fee_payment, sum, verify_message_signature};

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
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        sender_sk: Target,
    ) -> (Vec<UTXOTarget>, UTXOTarget, Option<UTXOTarget>) {
        // Verify the sender's signature over the transfer details
        let mut message = Vec::new();
        
        // Include recipient details in the message
        for recipient_pk_hash in &self.recipient_pk_hashes {
            message.extend_from_slice(recipient_pk_hash);
        }
        
        // Include output amounts in the message
        for &amount in &self.output_amounts {
            message.push(amount);
        }
        
        // Include asset ID in the message (assuming all inputs have the same asset ID)
        message.extend_from_slice(&self.input_utxos[0].asset_id_target);
        
        // Include a nonce in the message (could be a timestamp or random value)
        let nonce = builder.add_virtual_target();
        message.push(nonce);
        
        // Verify the signature
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.sender_sig,
            &self.sender_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Calculate and register nullifiers for all input UTXOs
        for input_utxo in &self.input_utxos {
            calculate_and_register_nullifier(
                builder,
                &input_utxo.salt_target,
                sender_sk,
            );
        }
        
        // Sum input amounts
        let input_amounts: Vec<Target> = self.input_utxos
            .iter()
            .map(|utxo| utxo.amount_target)
            .collect();
        let input_sum = sum(builder, &input_amounts);
        
        // Sum output amounts
        let output_sum = sum(builder, &self.output_amounts);
        
        // Verify conservation of value: input_sum >= output_sum
        let is_conserved = is_less_than_or_equal(builder, output_sum, input_sum);
        builder.assert_one(is_conserved);
        
        // Handle fee payment
        let _wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.sender_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &self.sender_sig,
        );
        
        // Calculate primary asset change
        let primary_change = builder.sub(input_sum, output_sum);
        
        // Create output UTXOs for recipients
        let mut output_utxos = Vec::new();
        for i in 0..self.recipient_pk_hashes.len() {
            let output_utxo = UTXOTarget::add_virtual(builder, self.input_utxos[0].asset_id_target.len());
            
            // Set the owner to the recipient
            for (a, b) in output_utxo.owner_pubkey_hash_target.iter().zip(self.recipient_pk_hashes[i].iter()) {
                builder.connect(*a, *b);
            }
            
            // Set the asset ID to the same as the input
            for (a, b) in output_utxo.asset_id_target.iter().zip(self.input_utxos[0].asset_id_target.iter()) {
                builder.connect(*a, *b);
            }
            
            // Set the amount
            builder.connect(output_utxo.amount_target, self.output_amounts[i]);
            
            // The salt is a random value, so we don't need to connect it
            
            output_utxos.push(output_utxo);
        }
        
        // Create a change UTXO for the primary asset if needed
        let zero = builder.zero();
        let is_zero = crate::gadgets::is_equal(builder, primary_change, zero);
        let primary_change_utxo = if is_zero == builder.one() {
            None
        } else {
            let change_utxo = UTXOTarget::add_virtual(builder, self.input_utxos[0].asset_id_target.len());
            
            // Set the owner to the sender
            for (a, b) in change_utxo.owner_pubkey_hash_target.iter().zip(self.input_utxos[0].owner_pubkey_hash_target.iter()) {
                builder.connect(*a, *b);
            }
            
            // Set the asset ID to the same as the input
            for (a, b) in change_utxo.asset_id_target.iter().zip(self.input_utxos[0].asset_id_target.iter()) {
                builder.connect(*a, *b);
            }
            
            // Set the amount to the change
            builder.connect(change_utxo.amount_target, primary_change);
            
            // The salt is a random value, so we don't need to connect it
            
            Some(change_utxo)
        };
        
        // Create a fee UTXO for the reservoir
        let fee_utxo = UTXOTarget::add_virtual(builder, self.fee_input_utxo.asset_id_target.len());
        
        // Set the owner to the fee reservoir
        for (a, b) in fee_utxo.owner_pubkey_hash_target.iter().zip(self.fee_reservoir_address_hash.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the asset ID to wBTC (same as fee input)
        for (a, b) in fee_utxo.asset_id_target.iter().zip(self.fee_input_utxo.asset_id_target.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the amount to the fee
        builder.connect(fee_utxo.amount_target, self.fee_amount);
        
        // Return the output UTXOs, fee UTXO, and optional change UTXO
        (output_utxos, fee_utxo, primary_change_utxo)
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        let input_utxos = vec![input_utxo];
        
        let recipient_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        let recipient_pk_hashes = vec![recipient_pk_hash];
        
        let output_amount = builder.add_virtual_target();
        let output_amounts = vec![output_amount];
        
        let sender_pk = PublicKeyTarget::add_virtual(&mut builder);
        let sender_sig = SignatureTarget::add_virtual(&mut builder);
        
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        // Use a virtual target for fee_amount instead of a constant
        let fee_amount = builder.add_virtual_target();
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let circuit = TransferCircuit {
            input_utxos,
            recipient_pk_hashes,
            output_amounts,
            sender_pk,
            sender_sig,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
        };
        
        // Add a virtual target for the sender's secret key
        let sender_sk = builder.add_virtual_target();
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, sender_sk);
        
        builder.build::<PoseidonGoldilocksConfig>()
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
    ) -> Result<SerializableProof, ProofError> {
        // Create the circuit
        let circuit_data = Self::create_circuit();
        let mut pw = PartialWitness::new();
        
        // Create a new circuit builder for virtual targets
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create input UTXOs
        let mut input_utxos = Vec::new();
        for (owner_pubkey_hash, asset_id, amount, salt) in &input_utxos_data {
            let utxo = UTXOTarget::add_virtual(&mut builder, salt.len());
            
            // Set witness values for the UTXO
            for (i, byte) in owner_pubkey_hash.iter().enumerate() {
                if i < utxo.owner_pubkey_hash_target.len() {
                    pw.set_target(
                        utxo.owner_pubkey_hash_target[i],
                        GoldilocksField::from_canonical_u64(*byte as u64),
                    );
                }
            }
            for (i, byte) in asset_id.iter().enumerate() {
                if i < utxo.asset_id_target.len() {
                    pw.set_target(
                        utxo.asset_id_target[i],
                        GoldilocksField::from_canonical_u64(*byte as u64),
                    );
                }
            }
            
            pw.set_target(utxo.amount_target, GoldilocksField::from_canonical_u64(*amount as u64));
            
            for (i, byte) in salt.iter().enumerate() {
                if i < utxo.salt_target.len() {
                    pw.set_target(
                        utxo.salt_target[i],
                        GoldilocksField::from_canonical_u64(*byte as u64),
                    );
                }
            }
            input_utxos.push(utxo);
        }
        
        // Create recipient public key hashes
        let mut recipient_pk_hash_targets = Vec::new();
        for pk_hash in &recipient_pk_hashes {
            let pk_hash_targets: Vec<Target> = (0..pk_hash.len())
                .map(|_| builder.add_virtual_target())
                .collect();
            
            for (i, byte) in pk_hash.iter().enumerate() {
                if i < pk_hash_targets.len() {
                    pw.set_target(
                        pk_hash_targets[i],
                        GoldilocksField::from_canonical_u64(*byte as u64),
                    );
                }
            }
            recipient_pk_hash_targets.push(pk_hash_targets);
        }
        
        // Create output amount targets
        let output_amount_targets: Vec<Target> = (0..output_amounts.len())
            .map(|_| builder.add_virtual_target())
            .collect();
        
        for (i, &amount) in output_amounts.iter().enumerate() {
            pw.set_target(
                output_amount_targets[i],
                GoldilocksField::from_canonical_u64(amount as u64),
            );
        }
        
        // Create sender's public key and signature
        let sender_pk = PublicKeyTarget::add_virtual(&mut builder);
        let sender_sig = SignatureTarget::add_virtual(&mut builder);
        
        // Set witness values for the sender's public key
        pw.set_target(sender_pk.point.x, GoldilocksField::from_canonical_u64(sender_pk_x as u64));
        pw.set_target(sender_pk.point.y, GoldilocksField::from_canonical_u64(sender_pk_y as u64));
        
        // Set witness values for the sender's signature
        pw.set_target(sender_sig.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x as u64));
        pw.set_target(sender_sig.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y as u64));
        pw.set_target(sender_sig.s_scalar, GoldilocksField::from_canonical_u64(signature_s as u64));
        
        // Create fee input UTXO
        let (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt) = &fee_input_utxo_data;
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, fee_salt.len());
        
        for (i, byte) in fee_owner_pubkey_hash.iter().enumerate() {
            if i < fee_input_utxo.owner_pubkey_hash_target.len() {
                pw.set_target(
                    fee_input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        for (i, byte) in fee_asset_id.iter().enumerate() {
            if i < fee_input_utxo.asset_id_target.len() {
                pw.set_target(
                    fee_input_utxo.asset_id_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        pw.set_target(fee_input_utxo.amount_target, GoldilocksField::from_canonical_u64(*fee_amount_value as u64));
        
        for (i, byte) in fee_salt.iter().enumerate() {
            if i < fee_input_utxo.salt_target.len() {
                pw.set_target(
                    fee_input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Create fee amount target
        let fee_amount_target = builder.add_virtual_target();
        pw.set_target(fee_amount_target, GoldilocksField::from_canonical_u64(fee_amount as u64));
        
        // Create fee reservoir address hash
        let fee_reservoir_address_hash_targets: Vec<Target> = (0..fee_reservoir_address_hash.len())
            .map(|_| builder.add_virtual_target())
            .collect();
        
        for (i, byte) in fee_reservoir_address_hash.iter().enumerate() {
            if i < fee_reservoir_address_hash_targets.len() {
                pw.set_target(
                    fee_reservoir_address_hash_targets[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Create the circuit
        let _circuit = TransferCircuit {
            input_utxos,
            recipient_pk_hashes: recipient_pk_hash_targets,
            output_amounts: output_amount_targets,
            sender_pk,
            sender_sig,
            fee_input_utxo,
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
        };
        
        // Add a virtual target for the sender's secret key
        let sender_sk_target = builder.add_virtual_target();
        pw.set_target(sender_sk_target, GoldilocksField::from_canonical_u64(sender_sk as u64));
        
        // Add a virtual target for the nonce
        let nonce_target = builder.add_virtual_target();
        pw.set_target(nonce_target, GoldilocksField::from_canonical_u64(nonce as u64));
        
        // Generate the proof
        let proof = generate_proof(&circuit_data, pw)?;
        
        // Serialize the proof
        serialize_proof(&proof)
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
    ) -> Result<SerializableProof, ProofError> {
        // Create a dummy circuit instance
        let circuit = Self {
            input_utxos: vec![],
            recipient_pk_hashes: vec![],
            output_amounts: vec![],
            sender_pk: PublicKeyTarget {
                point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
            },
            sender_sig: SignatureTarget {
                r_point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
                s_scalar: Target::default(),
            },
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: vec![],
                asset_id_target: vec![],
                amount_target: Target::default(),
                salt_target: vec![],
            },
            fee_amount: Target::default(),
            fee_reservoir_address_hash: vec![],
        };
        
        // Call the instance method
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
    
    /// Verify a proof for the circuit
    pub fn verify_proof(serialized_proof: &SerializableProof) -> Result<(), ProofError> {
        // Create the circuit
        let circuit_data = Self::create_circuit();
        
        // Deserialize the proof
        let proof = crate::core::proof::deserialize_proof(serialized_proof)?;
        
        // Verify the proof
        verify_proof(&circuit_data, &proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_transfer() {
        // This test verifies that we can create and build the circuit
        let circuit_data = TransferCircuit::create_circuit();
        
        // Just verify that the circuit was created successfully
        assert!(circuit_data.common.gates.len() > 0, "Circuit should have gates");
    }
}
