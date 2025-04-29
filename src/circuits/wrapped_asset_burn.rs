// Wrapped Asset Burn Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget};
use crate::core::proof::{generate_proof, verify_proof, serialize_proof, SerializableProof, ProofError};
use crate::gadgets::{calculate_and_register_nullifier, verify_message_signature};

/// Represents a signed fee quote from the custodian
#[derive(Debug, Clone)]
pub struct SignedQuoteTarget {
    /// The fee amount in BTC
    pub fee_btc: Target,
    
    /// The quote expiry timestamp
    pub expiry: Target,
    
    /// The custodian's signature
    pub signature: SignatureTarget,
}

/// Circuit for burning wrapped Bitcoin (wBTC)
///
/// This circuit verifies ownership of wBTC UTXOs, burns them,
/// and creates an authenticated withdrawal request for the custodian.
#[derive(Clone)]
pub struct WrappedAssetBurnCircuit {
    /// The wBTC UTXO to burn
    pub input_utxo: UTXOTarget,
    
    /// The sender's public key
    pub sender_pk: PublicKeyTarget,
    
    /// The sender's signature
    pub sender_sig: SignatureTarget,
    
    /// The destination BTC address data
    pub destination_btc_address: Vec<Target>,
    
    /// Optional fee quote from the custodian
    pub fee_quote: Option<SignedQuoteTarget>,
    
    /// The custodian's public key (for verifying the fee quote)
    pub custodian_pk: Option<PublicKeyTarget>,
}

impl WrappedAssetBurnCircuit {
    /// Build the wrapped asset burn circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        sender_sk: Target,
    ) -> Target {
        // Verify ownership of the input UTXO
        let mut message = Vec::new();
        message.extend_from_slice(&self.destination_btc_address);
        message.push(self.input_utxo.amount_target);
        
        let is_signature_valid = verify_message_signature(
            builder,
            &message,
            &self.sender_sig,
            &self.sender_pk,
        );
        
        // Ensure the signature is valid
        builder.assert_one(is_signature_valid);
        
        // Calculate and register the nullifier for the input UTXO
        let nullifier = calculate_and_register_nullifier(
            builder,
            &self.input_utxo.salt_target,
            sender_sk,
        );
        
        // Handle fee logic based on the approach used
        let net_amount = if let (Some(fee_quote), Some(custodian_pk)) = (&self.fee_quote, &self.custodian_pk) {
            // Approach 2: Fee Parameter
            // Verify the custodian's signature on the fee quote
            let mut quote_message = Vec::new();
            quote_message.push(fee_quote.fee_btc);
            quote_message.push(fee_quote.expiry);
            
            let is_quote_valid = verify_message_signature(
                builder,
                &quote_message,
                &fee_quote.signature,
                custodian_pk,
            );
            
            // Ensure the quote signature is valid
            builder.assert_one(is_quote_valid);
            
            // Calculate the net amount after fee
            let net_amount = builder.sub(self.input_utxo.amount_target, fee_quote.fee_btc);
            
            net_amount
        } else {
            // Approach 1: Off-chain Deduction or Approach 3: Explicit Fee
            // Use the full amount from the input UTXO
            self.input_utxo.amount_target
        };
        
        // Register the withdrawal request data as public inputs
        for target in &self.destination_btc_address {
            builder.register_public_input(*target);
        }
        builder.register_public_input(net_amount);
        
        // Return the nullifier
        nullifier
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a dummy circuit for now
        // In a real implementation, this would be parameterized
        let input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        let sender_pk = PublicKeyTarget::add_virtual(&mut builder);
        let sender_sig = SignatureTarget::add_virtual(&mut builder);
        
        let destination_btc_address: Vec<Target> = (0..20)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let fee_quote = None;
        let custodian_pk = None;
        
        let circuit = WrappedAssetBurnCircuit {
            input_utxo,
            sender_pk,
            sender_sig,
            destination_btc_address,
            fee_quote,
            custodian_pk,
        };
        
        // Add a virtual target for the sender's secret key
        let sender_sk = builder.add_virtual_target();
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, sender_sk);
        
        builder.build::<PoseidonGoldilocksConfig>()
    }
    
    /// Generate a proof for the circuit with the given inputs
    pub fn generate_proof(
        &self,
        input_utxo_owner_pubkey_hash: &[u8],
        input_utxo_asset_id: &[u8],
        input_utxo_amount: u64,
        input_utxo_salt: &[u8],
        sender_sk: u64,
        sender_pk_x: u64,
        sender_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        destination_btc_address: &[u8],
        fee_btc: Option<u64>,
        fee_expiry: Option<u64>,
        fee_signature_r_x: Option<u64>,
        fee_signature_r_y: Option<u64>,
        fee_signature_s: Option<u64>,
        custodian_pk_x: Option<u64>,
        custodian_pk_y: Option<u64>,
    ) -> Result<SerializableProof, ProofError> {
        // Create the circuit
        let circuit_data = Self::create_circuit();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Create a new circuit builder for virtual targets
        let config = plonky2::plonk::circuit_data::CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create the input UTXO
        let input_utxo = UTXOTarget::add_virtual(&mut builder, input_utxo_salt.len());
        
        // Create the sender's public key and signature
        let sender_pk = PublicKeyTarget::add_virtual(&mut builder);
        let sender_sig = SignatureTarget::add_virtual(&mut builder);
        
        // Create the destination BTC address
        let destination_btc_address_targets: Vec<Target> = (0..destination_btc_address.len())
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create the fee quote and custodian public key if provided
        let (fee_quote, custodian_pk) = if let (Some(fee), Some(expiry), Some(sig_r_x), Some(sig_r_y), Some(sig_s), Some(cust_pk_x), Some(cust_pk_y)) = 
            (fee_btc, fee_expiry, fee_signature_r_x, fee_signature_r_y, fee_signature_s, custodian_pk_x, custodian_pk_y) {
            
            let fee_target = builder.add_virtual_target();
            let expiry_target = builder.add_virtual_target();
            
            let fee_signature = SignatureTarget {
                r_point: crate::core::PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
                s_scalar: builder.add_virtual_target(),
            };
            
            let fee_quote = Some(SignedQuoteTarget {
                fee_btc: fee_target,
                expiry: expiry_target,
                signature: fee_signature.clone(),
            });
            
            let custodian_pk = Some(PublicKeyTarget {
                point: crate::core::PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
            });
            
            // Set the witness values for the fee quote
            pw.set_target(fee_target, GoldilocksField::from_canonical_u64(fee as u64));
            pw.set_target(expiry_target, GoldilocksField::from_canonical_u64(expiry as u64));
            pw.set_target(fee_signature.r_point.x, GoldilocksField::from_canonical_u64(sig_r_x as u64));
            pw.set_target(fee_signature.r_point.y, GoldilocksField::from_canonical_u64(sig_r_y as u64));
            pw.set_target(fee_signature.s_scalar, GoldilocksField::from_canonical_u64(sig_s as u64));
            
            // Set the witness values for the custodian public key
            if let Some(ref custodian_pk) = custodian_pk {
                pw.set_target(custodian_pk.point.x, GoldilocksField::from_canonical_u64(cust_pk_x as u64));
                pw.set_target(custodian_pk.point.y, GoldilocksField::from_canonical_u64(cust_pk_y as u64));
            }
            
            (fee_quote, custodian_pk)
        } else {
            (None, None)
        };
        
        // Create the circuit
        let circuit = WrappedAssetBurnCircuit {
            input_utxo: input_utxo.clone(),
            sender_pk: sender_pk.clone(),
            sender_sig: sender_sig.clone(),
            destination_btc_address: destination_btc_address_targets.clone(),
            fee_quote,
            custodian_pk,
        };
        
        // Add a virtual target for the sender's secret key
        let sender_sk_target = builder.add_virtual_target();
        
        // Set the witness values for the input UTXO
        for (i, byte) in input_utxo_owner_pubkey_hash.iter().enumerate() {
            if i < input_utxo.owner_pubkey_hash_target.len() {
                pw.set_target(
                    input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        for (i, byte) in input_utxo_asset_id.iter().enumerate() {
            if i < input_utxo.asset_id_target.len() {
                pw.set_target(
                    input_utxo.asset_id_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        pw.set_target(input_utxo.amount_target, GoldilocksField::from_canonical_u64(input_utxo_amount as u64));
        
        for (i, byte) in input_utxo_salt.iter().enumerate() {
            if i < input_utxo.salt_target.len() {
                pw.set_target(
                    input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Set the witness values for the sender's public key and signature
        pw.set_target(sender_pk.point.x, GoldilocksField::from_canonical_u64(sender_pk_x as u64));
        pw.set_target(sender_pk.point.y, GoldilocksField::from_canonical_u64(sender_pk_y as u64));
        
        pw.set_target(sender_sig.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x as u64));
        pw.set_target(sender_sig.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y as u64));
        pw.set_target(sender_sig.s_scalar, GoldilocksField::from_canonical_u64(signature_s as u64));
        
        // Set the witness values for the destination BTC address
        for (i, byte) in destination_btc_address.iter().enumerate() {
            if i < destination_btc_address_targets.len() {
                pw.set_target(
                    destination_btc_address_targets[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Set the witness value for the sender's secret key
        pw.set_target(sender_sk_target, GoldilocksField::from_canonical_u64(sender_sk as u64));
        
        // Generate the proof
        let proof = generate_proof(&circuit_data, pw)?;
        
        // Serialize the proof
        serialize_proof(&proof)
    }
    
    /// Generate a proof for the circuit with the given inputs (static method)
    pub fn generate_proof_static(
        input_utxo_owner_pubkey_hash: &[u8],
        input_utxo_asset_id: &[u8],
        input_utxo_amount: u64,
        input_utxo_salt: &[u8],
        sender_sk: u64,
        sender_pk_x: u64,
        sender_pk_y: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        destination_btc_address: &[u8],
        fee_btc: Option<u64>,
        fee_expiry: Option<u64>,
        fee_signature_r_x: Option<u64>,
        fee_signature_r_y: Option<u64>,
        fee_signature_s: Option<u64>,
        custodian_pk_x: Option<u64>,
        custodian_pk_y: Option<u64>,
    ) -> Result<SerializableProof, ProofError> {
        // Create a dummy circuit instance
        let circuit = Self {
            input_utxo: UTXOTarget {
                owner_pubkey_hash_target: vec![],
                asset_id_target: vec![],
                amount_target: Target::default(),
                salt_target: vec![],
            },
            sender_pk: PublicKeyTarget {
                point: crate::core::PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
            },
            sender_sig: SignatureTarget {
                r_point: crate::core::PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
                s_scalar: Target::default(),
            },
            destination_btc_address: vec![],
            fee_quote: None,
            custodian_pk: None,
        };
        
        // Call the instance method
        circuit.generate_proof(
            input_utxo_owner_pubkey_hash,
            input_utxo_asset_id,
            input_utxo_amount,
            input_utxo_salt,
            sender_sk,
            sender_pk_x,
            sender_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            destination_btc_address,
            fee_btc,
            fee_expiry,
            fee_signature_r_x,
            fee_signature_r_y,
            fee_signature_s,
            custodian_pk_x,
            custodian_pk_y,
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
    fn test_wrapped_asset_burn() {
        // This test verifies that we can create and build the circuit
        let circuit_data = WrappedAssetBurnCircuit::create_circuit();
        
        // Just verify that the circuit was created successfully
        assert!(circuit_data.common.gates.len() > 0, "Circuit should have gates");
    }
}
