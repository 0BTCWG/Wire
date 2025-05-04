// Wrapped Asset Burn Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use crate::core::proof::{serialize_proof, SerializableProof};
use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget};
use crate::errors::{ProofError, WireError, WireResult};
use crate::gadgets::{calculate_and_register_nullifier, verify_message_signature};

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
    pub fee_quote: Option<crate::gadgets::fee::SignedQuoteTarget>,

    /// The custodian's public key (for verifying the fee quote)
    pub custodian_pk: Option<PublicKeyTarget>,
}

impl WrappedAssetBurnCircuit {
    /// Build the wrapped asset burn circuit
    pub fn build<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        sender_sk: Target,
    ) -> Target {
        // Verify the sender's signature on the burn request
        let mut message = Vec::new();
        message.extend_from_slice(&self.input_utxo.owner_pubkey_hash_target);
        message.extend_from_slice(&self.input_utxo.asset_id_target);
        message.push(self.input_utxo.amount_target);
        message.extend_from_slice(&self.input_utxo.salt_target);
        message.extend_from_slice(&self.destination_btc_address);

        // Add fee quote to the message if present
        if let Some(fee_quote) = &self.fee_quote {
            message.push(fee_quote.fee_btc);
            message.push(fee_quote.expiry);
        }

        // Use our improved signature verification with domain separation
        let is_valid =
            verify_message_signature(builder, &message, &self.sender_sig, &self.sender_pk);

        // Ensure the signature is valid
        builder.assert_one(is_valid);

        // Verify the fee quote signature if present
        if let (Some(fee_quote), Some(custodian_pk)) = (&self.fee_quote, &self.custodian_pk) {
            let mut fee_message = Vec::new();
            fee_message.push(fee_quote.fee_btc);
            fee_message.push(fee_quote.expiry);

            // Use our improved signature verification with domain separation for fee quotes
            let fee_sig_valid =
                verify_message_signature(builder, &fee_message, &fee_quote.signature, custodian_pk);

            // Ensure the fee signature is valid
            builder.assert_one(fee_sig_valid);
        }

        // Calculate and register the nullifier
        let nullifier = calculate_and_register_nullifier(
            builder,
            &self.input_utxo.salt_target,
            &self.input_utxo.asset_id_target,
            self.input_utxo.amount_target,
            sender_sk,
        )
        .expect("Failed to calculate nullifier");

        // Register the amount as a public input
        builder.register_public_input(self.input_utxo.amount_target);

        // Register the destination BTC address as public inputs
        for target in &self.destination_btc_address {
            builder.register_public_input(*target);
        }

        // Register the fee as a public input if present
        if let Some(fee_quote) = &self.fee_quote {
            builder.register_public_input(fee_quote.fee_btc);
        } else {
            // Register zero as the fee if not present
            let zero = builder.zero();
            builder.register_public_input(zero);
        }

        // Register the nullifier as a public input
        builder.register_public_input(nullifier);

        // Register a zero as a public input (placeholder for future use)
        let zero = builder.zero();
        builder.register_public_input(zero);

        nullifier
    }

    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a sender secret key
        let _sender_sk_target = builder.add_virtual_target();

        // Create a sender public key
        let sender_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };

        // Create a signature
        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };

        // Create an input UTXO
        let input_utxo = UTXOTarget::add_virtual(&mut builder, crate::core::HASH_SIZE);

        // Create a destination BTC address
        let destination_btc_address: Vec<_> = (0..20) // Assuming P2PKH address
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create the circuit
        let circuit = WrappedAssetBurnCircuit {
            input_utxo,
            sender_pk,
            sender_sig: signature,
            destination_btc_address,
            fee_quote: None, // No fee quote for the basic circuit
            custodian_pk: None,
        };

        // Build the circuit
        let zero = builder.zero();
        circuit.build(&mut builder, zero);

        // Build the circuit data
        builder.build()
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
    ) -> WireResult<SerializableProof> {
        // Create the circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a sender secret key
        let sender_sk_target = builder.add_virtual_target();

        // Create a sender public key
        let sender_pk_target = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };

        // Create a signature
        let signature_target = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };

        // Create an input UTXO
        let input_utxo_target = UTXOTarget {
            owner_pubkey_hash_target: (0..input_utxo_owner_pubkey_hash.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..input_utxo_asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..input_utxo_salt.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
        };

        // Create a destination BTC address
        let destination_btc_address_target: Vec<_> = (0..destination_btc_address.len())
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create fee quote and custodian public key if provided
        let (fee_quote_target, custodian_pk_target) = if fee_btc.is_some()
            && fee_expiry.is_some()
            && fee_signature_r_x.is_some()
            && fee_signature_r_y.is_some()
            && fee_signature_s.is_some()
            && custodian_pk_x.is_some()
            && custodian_pk_y.is_some()
        {
            let fee_quote = crate::gadgets::fee::SignedQuoteTarget {
                fee_btc: builder.add_virtual_target(),
                expiry: builder.add_virtual_target(),
                signature: SignatureTarget {
                    r_point: crate::core::PointTarget {
                        x: builder.add_virtual_target(),
                        y: builder.add_virtual_target(),
                    },
                    s_scalar: builder.add_virtual_target(),
                },
            };

            let custodian_pk = PublicKeyTarget {
                point: crate::core::PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
            };

            (Some(fee_quote), Some(custodian_pk))
        } else {
            (None, None)
        };

        // Create the circuit
        let circuit = WrappedAssetBurnCircuit {
            input_utxo: input_utxo_target.clone(),
            sender_pk: sender_pk_target.clone(),
            sender_sig: signature_target.clone(),
            destination_btc_address: destination_btc_address_target.clone(),
            fee_quote: fee_quote_target.clone(),
            custodian_pk: custodian_pk_target.clone(),
        };

        // Build the circuit
        let zero = builder.zero();
        circuit.build(&mut builder, zero);

        // Build the circuit data
        let circuit_data = builder.build();

        // Create a partial witness
        let mut pw = PartialWitness::new();

        // Set the witness values
        pw.set_target(
            sender_sk_target,
            GoldilocksField::from_canonical_u64(sender_sk),
        );

        pw.set_target(
            sender_pk_target.point.x,
            GoldilocksField::from_canonical_u64(sender_pk_x),
        );
        pw.set_target(
            sender_pk_target.point.y,
            GoldilocksField::from_canonical_u64(sender_pk_y),
        );

        pw.set_target(
            signature_target.r_point.x,
            GoldilocksField::from_canonical_u64(signature_r_x),
        );
        pw.set_target(
            signature_target.r_point.y,
            GoldilocksField::from_canonical_u64(signature_r_y),
        );
        pw.set_target(
            signature_target.s_scalar,
            GoldilocksField::from_canonical_u64(signature_s),
        );

        for i in 0..input_utxo_owner_pubkey_hash
            .len()
            .min(input_utxo_target.owner_pubkey_hash_target.len())
        {
            pw.set_target(
                input_utxo_target.owner_pubkey_hash_target[i],
                GoldilocksField::from_canonical_u64(input_utxo_owner_pubkey_hash[i] as u64),
            );
        }

        for i in 0..input_utxo_asset_id
            .len()
            .min(input_utxo_target.asset_id_target.len())
        {
            pw.set_target(
                input_utxo_target.asset_id_target[i],
                GoldilocksField::from_canonical_u64(input_utxo_asset_id[i] as u64),
            );
        }

        pw.set_target(
            input_utxo_target.amount_target,
            GoldilocksField::from_canonical_u64(input_utxo_amount),
        );

        for i in 0..input_utxo_salt
            .len()
            .min(input_utxo_target.salt_target.len())
        {
            pw.set_target(
                input_utxo_target.salt_target[i],
                GoldilocksField::from_canonical_u64(input_utxo_salt[i] as u64),
            );
        }

        for i in 0..destination_btc_address
            .len()
            .min(destination_btc_address_target.len())
        {
            pw.set_target(
                destination_btc_address_target[i],
                GoldilocksField::from_canonical_u64(destination_btc_address[i] as u64),
            );
        }

        // Set fee quote and custodian public key values if provided
        if let (
            Some(fee_quote),
            Some(custodian_pk),
            Some(fee_btc_val),
            Some(fee_expiry_val),
            Some(fee_sig_r_x),
            Some(fee_sig_r_y),
            Some(fee_sig_s),
            Some(cust_pk_x),
            Some(cust_pk_y),
        ) = (
            &fee_quote_target,
            &custodian_pk_target,
            fee_btc,
            fee_expiry,
            fee_signature_r_x,
            fee_signature_r_y,
            fee_signature_s,
            custodian_pk_x,
            custodian_pk_y,
        ) {
            pw.set_target(
                fee_quote.fee_btc,
                GoldilocksField::from_canonical_u64(fee_btc_val),
            );
            pw.set_target(
                fee_quote.expiry,
                GoldilocksField::from_canonical_u64(fee_expiry_val),
            );

            pw.set_target(
                fee_quote.signature.r_point.x,
                GoldilocksField::from_canonical_u64(fee_sig_r_x),
            );
            pw.set_target(
                fee_quote.signature.r_point.y,
                GoldilocksField::from_canonical_u64(fee_sig_r_y),
            );
            pw.set_target(
                fee_quote.signature.s_scalar,
                GoldilocksField::from_canonical_u64(fee_sig_s),
            );

            pw.set_target(
                custodian_pk.point.x,
                GoldilocksField::from_canonical_u64(cust_pk_x),
            );
            pw.set_target(
                custodian_pk.point.y,
                GoldilocksField::from_canonical_u64(cust_pk_y),
            );
        }

        // Generate the proof
        let proof = circuit_data.prove(pw).map_err(|e| {
            WireError::ProofError(ProofError::GenerationError(format!(
                "Failed to generate proof: {}",
                e
            )))
        })?;

        // Serialize the proof
        serialize_proof(&proof).map_err(|e| WireError::ProofError(ProofError::from(e)))
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
    ) -> WireResult<SerializableProof> {
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a sender secret key
        let _sender_sk_target = builder.add_virtual_target();

        // Create a sender public key
        let sender_pk_target = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };

        // Create a signature
        let signature_target = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };

        // Create an input UTXO
        let input_utxo_target = UTXOTarget {
            owner_pubkey_hash_target: (0..input_utxo_owner_pubkey_hash.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..input_utxo_asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..input_utxo_salt.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
        };

        // Create a destination BTC address
        let destination_btc_address_target: Vec<_> = (0..destination_btc_address.len())
            .map(|_| builder.add_virtual_target())
            .collect();

        // Create the circuit instance
        let circuit = WrappedAssetBurnCircuit {
            input_utxo: input_utxo_target,
            sender_pk: sender_pk_target,
            sender_sig: signature_target,
            destination_btc_address: destination_btc_address_target,
            fee_quote: None,
            custodian_pk: None,
        };

        // Generate the proof
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

    /// Verify a proof for this circuit
    pub fn verify_proof(serializable_proof: &SerializableProof) -> WireResult<()> {
        let circuit_data = Self::create_circuit();
        let proof = serializable_proof
            .to_proof::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&circuit_data.common)
            .map_err(|e| WireError::ProofError(ProofError::from(e)))?;

        circuit_data.verify(proof).map_err(|e| {
            WireError::ProofError(ProofError::VerificationError(format!(
                "Failed to verify proof: {}",
                e
            )))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wrapped_asset_burn() {
        // This is a placeholder test
        // In a real implementation, this would test the circuit with actual inputs
        let circuit_data = WrappedAssetBurnCircuit::create_circuit();
        assert!(circuit_data.common.num_public_inputs > 0);
    }
}
