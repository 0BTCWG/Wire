// Native Asset Mint Circuit for the 0BTC Wire system

use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget};
use crate::errors::{WireError, WireResult};
use crate::gadgets::fee::enforce_fee_payment;
use crate::gadgets::hash::hash_targets;
use crate::gadgets::signature::verify_message_signature;

/// Circuit for minting native asset tokens
///
/// This circuit verifies that the minter is authorized to mint the asset,
/// enforces the fee payment, and creates the output UTXO.
#[derive(Clone)]
pub struct NativeAssetMintCircuit {
    /// The minter's public key
    pub minter_pk: PublicKeyTarget,

    /// The asset ID
    pub asset_id: Vec<Target>,

    /// The recipient's public key hash
    pub recipient_pk_hash: Vec<Target>,

    /// The amount to mint
    pub mint_amount: Target,

    /// The input UTXO containing wBTC for fee payment
    pub fee_input_utxo: UTXOTarget,

    /// The fee amount
    pub fee_amount: Target,

    /// The fee reservoir address
    pub fee_reservoir_address_hash: Vec<Target>,

    /// The signature for verifying ownership
    pub signature: SignatureTarget,
}

impl Default for NativeAssetMintCircuit {
    fn default() -> Self {
        Self {
            minter_pk: PublicKeyTarget {
                point: crate::core::PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
            },
            asset_id: vec![Target::default(); 32],
            recipient_pk_hash: vec![Target::default(); 32],
            mint_amount: Target::default(),
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: vec![Target::default(); 32],
                asset_id_target: vec![Target::default(); 32],
                amount_target: Target::default(),
                salt_target: vec![Target::default(); 32],
            },
            fee_amount: Target::default(),
            fee_reservoir_address_hash: vec![Target::default(); 32],
            signature: SignatureTarget {
                r_point: crate::core::PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
                s_scalar: Target::default(),
            },
        }
    }
}

impl NativeAssetMintCircuit {
    /// Build the native asset mint circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> UTXOTarget {
        // Create a message to sign (the mint parameters)
        let mut message = Vec::new();
        message.extend_from_slice(&self.asset_id);
        message.extend_from_slice(&self.recipient_pk_hash);
        message.push(self.mint_amount);

        // Use our improved signature verification with domain separation
        let is_valid =
            verify_message_signature(builder, &message, &self.signature, &self.minter_pk);

        // Assert that the signature is valid
        builder.assert_one(is_valid);

        // Enforce fee payment using our improved fee enforcement
        enforce_fee_payment(
            builder,
            &self.minter_pk, // fee payer public key
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &self.signature, // signature for fee verification
            &self.asset_id,  // expected asset ID
        );

        // Create a new UTXO for the minted tokens
        let minted_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.recipient_pk_hash.clone(),
            asset_id_target: self.asset_id.clone(),
            amount_target: self.mint_amount,
            salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
        };

        // Generate a random salt for the minted UTXO
        // In a real implementation, this would be a secure random value
        // For now, we'll just use a simple hash of the message
        let salt_hash = hash_targets(builder, &message);

        // Extract the elements from the HashOutTarget
        let salt_element0 = salt_hash.elements[0];
        let salt_element1 = salt_hash.elements[1];
        let salt_element2 = salt_hash.elements[2];
        let salt_element3 = salt_hash.elements[3];

        // Set salt targets using the hash elements
        for (i, target) in minted_utxo.salt_target.iter().enumerate() {
            match i % 4 {
                0 => builder.connect(*target, salt_element0),
                1 => builder.connect(*target, salt_element1),
                2 => builder.connect(*target, salt_element2),
                _ => builder.connect(*target, salt_element3),
            }
        }

        // Register the minted UTXO as public inputs
        for target in &minted_utxo.owner_pubkey_hash_target {
            builder.register_public_input(*target);
        }
        for target in &minted_utxo.asset_id_target {
            builder.register_public_input(*target);
        }
        builder.register_public_input(minted_utxo.amount_target);
        for target in &minted_utxo.salt_target {
            builder.register_public_input(*target);
        }

        // Return the minted UTXO
        minted_utxo
    }

    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a minter public key
        let minter_pk = PublicKeyTarget::add_virtual(&mut builder);

        // Create an asset ID
        let asset_id: Vec<Target> = (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a recipient public key hash
        let recipient_pk_hash: Vec<Target> =
            (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a mint amount
        let mint_amount = builder.add_virtual_target();

        // Create a fee input UTXO
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);

        // Create a fee amount
        let fee_amount = builder.add_virtual_target();

        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> =
            (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a signature
        let signature = SignatureTarget::add_virtual(&mut builder);

        // Create the circuit
        let circuit = NativeAssetMintCircuit {
            minter_pk,
            asset_id,
            recipient_pk_hash,
            mint_amount,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
            signature,
        };

        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);

        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }

    /// Generate a proof for the native asset mint circuit
    pub fn generate_proof_static(
        minter_pk_x: u64,
        minter_pk_y: u64,
        asset_id: Vec<u8>,
        recipient_pk_hash: Vec<u8>,
        mint_amount: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        fee_input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
    ) -> WireResult<crate::core::proof::SerializableProof> {
        use crate::core::proof::serialize_proof;
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};

        // Create the circuit
        let _circuit_data = Self::create_circuit();
        let mut pw = PartialWitness::new();

        // Create a new circuit builder for virtual targets
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Set minter public key
        let minter_pk = PublicKeyTarget::add_virtual(&mut builder);
        let _ = pw.set_target(
            minter_pk.point.x,
            GoldilocksField::from_canonical_u64(minter_pk_x),
        );
        let _ = pw.set_target(
            minter_pk.point.y,
            GoldilocksField::from_canonical_u64(minter_pk_y),
        );

        // Set asset ID
        let asset_id_targets: Vec<Target> = (0..asset_id.len())
            .map(|_| builder.add_virtual_target())
            .collect();

        for (i, byte) in asset_id.iter().enumerate() {
            if i < asset_id_targets.len() {
                let _ = pw.set_target(
                    asset_id_targets[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }

        // Set recipient public key hash
        let recipient_pk_hash_targets: Vec<Target> = (0..recipient_pk_hash.len())
            .map(|_| builder.add_virtual_target())
            .collect();

        for (i, byte) in recipient_pk_hash.iter().enumerate() {
            if i < recipient_pk_hash_targets.len() {
                let _ = pw.set_target(
                    recipient_pk_hash_targets[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }

        // Set mint amount
        let mint_amount_target = builder.add_virtual_target();
        let _ = pw.set_target(
            mint_amount_target,
            GoldilocksField::from_canonical_u64(mint_amount),
        );

        // Set signature
        let signature = SignatureTarget::add_virtual(&mut builder);
        let _ = pw.set_target(
            signature.r_point.x,
            GoldilocksField::from_canonical_u64(signature_r_x),
        );
        let _ = pw.set_target(
            signature.r_point.y,
            GoldilocksField::from_canonical_u64(signature_r_y),
        );
        let _ = pw.set_target(
            signature.s_scalar,
            GoldilocksField::from_canonical_u64(signature_s),
        );

        // Create fee input UTXO
        let (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt) =
            &fee_input_utxo_data;
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);

        // Set fee input UTXO values
        for (i, byte) in fee_owner_pubkey_hash.iter().enumerate() {
            if i < fee_input_utxo.owner_pubkey_hash_target.len() {
                let _ = pw.set_target(
                    fee_input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        for (i, byte) in fee_asset_id.iter().enumerate() {
            if i < fee_input_utxo.asset_id_target.len() {
                let _ = pw.set_target(
                    fee_input_utxo.asset_id_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        let _ = pw.set_target(
            fee_input_utxo.amount_target,
            GoldilocksField::from_canonical_u64(*fee_amount_value),
        );
        for (i, byte) in fee_salt.iter().enumerate() {
            if i < fee_input_utxo.salt_target.len() {
                let _ = pw.set_target(
                    fee_input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }

        // Set fee amount
        let fee_amount_target = builder.add_virtual_target();
        let _ = pw.set_target(
            fee_amount_target,
            GoldilocksField::from_canonical_u64(fee_amount),
        );

        // Set fee reservoir address hash
        let fee_reservoir_address_hash_targets: Vec<Target> = (0..fee_reservoir_address_hash.len())
            .map(|_| builder.add_virtual_target())
            .collect();

        for (i, byte) in fee_reservoir_address_hash.iter().enumerate() {
            if i < fee_reservoir_address_hash_targets.len() {
                let _ = pw.set_target(
                    fee_reservoir_address_hash_targets[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }

        // Create the circuit
        let circuit = NativeAssetMintCircuit {
            minter_pk,
            asset_id: asset_id_targets,
            recipient_pk_hash: recipient_pk_hash_targets,
            mint_amount: mint_amount_target,
            fee_input_utxo,
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
            signature,
        };

        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);

        // Build the circuit data
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();

        // Generate the proof
        let proof = crate::core::proof::generate_proof(&circuit_data, pw)
            .map_err(|e| WireError::ProofError(crate::core::proof::ProofError::from(e).into()))?;

        // Serialize the proof
        serialize_proof(&proof)
            .map_err(|e| WireError::ProofError(crate::core::proof::ProofError::from(e).into()))
    }

    /// Verify a proof of a native asset mint
    pub fn verify_proof(
        serialized_proof: &crate::core::proof::SerializableProof,
    ) -> WireResult<()> {
        use crate::core::proof::deserialize_proof;

        // Create the circuit
        let circuit_data = Self::create_circuit();

        // Deserialize the proof
        let proof = deserialize_proof(serialized_proof, &circuit_data.common)
            .map_err(|e| WireError::ProofError(crate::core::proof::ProofError::from(e).into()))?;

        // Verify the proof
        crate::core::proof::verify_proof(&circuit_data, proof)
            .map_err(|e| WireError::ProofError(crate::core::proof::ProofError::from(e).into()))?;

        Ok(())
    }

    fn build_circuit(
        &self,
    ) -> WireResult<(
        CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2>,
        UTXOTarget,
    )> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);

        // Create a minter public key
        let minter_pk = PublicKeyTarget::add_virtual(&mut builder);

        // Create an asset ID
        let asset_id: Vec<Target> = (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a recipient public key hash
        let recipient_pk_hash: Vec<Target> =
            (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a mint amount
        let mint_amount = builder.add_virtual_target();

        // Create a fee input UTXO
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);

        // Create a fee amount
        let fee_amount = builder.add_virtual_target();

        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> =
            (0..32).map(|_| builder.add_virtual_target()).collect();

        // Create a signature
        let signature = SignatureTarget::add_virtual(&mut builder);

        // Create the circuit
        let circuit = NativeAssetMintCircuit {
            minter_pk,
            asset_id,
            recipient_pk_hash,
            mint_amount,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
            signature,
        };

        // Build the circuit
        let minted_utxo =
            circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);

        // Build the circuit data
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();

        Ok((circuit_data, minted_utxo))
    }
}
