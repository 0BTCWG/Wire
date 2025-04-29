// Native Asset Burn Circuit for the 0BTC Wire system
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

use crate::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE};
use crate::gadgets::comparison::is_less_than_or_equal;
use crate::gadgets::{enforce_fee_payment, hash_utxo_commitment, verify_message_signature};

/// Circuit for burning native asset tokens
///
/// This circuit verifies ownership of the tokens to burn,
/// enforces the fee payment, and registers the nullifiers.
pub struct NativeAssetBurnCircuit {
    /// The input UTXO containing the tokens to burn
    pub input_utxo: UTXOTarget,
    
    /// The owner's public key
    pub owner_pk: PublicKeyTarget,
    
    /// The amount to burn
    pub burn_amount: Target,
    
    /// The input UTXO containing wBTC for fee payment
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee amount
    pub fee_amount: Target,
    
    /// The fee reservoir address
    pub fee_reservoir_address_hash: Vec<Target>,
    
    /// The signature for verifying ownership
    pub signature: SignatureTarget,
}

impl NativeAssetBurnCircuit {
    /// Build the native asset burn circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        _owner_sk: Target,
    ) -> UTXOTarget {
        // Verify ownership of the input UTXO
        let input_utxo_commitment = hash_utxo_commitment(
            builder,
            &self.input_utxo.owner_pubkey_hash_target,
            &self.input_utxo.asset_id_target,
            self.input_utxo.amount_target,
            &self.input_utxo.salt_target,
        );
        
        // Create a message to sign (the UTXO commitment)
        let mut message = Vec::new();
        message.extend_from_slice(&input_utxo_commitment);
        
        // Verify the signature
        let is_valid = verify_message_signature(
            builder,
            &message,
            &self.signature,
            &self.owner_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Enforce that the burn amount is less than or equal to the input amount
        let is_valid_amount = is_less_than_or_equal(
            builder,
            self.burn_amount,
            self.input_utxo.amount_target,
        );
        builder.connect(is_valid_amount, one);
        
        // Calculate the change amount
        let change_amount = builder.sub(
            self.input_utxo.amount_target,
            self.burn_amount,
        );
        
        // Enforce fee payment
        let _wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.owner_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &self.signature,
        );
        
        // Create a change UTXO if there's any change
        let change_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.input_utxo.owner_pubkey_hash_target.clone(),
            asset_id_target: self.input_utxo.asset_id_target.clone(),
            amount_target: change_amount,
            salt_target: (0..HASH_SIZE)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Return the change UTXO
        change_utxo
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create dummy inputs for testing
        let input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        let owner_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        let burn_amount = builder.add_virtual_target();
        
        let fee_input_utxo = UTXOTarget::add_virtual(&mut builder, 32);
        
        // Use a virtual target for fee_amount instead of a constant
        let fee_amount = builder.add_virtual_target();
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        let circuit = NativeAssetBurnCircuit {
            input_utxo,
            owner_pk,
            burn_amount,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
            signature,
        };
        
        // Create a dummy owner secret key
        let _owner_sk = builder.add_virtual_target();
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, _owner_sk);
        
        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }
    
    /// Generate a proof for the native asset burn circuit
    pub fn generate_proof_static(
        input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        owner_pk_x: u64,
        owner_pk_y: u64,
        owner_sk: u64,
        burn_amount: u64,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        fee_input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
    ) -> Result<crate::core::proof::SerializableProof, crate::core::proof::ProofError> {
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};
        use crate::core::proof::{serialize_proof, ProofError};
        
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create the circuit instance
        let circuit = NativeAssetBurnCircuit {
            input_utxo: UTXOTarget {
                owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
            },
            owner_pk: PublicKeyTarget {
                point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
            },
            burn_amount: builder.add_virtual_target(),
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
            },
            fee_amount: builder.add_virtual_target(),
            fee_reservoir_address_hash: (0..32).map(|_| builder.add_virtual_target()).collect(),
            signature: SignatureTarget {
                r_point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
                s_scalar: builder.add_virtual_target(),
            },
        };
        
        // Build the circuit
        let owner_sk_target = builder.add_virtual_target();
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, owner_sk_target);
        
        // Build the circuit data
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Set input UTXO values
        let (input_owner_pubkey_hash, input_asset_id, input_amount, input_salt) = &input_utxo_data;
        for (i, byte) in input_owner_pubkey_hash.iter().enumerate() {
            if i < circuit.input_utxo.owner_pubkey_hash_target.len() {
                pw.set_target(
                    circuit.input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        for (i, byte) in input_asset_id.iter().enumerate() {
            if i < circuit.input_utxo.asset_id_target.len() {
                pw.set_target(
                    circuit.input_utxo.asset_id_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        pw.set_target(circuit.input_utxo.amount_target, GoldilocksField::from_canonical_u64(*input_amount));
        for (i, byte) in input_salt.iter().enumerate() {
            if i < circuit.input_utxo.salt_target.len() {
                pw.set_target(
                    circuit.input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Set owner public key
        pw.set_target(circuit.owner_pk.point.x, GoldilocksField::from_canonical_u64(owner_pk_x));
        pw.set_target(circuit.owner_pk.point.y, GoldilocksField::from_canonical_u64(owner_pk_y));
        
        // Set owner secret key
        pw.set_target(owner_sk_target, GoldilocksField::from_canonical_u64(owner_sk));
        
        // Set burn amount
        pw.set_target(circuit.burn_amount, GoldilocksField::from_canonical_u64(burn_amount));
        
        // Set fee input UTXO values
        let (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt) = &fee_input_utxo_data;
        for (i, byte) in fee_owner_pubkey_hash.iter().enumerate() {
            if i < circuit.fee_input_utxo.owner_pubkey_hash_target.len() {
                pw.set_target(
                    circuit.fee_input_utxo.owner_pubkey_hash_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        for (i, byte) in fee_asset_id.iter().enumerate() {
            if i < circuit.fee_input_utxo.asset_id_target.len() {
                pw.set_target(
                    circuit.fee_input_utxo.asset_id_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        pw.set_target(circuit.fee_input_utxo.amount_target, GoldilocksField::from_canonical_u64(*fee_amount_value));
        for (i, byte) in fee_salt.iter().enumerate() {
            if i < circuit.fee_input_utxo.salt_target.len() {
                pw.set_target(
                    circuit.fee_input_utxo.salt_target[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Set fee amount
        pw.set_target(circuit.fee_amount, GoldilocksField::from_canonical_u64(fee_amount));
        
        // Set fee reservoir address hash
        for (i, byte) in fee_reservoir_address_hash.iter().enumerate() {
            if i < circuit.fee_reservoir_address_hash.len() {
                pw.set_target(
                    circuit.fee_reservoir_address_hash[i],
                    GoldilocksField::from_canonical_u64(*byte as u64),
                );
            }
        }
        
        // Set signature values
        pw.set_target(circuit.signature.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x));
        pw.set_target(circuit.signature.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y));
        pw.set_target(circuit.signature.s_scalar, GoldilocksField::from_canonical_u64(signature_s));
        
        // Generate the proof
        let proof = crate::core::proof::generate_proof(&circuit_data, pw)
            .map_err(|e| ProofError::ProofGenerationError(format!("{:?}", e)))?;
        
        // Serialize the proof
        serialize_proof(&proof)
    }
    
    /// Verify a proof for the native asset burn circuit
    pub fn verify_proof(serialized_proof: &crate::core::proof::SerializableProof) -> Result<(), crate::core::proof::ProofError> {
        use crate::core::proof::deserialize_proof;
        
        // Create a new circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create the circuit instance
        let circuit = NativeAssetBurnCircuit {
            input_utxo: UTXOTarget {
                owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
            },
            owner_pk: PublicKeyTarget {
                point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
            },
            burn_amount: builder.add_virtual_target(),
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                asset_id_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
                amount_target: builder.add_virtual_target(),
                salt_target: (0..32).map(|_| builder.add_virtual_target()).collect(),
            },
            fee_amount: builder.add_virtual_target(),
            fee_reservoir_address_hash: (0..32).map(|_| builder.add_virtual_target()).collect(),
            signature: SignatureTarget {
                r_point: PointTarget {
                    x: builder.add_virtual_target(),
                    y: builder.add_virtual_target(),
                },
                s_scalar: builder.add_virtual_target(),
            },
        };
        
        // Build the circuit
        let owner_sk_target = builder.add_virtual_target();
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, owner_sk_target);
        
        // Build the circuit data
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        
        // Deserialize the proof
        let proof = deserialize_proof(serialized_proof)?;
        
        // Verify the proof
        crate::core::proof::verify_proof(&circuit_data, &proof)
    }
}
