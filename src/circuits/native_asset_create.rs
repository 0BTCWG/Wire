// Native Asset Create Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::gadgets::{calculate_asset_id, enforce_fee_payment, verify_message_signature};

/// Circuit for creating a new native asset
///
/// This circuit allows a user to create a new native asset type
/// with a specified creator, decimals, and max supply.
pub struct NativeAssetCreateCircuit {
    /// The creator's public key
    pub creator_pk: PublicKeyTarget,
    
    /// The asset nonce
    pub asset_nonce: Target,
    
    /// The number of decimals for the asset
    pub decimals: Target,
    
    /// The maximum supply of the asset
    pub max_supply: Target,
    
    /// Whether the asset is mintable
    pub is_mintable: Target,
    
    /// The input UTXO containing wBTC for fee payment
    pub fee_input_utxo: UTXOTarget,
    
    /// The fee amount
    pub fee_amount: Target,
    
    /// The fee reservoir address
    pub fee_reservoir_address_hash: Vec<Target>,
    
    /// The signature for verifying ownership
    pub signature: SignatureTarget,
}

impl NativeAssetCreateCircuit {
    /// Build the native asset create circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        // Create the asset parameters
        let mut asset_params = Vec::new();
        asset_params.push(self.asset_nonce);
        asset_params.push(self.decimals);
        asset_params.push(self.max_supply);
        asset_params.push(self.is_mintable);
        
        // Hash the asset parameters to create the asset ID
        let asset_id = calculate_asset_id(
            builder,
            &[self.creator_pk.point.x, self.creator_pk.point.y],
            self.asset_nonce,
            self.decimals,
            self.max_supply,
            self.is_mintable,
        );
        
        // Create a message to sign (the asset ID)
        let mut message = Vec::new();
        message.extend_from_slice(&asset_id);
        
        // Verify the signature
        let is_valid = verify_message_signature(
            builder,
            &message,
            &self.signature,
            &self.creator_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Enforce fee payment
        let _wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.creator_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &self.signature,
        );
        
        // Return the asset ID
        asset_id
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a creator public key
        let creator_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Create asset parameters
        let asset_nonce = builder.add_virtual_target();
        let decimals = builder.add_virtual_target();
        let max_supply = builder.add_virtual_target();
        let is_mintable = builder.add_virtual_target();
        
        // Create a fee input UTXO
        let fee_input_utxo = UTXOTarget {
            owner_pubkey_hash_target: (0..32)
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..32)
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..32)
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Create a fee amount (use a virtual target instead of a constant)
        let fee_amount = builder.add_virtual_target();
        
        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a signature
        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create the circuit
        let circuit = NativeAssetCreateCircuit {
            creator_pk,
            asset_nonce,
            decimals,
            max_supply,
            is_mintable,
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
    
    /// Generate a proof for the native asset create circuit
    pub fn generate_proof_static(
        creator_pk_x: u64,
        creator_pk_y: u64,
        asset_nonce: u64,
        decimals: u64,
        max_supply: u64,
        is_mintable: bool,
        signature_r_x: u64,
        signature_r_y: u64,
        signature_s: u64,
        fee_input_utxo_data: (Vec<u8>, Vec<u8>, u64, Vec<u8>), // (owner_pubkey_hash, asset_id, amount, salt)
        fee_amount: u64,
        fee_reservoir_address_hash: Vec<u8>,
    ) -> Result<crate::core::proof::SerializableProof, crate::core::proof::ProofError> {
        use plonky2::iop::witness::{PartialWitness, WitnessWrite};
        use crate::core::proof::{serialize_proof, ProofError};
        
        // Create a new circuit builder for virtual targets
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Set creator public key
        let creator_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Set asset parameters
        let asset_nonce_target = builder.add_virtual_target();
        let decimals_target = builder.add_virtual_target();
        let max_supply_target = builder.add_virtual_target();
        let is_mintable_target = builder.add_virtual_target();
        
        // Create fee input UTXO
        let (fee_owner_pubkey_hash, fee_asset_id, fee_amount_value, fee_salt) = &fee_input_utxo_data;
        let fee_input_utxo = UTXOTarget {
            owner_pubkey_hash_target: (0..fee_owner_pubkey_hash.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: (0..fee_asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..fee_salt.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Set fee amount
        let fee_amount_target = builder.add_virtual_target();
        
        // Set fee reservoir address hash
        let fee_reservoir_address_hash_targets: Vec<Target> = (0..fee_reservoir_address_hash.len())
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create signature
        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Create the circuit
        let circuit = NativeAssetCreateCircuit {
            creator_pk,
            asset_nonce: asset_nonce_target,
            decimals: decimals_target,
            max_supply: max_supply_target,
            is_mintable: is_mintable_target,
            fee_input_utxo,
            fee_amount: fee_amount_target,
            fee_reservoir_address_hash: fee_reservoir_address_hash_targets,
            signature,
        };
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);
        
        // Build the circuit data
        let circuit_data = builder.build::<PoseidonGoldilocksConfig>();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Set creator public key
        pw.set_target(circuit.creator_pk.point.x, GoldilocksField::from_canonical_u64(creator_pk_x));
        pw.set_target(circuit.creator_pk.point.y, GoldilocksField::from_canonical_u64(creator_pk_y));
        
        // Set asset parameters
        pw.set_target(circuit.asset_nonce, GoldilocksField::from_canonical_u64(asset_nonce));
        pw.set_target(circuit.decimals, GoldilocksField::from_canonical_u64(decimals));
        pw.set_target(circuit.max_supply, GoldilocksField::from_canonical_u64(max_supply));
        pw.set_target(
            circuit.is_mintable, 
            GoldilocksField::from_canonical_u64(if is_mintable { 1 } else { 0 })
        );
        
        // Set signature
        pw.set_target(circuit.signature.r_point.x, GoldilocksField::from_canonical_u64(signature_r_x));
        pw.set_target(circuit.signature.r_point.y, GoldilocksField::from_canonical_u64(signature_r_y));
        pw.set_target(circuit.signature.s_scalar, GoldilocksField::from_canonical_u64(signature_s));
        
        // Set fee input UTXO values
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
        
        // Generate the proof
        let proof = crate::core::proof::generate_proof(&circuit_data, pw)
            .map_err(|e| ProofError::ProofGenerationError(format!("{:?}", e)))?;
        
        // Serialize the proof
        serialize_proof(&proof)
    }
    
    /// Verify a proof for the native asset create circuit
    pub fn verify_proof(serialized_proof: &crate::core::proof::SerializableProof) -> Result<(), crate::core::proof::ProofError> {
        use crate::core::proof::deserialize_proof;
        
        // Create the circuit
        let circuit_data = Self::create_circuit();
        
        // Deserialize the proof
        let proof = deserialize_proof(serialized_proof)?;
        
        // Verify the proof
        crate::core::proof::verify_proof(&circuit_data, &proof)
    }
}
