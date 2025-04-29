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
}

impl NativeAssetCreateCircuit {
    /// Build the native asset create circuit
    pub fn build<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> UTXOTarget {
        // Create a message to sign (the asset parameters)
        let mut message = Vec::new();
        message.push(self.asset_nonce);
        message.push(self.decimals);
        message.push(self.max_supply);
        message.push(self.is_mintable);
        
        // Create a signature
        let signature = SignatureTarget {
            r_point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
            s_scalar: builder.add_virtual_target(),
        };
        
        // Verify the signature
        let is_valid = verify_message_signature(
            builder,
            &message,
            &signature,
            &self.creator_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Calculate the asset ID
        let asset_id = calculate_asset_id(
            builder,
            &[self.creator_pk.point.x, self.creator_pk.point.y],
            self.asset_nonce,
            self.decimals,
            self.max_supply,
            self.is_mintable,
        );
        
        // Enforce fee payment
        let _wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.creator_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &signature,
        );
        
        // Create a registry UTXO for the asset
        let registry_utxo = UTXOTarget {
            owner_pubkey_hash_target: (0..asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
            asset_id_target: asset_id.clone(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Set the owner to the creator's public key hash
        // In a real implementation, we would hash the creator's public key
        // For now, we'll just use the asset ID as a placeholder
        for (a, b) in registry_utxo.owner_pubkey_hash_target.iter().zip(asset_id.iter()) {
            builder.connect(*a, *b);
        }
        
        // Set the amount to 0 (this is just a registry entry)
        let zero = builder.zero();
        builder.connect(registry_utxo.amount_target, zero);
        
        // Return the registry UTXO
        registry_utxo
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
        
        // Create a fee amount
        let fee_amount = builder.constant(GoldilocksField::from_noncanonical_u64(DEFAULT_FEE));
        
        // Create a fee reservoir address
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
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
        };
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder);
        
        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }
}
