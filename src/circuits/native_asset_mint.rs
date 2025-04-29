// Native Asset Mint Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, DEFAULT_FEE};
use crate::gadgets::{enforce_fee_payment, verify_message_signature};

/// Circuit for minting native asset tokens
///
/// This circuit verifies that the minter is authorized to mint the asset,
/// enforces the fee payment, and creates the output UTXO.
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
            &self.minter_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Enforce fee payment
        let _wbtc_change_amount = enforce_fee_payment(
            builder,
            &self.minter_pk,
            &self.fee_input_utxo,
            self.fee_amount,
            &self.fee_reservoir_address_hash,
            &signature,
        );
        
        // Create an output UTXO for the recipient
        let output_utxo = UTXOTarget {
            owner_pubkey_hash_target: self.recipient_pk_hash.clone(),
            asset_id_target: self.asset_id.clone(),
            amount_target: builder.add_virtual_target(),
            salt_target: (0..self.asset_id.len())
                .map(|_| builder.add_virtual_target())
                .collect(),
        };
        
        // Set the amount
        builder.connect(output_utxo.amount_target, self.mint_amount);
        
        // Return the output UTXO
        output_utxo
    }
    
    /// Create and build the circuit
    pub fn create_circuit() -> CircuitData<GoldilocksField, PoseidonGoldilocksConfig, 2> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<GoldilocksField, 2>::new(config);
        
        // Create a minter public key
        let minter_pk = PublicKeyTarget {
            point: crate::core::PointTarget {
                x: builder.add_virtual_target(),
                y: builder.add_virtual_target(),
            },
        };
        
        // Create an asset ID
        let asset_id: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a recipient public key hash
        let recipient_pk_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        // Create a mint amount
        let mint_amount = builder.add_virtual_target();
        
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
        let circuit = NativeAssetMintCircuit {
            minter_pk,
            asset_id,
            recipient_pk_hash,
            mint_amount,
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
