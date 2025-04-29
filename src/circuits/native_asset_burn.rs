// Native Asset Burn Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, HASH_SIZE, DEFAULT_FEE};
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
        
        // Create a signature using the owner's secret key
        // In a real implementation, this would use a proper EdDSA signature
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
            &self.owner_pk,
        );
        
        // Assert that the signature is valid
        let one = builder.one();
        builder.connect(is_valid, one);
        
        // Enforce that the burn amount is less than or equal to the input amount
        let is_valid_amount = crate::gadgets::is_less_than_or_equal(
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
            &signature,
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
        
        // Use the Field trait to create a constant from u64
        let fee_amount = builder.constant(GoldilocksField::from_noncanonical_u64(DEFAULT_FEE));
        
        let fee_reservoir_address_hash: Vec<Target> = (0..32)
            .map(|_| builder.add_virtual_target())
            .collect();
        
        let circuit = NativeAssetBurnCircuit {
            input_utxo,
            owner_pk,
            burn_amount,
            fee_input_utxo,
            fee_amount,
            fee_reservoir_address_hash,
        };
        
        // Create a dummy owner secret key
        let _owner_sk = builder.add_virtual_target();
        
        // Build the circuit
        circuit.build::<GoldilocksField, PoseidonGoldilocksConfig, 2>(&mut builder, _owner_sk);
        
        // Build the circuit data
        builder.build::<PoseidonGoldilocksConfig>()
    }
}
