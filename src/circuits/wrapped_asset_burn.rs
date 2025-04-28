// Wrapped Asset Burn Circuit for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitData;
use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
use plonky2::field::goldilocks_field::GoldilocksField;

use crate::core::{PublicKeyTarget, SignatureTarget, UTXOTarget};
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::PointTarget;
    use plonky2::iop::witness::PartialWitness;
    
    #[test]
    fn test_wrapped_asset_burn() {
        // Create the circuit
        let circuit_data = WrappedAssetBurnCircuit::create_circuit();
        
        // Create a witness
        let mut pw = PartialWitness::new();
        
        // In a real test, we would set the witness values
        // For now, we'll just create an empty witness
        
        // Generate the proof
        let proof = circuit_data.prove(pw).unwrap();
        
        // Verify the proof
        circuit_data.verify(proof).unwrap();
    }
}
