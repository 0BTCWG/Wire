#[cfg(test)]
mod native_asset_circuit_tests {
    use wire_lib::circuits::native_asset_create::NativeAssetCreateCircuit;
    use wire_lib::circuits::native_asset_mint::NativeAssetMintCircuit;
    use wire_lib::circuits::native_asset_burn::NativeAssetBurnCircuit;
    use plonky2::iop::target::Target;
    use wire_lib::core::{PublicKeyTarget, SignatureTarget, UTXOTarget, PointTarget};
    
    #[test]
    fn test_native_asset_create_real_proof() {
        // Test parameters
        let creator_pk_x = 123456789;
        let creator_pk_y = 987654321;
        let asset_nonce = 42;
        let decimals = 8;
        let max_supply = 1000000;
        let is_mintable = true;
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;
        
        // Fee input UTXO (wBTC)
        let fee_input_utxo_data = (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // wBTC asset ID
            500, // Amount
            vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], // Salt
        );
        
        // Fee information
        let fee_amount = 100;
        let fee_reservoir_address_hash = vec![90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121];
        
        // Generate a proof
        let proof_result = NativeAssetCreateCircuit::generate_proof_static(
            creator_pk_x,
            creator_pk_y,
            asset_nonce,
            decimals,
            max_supply,
            is_mintable,
            signature_r_x,
            signature_r_y,
            signature_s,
            fee_input_utxo_data,
            fee_amount,
            fee_reservoir_address_hash,
        ).expect("Failed to generate proof");
        
        // Verify the proof
        let verification_result = NativeAssetCreateCircuit::verify_proof(&proof_result);
        assert!(verification_result.is_ok(), "Proof verification failed: {:?}", verification_result.err());
    }
    
    #[test]
    fn test_native_asset_mint_real_proof() {
        // Test parameters
        let minter_pk_x = 123456789;
        let minter_pk_y = 987654321;
        let asset_id = vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1];
        let recipient_pk_hash = vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2];
        let mint_amount = 500;
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;
        
        // Fee input UTXO (wBTC)
        let fee_input_utxo_data = (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // wBTC asset ID
            500, // Amount
            vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], // Salt
        );
        
        // Fee information
        let fee_amount = 100;
        let fee_reservoir_address_hash = vec![90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121];
        
        // Generate a proof
        let proof_result = NativeAssetMintCircuit::generate_proof_static(
            minter_pk_x,
            minter_pk_y,
            asset_id,
            recipient_pk_hash,
            mint_amount,
            signature_r_x,
            signature_r_y,
            signature_s,
            fee_input_utxo_data,
            fee_amount,
            fee_reservoir_address_hash,
        ).expect("Failed to generate proof");
        
        // Verify the proof
        let verification_result = NativeAssetMintCircuit::verify_proof(&proof_result);
        assert!(verification_result.is_ok(), "Proof verification failed: {:?}", verification_result.err());
    }
    
    #[test]
    fn test_native_asset_burn_real_proof() {
        // Test parameters for input UTXO
        let input_utxo_data = (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            vec![1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1], // Custom asset ID
            1000, // Amount
            vec![3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3], // Salt
        );
        
        let owner_pk_x = 123456789;
        let owner_pk_y = 987654321;
        let owner_sk = 987654321;
        let burn_amount = 500; // Burn half of the tokens
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;
        
        // Fee input UTXO (wBTC)
        let fee_input_utxo_data = (
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], // wBTC asset ID
            200, // Amount - reduced to avoid constraint violations
            vec![2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2], // Salt
        );
        
        // Fee information
        let fee_amount = 100;
        let fee_reservoir_address_hash = vec![90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121];
        
        // Generate a proof
        let proof_result = NativeAssetBurnCircuit::generate_proof_static(
            input_utxo_data,
            owner_pk_x,
            owner_pk_y,
            owner_sk,
            burn_amount,
            signature_r_x,
            signature_r_y,
            signature_s,
            fee_input_utxo_data,
            fee_amount,
            fee_reservoir_address_hash,
        ).expect("Failed to generate proof");
        
        // Verify the proof
        let verification_result = NativeAssetBurnCircuit::verify_proof(&proof_result);
        assert!(verification_result.is_ok(), "Proof verification failed: {:?}", verification_result.err());
    }
}
