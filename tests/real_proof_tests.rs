#[cfg(test)]
mod real_proof_tests {
    use plonky2::iop::target::Target;
    use wire_lib::circuits::transfer::TransferCircuit;
    use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
    use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
    use wire_lib::core::proof::SerializableProof;
    use wire_lib::core::{PointTarget, PublicKeyTarget, SignatureTarget, UTXOTarget};

    #[test]
    fn test_wrapped_asset_mint_real_proof() {
        // Test parameters
        let recipient_pk_hash = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let amount = 1000;
        let deposit_nonce = 12345;
        let custodian_pk_x = 123456789;
        let custodian_pk_y = 987654321;
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;

        // Generate a proof
        let proof_result = WrappedAssetMintCircuit::generate_proof(
            &recipient_pk_hash,
            amount,
            deposit_nonce,
            custodian_pk_x,
            custodian_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        )
        .expect("Failed to generate proof");

        // Verify the proof
        let verification_result = WrappedAssetMintCircuit::verify_proof(&proof_result);
        assert!(
            verification_result.is_ok(),
            "Proof verification failed: {:?}",
            verification_result.err()
        );
    }

    #[test]
    fn test_wrapped_asset_burn_real_proof() {
        // Test parameters
        let input_utxo_owner_pubkey_hash = vec![
            1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
            25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let input_utxo_asset_id = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ]; // wBTC asset ID
        let input_utxo_amount = 2000;
        let input_utxo_salt = vec![
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
            42, 42, 42, 42, 42, 42, 42, 42, 42, 42,
        ];
        let sender_sk = 987654321;
        let sender_pk_x = 123456789;
        let sender_pk_y = 987654321;
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;
        let destination_btc_address = vec![
            10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 110, 120, 130, 140, 150, 160, 170, 180, 190,
            200,
        ];

        // Create a circuit instance
        let circuit = WrappedAssetBurnCircuit {
            input_utxo: UTXOTarget {
                owner_pubkey_hash_target: vec![],
                asset_id_target: vec![],
                amount_target: Target::default(),
                salt_target: vec![],
            },
            sender_pk: PublicKeyTarget {
                point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
            },
            sender_sig: SignatureTarget {
                r_point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
                s_scalar: Target::default(),
            },
            destination_btc_address: vec![],
            fee_quote: None,
            custodian_pk: None,
        };

        // Generate a proof without fee quote
        let proof_result = WrappedAssetBurnCircuit::generate_proof_static(
            &input_utxo_owner_pubkey_hash,
            &input_utxo_asset_id,
            input_utxo_amount,
            &input_utxo_salt,
            sender_sk,
            sender_pk_x,
            sender_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            &destination_btc_address,
            None, // No fee
            None, // No expiry
            None, // No fee signature r_x
            None, // No fee signature r_y
            None, // No fee signature s
            None, // No custodian pk_x
            None, // No custodian pk_y
        )
        .expect("Failed to generate proof");

        // Verify the proof
        let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof_result);
        assert!(
            verification_result.is_ok(),
            "Proof verification failed: {:?}",
            verification_result.err()
        );
    }

    #[test]
    fn test_transfer_real_proof() {
        // Test parameters for input UTXOs
        let input_utxo_1 = (
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 1,
            ], // Asset ID
            1000, // Amount
            vec![
                1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                1, 1, 1, 1,
            ], // Salt
        );

        let input_utxos_data = vec![input_utxo_1];

        // Recipient public key hashes
        let recipient_1_pk_hash = vec![
            50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71,
            72, 73, 74, 75, 76, 77, 78, 79, 80, 81,
        ];
        let recipient_pk_hashes = vec![recipient_1_pk_hash];

        // Output amounts
        let output_amounts = vec![800]; // Sending 800 tokens to recipient 1

        // Sender information
        let sender_sk = 987654321;
        let sender_pk_x = 123456789;
        let sender_pk_y = 987654321;
        let signature_r_x = 111222333;
        let signature_r_y = 444555666;
        let signature_s = 777888999;

        // Fee input UTXO (wBTC)
        let fee_input_utxo_data = (
            vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            vec![
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0,
            ], // wBTC asset ID
            500, // Amount
            vec![
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
                2, 2, 2, 2,
            ], // Salt
        );

        // Fee information
        let fee_amount = 100;
        let fee_reservoir_address_hash = vec![
            90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108,
            109, 110, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
        ];
        let nonce = 12345;

        // Create a circuit instance
        let circuit = TransferCircuit {
            input_utxos: vec![],
            recipient_pk_hashes: vec![],
            output_amounts: vec![],
            sender_pk: PublicKeyTarget {
                point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
            },
            sender_sig: SignatureTarget {
                r_point: PointTarget {
                    x: Target::default(),
                    y: Target::default(),
                },
                s_scalar: Target::default(),
            },
            fee_input_utxo: UTXOTarget {
                owner_pubkey_hash_target: vec![],
                asset_id_target: vec![],
                amount_target: Target::default(),
                salt_target: vec![],
            },
            fee_amount: Target::default(),
            fee_reservoir_address_hash: vec![],
        };

        // Generate a proof
        let proof_result = TransferCircuit::generate_proof_static(
            input_utxos_data,
            recipient_pk_hashes,
            output_amounts,
            sender_sk,
            sender_pk_x,
            sender_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            fee_input_utxo_data,
            fee_amount,
            fee_reservoir_address_hash,
            nonce,
        )
        .expect("Failed to generate proof");

        // Verify the proof
        let verification_result = TransferCircuit::verify_proof(&proof_result);
        assert!(
            verification_result.is_ok(),
            "Proof verification failed: {:?}",
            verification_result.err()
        );
    }
}
