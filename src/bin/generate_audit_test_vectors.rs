use clap::{Arg, Command};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;
use wire_lib::circuits::add_liquidity::AddLiquidityCircuit;
use wire_lib::circuits::remove_liquidity::RemoveLiquidityCircuit;
use wire_lib::circuits::stablecoin_mint::StablecoinMintCircuit;
use wire_lib::circuits::stablecoin_redeem::StablecoinRedeemCircuit;
use wire_lib::circuits::swap::SwapCircuit;
use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::core::{CollateralMetadataTarget, CollateralUTXOTarget, UTXOTarget};

fn main() {
    let matches = Command::new("0BTC Wire Audit Test Vector Generator")
        .version("1.0")
        .author("0BTC Wire Team")
        .about("Generates test vectors for the 0BTC Wire audit")
        .arg(
            Arg::new("output-dir")
                .long("output-dir")
                .value_name("DIR")
                .help("Directory to output test vectors")
                .required(true),
        )
        .get_matches();

    let output_dir = matches.get_one::<String>("output-dir").unwrap();
    let output_path = Path::new(output_dir);

    // Create output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path).expect("Failed to create output directory");
    }

    // Generate test vectors
    generate_wrapped_mint_test_vectors(output_path);
    generate_wrapped_burn_test_vectors(output_path);
    generate_transfer_test_vectors(output_path);

    // Generate AMM test vectors
    generate_swap_test_vectors(output_path);
    generate_add_liquidity_test_vectors(output_path);
    generate_remove_liquidity_test_vectors(output_path);

    // Generate Stablecoin test vectors
    generate_stablecoin_mint_test_vectors(output_path);
    generate_stablecoin_redeem_test_vectors(output_path);

    println!("Test vectors generated successfully in {}", output_dir);
}

fn generate_wrapped_mint_test_vectors(output_path: &Path) {
    println!("Generating wrapped mint test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector
    let recipient_pk_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let amount = 1_000_000; // 0.01 BTC in satoshis
    let deposit_nonce = 42;
    let custodian_pk_x = 0xfedcba0987654321;
    let custodian_pk_y = 0x1122334455667788;
    let signature_r_x = 0xaabbccddeeff0011;
    let signature_r_y = 0x2233445566778899;
    let signature_s = 0x9988776655443322;

    // Skip creating a circuit instance and use the static method directly
    let result = WrappedAssetMintCircuit::generate_proof(
        &recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );

    if let Ok(proof) = result {
        // Create test vector
        let test_vector = json!({
            "name": "valid_wrapped_mint",
            "description": "Valid wrapped mint proof",
            "inputs": {
                "recipient_pk_hash": recipient_pk_hash,
                "amount": amount,
                "deposit_nonce": deposit_nonce,
                "custodian_pk_x": custodian_pk_x,
                "custodian_pk_y": custodian_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s
            },
            "expected_result": {
                "valid": true
            },
            "proof": proof
        });

        test_vectors.push(test_vector);

        // Invalid signature test vector
        let invalid_signature_test_vector = json!({
            "name": "invalid_signature_wrapped_mint",
            "description": "Wrapped mint proof with invalid signature",
            "inputs": {
                "recipient_pk_hash": recipient_pk_hash,
                "amount": amount,
                "deposit_nonce": deposit_nonce,
                "custodian_pk_x": custodian_pk_x,
                "custodian_pk_y": custodian_pk_y,
                "signature_r_x": 0,
                "signature_r_y": 0,
                "signature_s": 0
            },
            "expected_result": {
                "valid": false,
                "error": "Invalid signature"
            }
        });

        test_vectors.push(invalid_signature_test_vector);

        // Zero amount test vector
        let zero_amount_test_vector = json!({
            "name": "zero_amount_wrapped_mint",
            "description": "Wrapped mint proof with zero amount",
            "inputs": {
                "recipient_pk_hash": recipient_pk_hash,
                "amount": 0,
                "deposit_nonce": deposit_nonce,
                "custodian_pk_x": custodian_pk_x,
                "custodian_pk_y": custodian_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s
            },
            "expected_result": {
                "valid": false,
                "error": "Amount must be greater than zero"
            }
        });

        test_vectors.push(zero_amount_test_vector);

        // Write test vectors to file
        let file_path = output_path.join("wrapped_mint_test_vectors.json");
        let mut file = File::create(&file_path).expect("Failed to create file");
        let json_str =
            serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes())
            .expect("Failed to write test vectors");

        println!("Wrapped mint test vectors written to {:?}", file_path);
    } else {
        println!("Failed to generate wrapped mint proof: {:?}", result.err());
    }
}

fn generate_wrapped_burn_test_vectors(output_path: &Path) {
    println!("Generating wrapped burn test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector
    let owner_pubkey_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let asset_id = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let amount = 1_000_000; // 0.01 BTC in satoshis
    let salt = vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
    let sender_sk = 0x1234567890abcdef;
    let sender_pk_x = 0xfedcba0987654321;
    let sender_pk_y = 0x1122334455667788;
    let signature_r_x = 0xaabbccddeeff0011;
    let signature_r_y = 0x2233445566778899;
    let signature_s = 0x9988776655443322;
    let destination_btc_address = vec![
        0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x88, 0xac,
    ];

    // Skip creating a circuit instance and use the static method directly
    let result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash,
        &asset_id,
        amount,
        &salt,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        &destination_btc_address,
        None, // fee_btc
        None, // fee_expiry
        None, // fee_signature_r_x
        None, // fee_signature_r_y
        None, // fee_signature_s
        None, // custodian_pk_x
        None, // custodian_pk_y
    );

    if let Ok(proof) = result {
        // Create test vector
        let test_vector = json!({
            "name": "valid_wrapped_burn",
            "description": "Valid wrapped burn proof",
            "inputs": {
                "owner_pubkey_hash": owner_pubkey_hash,
                "asset_id": asset_id,
                "amount": amount,
                "salt": salt,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s,
                "destination_btc_address": destination_btc_address
            },
            "expected_result": {
                "valid": true
            },
            "proof": proof
        });

        test_vectors.push(test_vector);

        // Invalid signature test vector
        let invalid_signature_test_vector = json!({
            "name": "invalid_signature_wrapped_burn",
            "description": "Wrapped burn proof with invalid signature",
            "inputs": {
                "owner_pubkey_hash": owner_pubkey_hash,
                "asset_id": asset_id,
                "amount": amount,
                "salt": salt,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": 0,
                "signature_r_y": 0,
                "signature_s": 0,
                "destination_btc_address": destination_btc_address
            },
            "expected_result": {
                "valid": false,
                "error": "Invalid signature"
            }
        });

        test_vectors.push(invalid_signature_test_vector);

        // Zero amount test vector
        let zero_amount_test_vector = json!({
            "name": "zero_amount_wrapped_burn",
            "description": "Wrapped burn proof with zero amount",
            "inputs": {
                "owner_pubkey_hash": owner_pubkey_hash,
                "asset_id": asset_id,
                "amount": 0,
                "salt": salt,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s,
                "destination_btc_address": destination_btc_address
            },
            "expected_result": {
                "valid": false,
                "error": "Amount must be greater than zero"
            }
        });

        test_vectors.push(zero_amount_test_vector);

        // Write test vectors to file
        let file_path = output_path.join("wrapped_burn_test_vectors.json");
        let mut file = File::create(&file_path).expect("Failed to create file");
        let json_str =
            serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes())
            .expect("Failed to write test vectors");

        println!("Wrapped burn test vectors written to {:?}", file_path);
    } else {
        println!("Failed to generate wrapped burn proof: {:?}", result.err());
    }
}

fn generate_transfer_test_vectors(output_path: &Path) {
    println!("Generating transfer test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector
    let owner_pubkey_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let asset_id = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let amount = 1_000_000; // 0.01 BTC in satoshis
    let salt = vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
    let sender_sk = 0x1234567890abcdef;
    let sender_pk_x: u64 = 0xfedcba0987654321;
    let sender_pk_y: u64 = 0x1122334455667788;
    let signature_r_x: u64 = 0xaabbccddeeff0011;
    let signature_r_y: u64 = 0x2233445566778899;
    let signature_s: u64 = 0x9988776655443322;
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create input UTXOs
    let input_utxos_data = vec![(
        owner_pubkey_hash.clone(),
        asset_id.clone(),
        amount,
        salt.clone(),
    )];

    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];

    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (
        owner_pubkey_hash.clone(),
        asset_id.clone(),
        amount,
        salt.clone(),
    );

    // Convert input data to the correct format
    let input_utxos: Vec<Vec<u8>> = input_utxos_data
        .iter()
        .map(|utxo| {
            let (owner_pk_hash, asset_id, amount, salt) = utxo;
            // Convert amount to bytes directly
            let mut amount_bytes = Vec::with_capacity(8);
            let amount_bytes_array = u64_to_le_bytes(*amount);
            amount_bytes.extend_from_slice(&amount_bytes_array);
            vec![
                owner_pk_hash.clone(),
                asset_id.clone(),
                amount_bytes,
                salt.clone(),
            ]
            .concat()
        })
        .collect();

    // Create a transfer circuit instance
    let transfer_circuit = TransferCircuit::new(
        input_utxos_data.len(),
        recipient_pk_hashes.clone(),
        output_amounts.clone(),
        vec![
            sender_pk_x.to_le_bytes().to_vec(),
            sender_pk_y.to_le_bytes().to_vec(),
        ]
        .concat(),
        vec![
            signature_r_x.to_le_bytes().to_vec(),
            signature_r_y.to_le_bytes().to_vec(),
            signature_s.to_le_bytes().to_vec(),
        ]
        .concat(),
        vec![
            fee_input_utxo_data.0.clone(),
            fee_input_utxo_data.1.clone(),
            fee_input_utxo_data.2.to_le_bytes().to_vec(),
            fee_input_utxo_data.3.clone(),
        ]
        .concat(),
        fee_amount,
        fee_reservoir_address_hash.clone(),
    );

    // Generate proof
    let result = transfer_circuit.generate_proof(
        input_utxos,
        recipient_pk_hashes.clone(),
        output_amounts.clone(),
        sender_sk,
        vec![
            sender_pk_x.to_le_bytes().to_vec(),
            sender_pk_y.to_le_bytes().to_vec(),
        ]
        .concat(),
        vec![
            signature_r_x.to_le_bytes().to_vec(),
            signature_r_y.to_le_bytes().to_vec(),
            signature_s.to_le_bytes().to_vec(),
        ]
        .concat(),
        vec![
            fee_input_utxo_data.0.clone(),
            fee_input_utxo_data.1.clone(),
            fee_input_utxo_data.2.to_le_bytes().to_vec(),
            fee_input_utxo_data.3.clone(),
        ]
        .concat(),
        fee_amount,
        fee_reservoir_address_hash.clone(),
        nonce,
    );

    if let Ok(proof) = result {
        // Create test vector
        let test_vector = json!({
            "name": "valid_transfer",
            "description": "Valid transfer proof",
            "inputs": {
                "input_utxos": [
                    {
                        "owner_pubkey_hash": owner_pubkey_hash,
                        "asset_id": asset_id,
                        "amount": amount,
                        "salt": salt
                    }
                ],
                "recipient_pk_hashes": recipient_pk_hashes,
                "output_amounts": output_amounts,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s,
                "fee_input_utxo": {
                    "owner_pubkey_hash": owner_pubkey_hash,
                    "asset_id": asset_id,
                    "amount": amount,
                    "salt": salt
                },
                "fee_amount": fee_amount,
                "fee_reservoir_address_hash": fee_reservoir_address_hash,
                "nonce": nonce
            },
            "expected_result": {
                "valid": true
            },
            "proof": proof
        });

        test_vectors.push(test_vector);

        // Invalid signature test vector
        let invalid_signature_test_vector = json!({
            "name": "invalid_signature_transfer",
            "description": "Transfer proof with invalid signature",
            "inputs": {
                "input_utxos": [
                    {
                        "owner_pubkey_hash": owner_pubkey_hash,
                        "asset_id": asset_id,
                        "amount": amount,
                        "salt": salt
                    }
                ],
                "recipient_pk_hashes": recipient_pk_hashes,
                "output_amounts": output_amounts,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": 0,
                "signature_r_y": 0,
                "signature_s": 0,
                "fee_input_utxo": {
                    "owner_pubkey_hash": owner_pubkey_hash,
                    "asset_id": asset_id,
                    "amount": amount,
                    "salt": salt
                },
                "fee_amount": fee_amount,
                "fee_reservoir_address_hash": fee_reservoir_address_hash,
                "nonce": nonce
            },
            "expected_result": {
                "valid": false,
                "error": "Invalid signature"
            }
        });

        test_vectors.push(invalid_signature_test_vector);

        // Conservation of value violation test vector
        let invalid_output_amounts = vec![amount + 1]; // Output > Input
        let conservation_violation_test_vector = json!({
            "name": "conservation_violation_transfer",
            "description": "Transfer proof with conservation of value violation",
            "inputs": {
                "input_utxos": [
                    {
                        "owner_pubkey_hash": owner_pubkey_hash,
                        "asset_id": asset_id,
                        "amount": amount,
                        "salt": salt
                    }
                ],
                "recipient_pk_hashes": recipient_pk_hashes,
                "output_amounts": invalid_output_amounts,
                "sender_sk": sender_sk,
                "sender_pk_x": sender_pk_x,
                "sender_pk_y": sender_pk_y,
                "signature_r_x": signature_r_x,
                "signature_r_y": signature_r_y,
                "signature_s": signature_s,
                "fee_input_utxo": {
                    "owner_pubkey_hash": owner_pubkey_hash,
                    "asset_id": asset_id,
                    "amount": amount,
                    "salt": salt
                },
                "fee_amount": fee_amount,
                "fee_reservoir_address_hash": fee_reservoir_address_hash,
                "nonce": nonce
            },
            "expected_result": {
                "valid": false,
                "error": "Conservation of value violation"
            }
        });

        test_vectors.push(conservation_violation_test_vector);

        // Write test vectors to file
        let file_path = output_path.join("transfer_test_vectors.json");
        let mut file = File::create(&file_path).expect("Failed to create file");
        let json_str =
            serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes())
            .expect("Failed to write test vectors");

        println!("Transfer test vectors written to {:?}", file_path);
    } else {
        println!("Failed to generate transfer proof: {:?}", result.err());
    }
}

fn generate_swap_test_vectors(output_path: &Path) {
    println!("Generating swap test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector - balanced swap
    {
        // Create input UTXOs
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let token_a_asset_id = [0x01; 32];
        let token_b_asset_id = [0x02; 32];
        let token_a_amount = 1000;
        let token_b_amount = 2000;

        let input_utxo_a =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_a_asset_id, token_a_amount);

        let input_utxo_b =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_b_asset_id, token_b_amount);

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof
        let result = SwapCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = SwapCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify valid swap proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid swap with balanced token amounts",
                    "input": {
                        "input_utxo_a": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_a_asset_id)),
                            "amount": token_a_amount,
                        },
                        "input_utxo_b": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_b_asset_id)),
                            "amount": token_b_amount,
                        },
                        "signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                panic!("Failed to generate valid swap proof: {:?}", e);
            }
        }
    }

    // Valid test vector - extreme price ratio
    {
        // Create input UTXOs with extreme price ratio
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let token_a_asset_id = [0x01; 32];
        let token_b_asset_id = [0x02; 32];
        let token_a_amount = 1000000;
        let token_b_amount = 10;

        let input_utxo_a =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_a_asset_id, token_a_amount);

        let input_utxo_b =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_b_asset_id, token_b_amount);

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof
        let result = SwapCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = SwapCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify extreme price ratio swap proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid swap with extreme price ratio (100,000:1)",
                    "input": {
                        "input_utxo_a": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_a_asset_id)),
                            "amount": token_a_amount,
                        },
                        "input_utxo_b": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_b_asset_id)),
                            "amount": token_b_amount,
                        },
                        "signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                // If this fails, it might be due to legitimate constraints
                println!("Failed to generate extreme price ratio swap proof: {:?}", e);

                // Create test vector for failed case
                let test_vector = json!({
                    "description": "Swap with extreme price ratio (100,000:1) - failed",
                    "input": {
                        "input_utxo_a": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_a_asset_id)),
                            "amount": token_a_amount,
                        },
                        "input_utxo_b": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_b_asset_id)),
                            "amount": token_b_amount,
                        },
                        "signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                    },
                    "output": {
                        "error": format!("{:?}", e),
                        "verification_result": "invalid",
                    },
                });

                test_vectors.push(test_vector);
            }
        }
    }

    // Invalid test vector - same asset IDs (should fail)
    {
        // Create input UTXOs with same asset IDs
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let asset_id = [0x01; 32]; // Same asset ID for both
        let token_a_amount = 1000;
        let token_b_amount = 2000;

        let input_utxo_a = UTXOTarget::new_test(owner_pk_x, owner_pk_y, asset_id, token_a_amount);

        let input_utxo_b = UTXOTarget::new_test(
            owner_pk_x,
            owner_pk_y,
            asset_id, // Same asset ID
            token_b_amount,
        );

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof (should fail)
        let result = SwapCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        // Create test vector
        let test_vector = json!({
            "description": "Invalid swap with same asset IDs",
            "input": {
                "input_utxo_a": {
                    "owner_pk_x": format!("0x{:x}", owner_pk_x),
                    "owner_pk_y": format!("0x{:x}", owner_pk_y),
                    "asset_id": format!("0x{}", hex::encode(asset_id)),
                    "amount": token_a_amount,
                },
                "input_utxo_b": {
                    "owner_pk_x": format!("0x{:x}", owner_pk_x),
                    "owner_pk_y": format!("0x{:x}", owner_pk_y),
                    "asset_id": format!("0x{}", hex::encode(asset_id)),
                    "amount": token_b_amount,
                },
                "signature": {
                    "r_x": format!("0x{:x}", signature_r_x),
                    "r_y": format!("0x{:x}", signature_r_y),
                    "s": format!("0x{:x}", signature_s),
                },
            },
            "output": {
                "error": format!("{:?}", result.err()),
                "verification_result": "invalid",
            },
        });

        test_vectors.push(test_vector);
    }

    // Write test vectors to file
    let file_path = output_path.join("swap_test_vectors.json");
    let mut file = File::create(file_path).expect("Failed to create swap test vectors file");
    let json_string =
        serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize swap test vectors");
    file.write_all(json_string.as_bytes())
        .expect("Failed to write swap test vectors");
}

// Helper function to convert u64 to little-endian bytes
fn u64_to_le_bytes(value: u64) -> [u8; 8] {
    let mut bytes = [0u8; 8];
    bytes[0] = (value & 0xff) as u8;
    bytes[1] = ((value >> 8) & 0xff) as u8;
    bytes[2] = ((value >> 16) & 0xff) as u8;
    bytes[3] = ((value >> 24) & 0xff) as u8;
    bytes[4] = ((value >> 32) & 0xff) as u8;
    bytes[5] = ((value >> 40) & 0xff) as u8;
    bytes[6] = ((value >> 48) & 0xff) as u8;
    bytes[7] = ((value >> 56) & 0xff) as u8;
    bytes
}

fn generate_add_liquidity_test_vectors(output_path: &Path) {
    println!("Generating add_liquidity test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector - initial liquidity provision
    {
        // Create input UTXOs
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let token_a_asset_id = [0x01; 32];
        let token_b_asset_id = [0x02; 32];
        let token_a_amount = 1000;
        let token_b_amount = 2000;
        let initial_liquidity = 0; // First liquidity provision

        let input_utxo_a =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_a_asset_id, token_a_amount);

        let input_utxo_b =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_b_asset_id, token_b_amount);

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof
        let result = AddLiquidityCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            initial_liquidity,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = AddLiquidityCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify initial liquidity provision proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid initial liquidity provision",
                    "input": {
                        "input_utxo_a": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_a_asset_id)),
                            "amount": token_a_amount,
                        },
                        "input_utxo_b": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_b_asset_id)),
                            "amount": token_b_amount,
                        },
                        "initial_liquidity": initial_liquidity,
                        "signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                panic!("Failed to generate valid add_liquidity proof: {:?}", e);
            }
        }
    }

    // Valid test vector - additional liquidity provision
    {
        // Create input UTXOs
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let token_a_asset_id = [0x01; 32];
        let token_b_asset_id = [0x02; 32];
        let token_a_amount = 500;
        let token_b_amount = 1000;
        let initial_liquidity = 1414; // Existing liquidity (sqrt(1000*2000))

        let input_utxo_a =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_a_asset_id, token_a_amount);

        let input_utxo_b =
            UTXOTarget::new_test(owner_pk_x, owner_pk_y, token_b_asset_id, token_b_amount);

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof
        let result = AddLiquidityCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            initial_liquidity,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = AddLiquidityCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify additional liquidity provision proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid additional liquidity provision",
                    "input": {
                        "input_utxo_a": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_a_asset_id)),
                            "amount": token_a_amount,
                        },
                        "input_utxo_b": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(token_b_asset_id)),
                            "amount": token_b_amount,
                        },
                        "initial_liquidity": initial_liquidity,
                        "signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                panic!("Failed to generate valid add_liquidity proof: {:?}", e);
            }
        }
    }

    // Invalid test vector - mismatched asset IDs (should fail)
    {
        // Create input UTXOs with same asset IDs
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let asset_id = [0x01; 32]; // Same asset ID for both
        let token_a_amount = 1000;
        let token_b_amount = 2000;
        let initial_liquidity = 0;

        let input_utxo_a = UTXOTarget::new_test(owner_pk_x, owner_pk_y, asset_id, token_a_amount);

        let input_utxo_b = UTXOTarget::new_test(
            owner_pk_x,
            owner_pk_y,
            asset_id, // Same asset ID
            token_b_amount,
        );

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Generate proof (should fail)
        let result = AddLiquidityCircuit::generate_proof_static(
            &input_utxo_a,
            &input_utxo_b,
            initial_liquidity,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
        );

        // Create test vector
        let test_vector = json!({
            "description": "Invalid add_liquidity with same asset IDs",
            "input": {
                "input_utxo_a": {
                    "owner_pk_x": format!("0x{:x}", owner_pk_x),
                    "owner_pk_y": format!("0x{:x}", owner_pk_y),
                    "asset_id": format!("0x{}", hex::encode(asset_id)),
                    "amount": token_a_amount,
                },
                "input_utxo_b": {
                    "owner_pk_x": format!("0x{:x}", owner_pk_x),
                    "owner_pk_y": format!("0x{:x}", owner_pk_y),
                    "asset_id": format!("0x{}", hex::encode(asset_id)),
                    "amount": token_b_amount,
                },
                "initial_liquidity": initial_liquidity,
                "signature": {
                    "r_x": format!("0x{:x}", signature_r_x),
                    "r_y": format!("0x{:x}", signature_r_y),
                    "s": format!("0x{:x}", signature_s),
                },
            },
            "output": {
                "error": format!("{:?}", result.err()),
                "verification_result": "invalid",
            },
        });

        test_vectors.push(test_vector);
    }

    // Write test vectors to file
    let file_path = output_path.join("add_liquidity_test_vectors.json");
    let mut file =
        File::create(file_path).expect("Failed to create add_liquidity test vectors file");
    let json_string = serde_json::to_string_pretty(&test_vectors)
        .expect("Failed to serialize add_liquidity test vectors");
    file.write_all(json_string.as_bytes())
        .expect("Failed to write add_liquidity test vectors");
}

fn generate_stablecoin_mint_test_vectors(output_path: &Path) {
    println!("Generating stablecoin_mint test vectors...");

    let mut test_vectors = Vec::new();

    // Valid test vector - minimum collateralization
    {
        // Create input UTXO for collateral
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let mpc_pk_x = 0xaabbccddeeff0011;
        let mpc_pk_y = 0x2233445566778899;
        let collateral_asset_id = [0x01; 32]; // wBTC
        let collateral_amount = 150;
        let zusd_amount = 100;
        let price = 1; // 1:1 price ratio for simplicity

        let input_utxo = UTXOTarget::new_test(
            owner_pk_x,
            owner_pk_y,
            collateral_asset_id,
            collateral_amount,
        );

        // Create collateral metadata
        let collateral_metadata = CollateralMetadataTarget {
            issuance_id: 1,
            lock_timestamp: 12345,
            timelock_period: 86400, // 1 day in seconds
            lock_price: price,
            collateral_ratio: 150, // Minimum ratio
        };

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Price oracle signature
        let price_sig_r_x = 0x1122334455667788;
        let price_sig_r_y = 0x99aabbccddeeff00;
        let price_sig_s = 0x8877665544332211;

        // Generate proof
        let result = StablecoinMintCircuit::generate_proof_static(
            &input_utxo,
            zusd_amount,
            price,
            mpc_pk_x,
            mpc_pk_y,
            &collateral_metadata,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            price_sig_r_x,
            price_sig_r_y,
            price_sig_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = StablecoinMintCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify minimum collateralization mint proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid stablecoin mint with minimum collateralization (150%)",
                    "input": {
                        "input_utxo": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(collateral_asset_id)),
                            "amount": collateral_amount,
                        },
                        "zusd_amount": zusd_amount,
                        "price": price,
                        "mpc_pk_x": format!("0x{:x}", mpc_pk_x),
                        "mpc_pk_y": format!("0x{:x}", mpc_pk_y),
                        "collateral_metadata": {
                            "issuance_id": collateral_metadata.issuance_id,
                            "lock_timestamp": collateral_metadata.lock_timestamp,
                            "timelock_period": collateral_metadata.timelock_period,
                            "lock_price": collateral_metadata.lock_price,
                            "collateral_ratio": collateral_metadata.collateral_ratio,
                        },
                        "user_signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                        "price_signature": {
                            "r_x": format!("0x{:x}", price_sig_r_x),
                            "r_y": format!("0x{:x}", price_sig_r_y),
                            "s": format!("0x{:x}", price_sig_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                panic!("Failed to generate valid stablecoin mint proof: {:?}", e);
            }
        }
    }

    // Valid test vector - higher collateralization
    {
        // Create input UTXO for collateral
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let mpc_pk_x = 0xaabbccddeeff0011;
        let mpc_pk_y = 0x2233445566778899;
        let collateral_asset_id = [0x01; 32]; // wBTC
        let collateral_amount = 200;
        let zusd_amount = 100;
        let price = 1; // 1:1 price ratio for simplicity

        let input_utxo = UTXOTarget::new_test(
            owner_pk_x,
            owner_pk_y,
            collateral_asset_id,
            collateral_amount,
        );

        // Create collateral metadata
        let collateral_metadata = CollateralMetadataTarget {
            issuance_id: 1,
            lock_timestamp: 12345,
            timelock_period: 86400, // 1 day in seconds
            lock_price: price,
            collateral_ratio: 200, // Higher ratio
        };

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Price oracle signature
        let price_sig_r_x = 0x1122334455667788;
        let price_sig_r_y = 0x99aabbccddeeff00;
        let price_sig_s = 0x8877665544332211;

        // Generate proof
        let result = StablecoinMintCircuit::generate_proof_static(
            &input_utxo,
            zusd_amount,
            price,
            mpc_pk_x,
            mpc_pk_y,
            &collateral_metadata,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            price_sig_r_x,
            price_sig_r_y,
            price_sig_s,
        );

        match result {
            Ok(proof) => {
                // Verify proof
                let verification_result = StablecoinMintCircuit::verify_proof(&proof);
                assert!(
                    verification_result.is_ok(),
                    "Failed to verify higher collateralization mint proof"
                );

                // Create test vector
                let test_vector = json!({
                    "description": "Valid stablecoin mint with higher collateralization (200%)",
                    "input": {
                        "input_utxo": {
                            "owner_pk_x": format!("0x{:x}", owner_pk_x),
                            "owner_pk_y": format!("0x{:x}", owner_pk_y),
                            "asset_id": format!("0x{}", hex::encode(collateral_asset_id)),
                            "amount": collateral_amount,
                        },
                        "zusd_amount": zusd_amount,
                        "price": price,
                        "mpc_pk_x": format!("0x{:x}", mpc_pk_x),
                        "mpc_pk_y": format!("0x{:x}", mpc_pk_y),
                        "collateral_metadata": {
                            "issuance_id": collateral_metadata.issuance_id,
                            "lock_timestamp": collateral_metadata.lock_timestamp,
                            "timelock_period": collateral_metadata.timelock_period,
                            "lock_price": collateral_metadata.lock_price,
                            "collateral_ratio": collateral_metadata.collateral_ratio,
                        },
                        "user_signature": {
                            "r_x": format!("0x{:x}", signature_r_x),
                            "r_y": format!("0x{:x}", signature_r_y),
                            "s": format!("0x{:x}", signature_s),
                        },
                        "price_signature": {
                            "r_x": format!("0x{:x}", price_sig_r_x),
                            "r_y": format!("0x{:x}", price_sig_r_y),
                            "s": format!("0x{:x}", price_sig_s),
                        },
                    },
                    "output": {
                        "proof": hex::encode(&proof.proof),
                        "public_inputs": proof.public_inputs.iter().map(|x| format!("0x{:x}", x)).collect::<Vec<_>>(),
                        "verification_result": "valid",
                    },
                });

                test_vectors.push(test_vector);
            }
            Err(e) => {
                panic!("Failed to generate valid stablecoin mint proof: {:?}", e);
            }
        }
    }

    // Invalid test vector - insufficient collateralization (should fail)
    {
        // Create input UTXO for collateral
        let owner_pk_x = 0x1234567890abcdef;
        let owner_pk_y = 0xfedcba0987654321;
        let mpc_pk_x = 0xaabbccddeeff0011;
        let mpc_pk_y = 0x2233445566778899;
        let collateral_asset_id = [0x01; 32]; // wBTC
        let collateral_amount = 100;
        let zusd_amount = 100;
        let price = 1; // 1:1 price ratio for simplicity

        let input_utxo = UTXOTarget::new_test(
            owner_pk_x,
            owner_pk_y,
            collateral_asset_id,
            collateral_amount,
        );

        // Create collateral metadata with insufficient ratio
        let collateral_metadata = CollateralMetadataTarget {
            issuance_id: 1,
            lock_timestamp: 12345,
            timelock_period: 86400, // 1 day in seconds
            lock_price: price,
            collateral_ratio: 100, // Below minimum ratio
        };

        // Signature values
        let signature_r_x = 0xaabbccddeeff0011;
        let signature_r_y = 0x2233445566778899;
        let signature_s = 0x9988776655443322;

        // Price oracle signature
        let price_sig_r_x = 0x1122334455667788;
        let price_sig_r_y = 0x99aabbccddeeff00;
        let price_sig_s = 0x8877665544332211;

        // Generate proof (should fail)
        let result = StablecoinMintCircuit::generate_proof_static(
            &input_utxo,
            zusd_amount,
            price,
            mpc_pk_x,
            mpc_pk_y,
            &collateral_metadata,
            owner_pk_x,
            owner_pk_y,
            signature_r_x,
            signature_r_y,
            signature_s,
            price_sig_r_x,
            price_sig_r_y,
            price_sig_s,
        );

        // Create test vector
        let test_vector = json!({
            "description": "Invalid stablecoin mint with insufficient collateralization (100%)",
            "input": {
                "input_utxo": {
                    "owner_pk_x": format!("0x{:x}", owner_pk_x),
                    "owner_pk_y": format!("0x{:x}", owner_pk_y),
                    "asset_id": format!("0x{}", hex::encode(collateral_asset_id)),
                    "amount": collateral_amount,
                },
                "zusd_amount": zusd_amount,
                "price": price,
                "mpc_pk_x": format!("0x{:x}", mpc_pk_x),
                "mpc_pk_y": format!("0x{:x}", mpc_pk_y),
                "collateral_metadata": {
                    "issuance_id": collateral_metadata.issuance_id,
                    "lock_timestamp": collateral_metadata.lock_timestamp,
                    "timelock_period": collateral_metadata.timelock_period,
                    "lock_price": collateral_metadata.lock_price,
                    "collateral_ratio": collateral_metadata.collateral_ratio,
                },
                "user_signature": {
                    "r_x": format!("0x{:x}", signature_r_x),
                    "r_y": format!("0x{:x}", signature_r_y),
                    "s": format!("0x{:x}", signature_s),
                },
                "price_signature": {
                    "r_x": format!("0x{:x}", price_sig_r_x),
                    "r_y": format!("0x{:x}", price_sig_r_y),
                    "s": format!("0x{:x}", price_sig_s),
                },
            },
            "output": {
                "error": format!("{:?}", result.err()),
                "verification_result": "invalid",
            },
        });

        test_vectors.push(test_vector);
    }

    // Write test vectors to file
    let file_path = output_path.join("stablecoin_mint_test_vectors.json");
    let mut file =
        File::create(file_path).expect("Failed to create stablecoin_mint test vectors file");
    let json_string = serde_json::to_string_pretty(&test_vectors)
        .expect("Failed to serialize stablecoin_mint test vectors");
    file.write_all(json_string.as_bytes())
        .expect("Failed to write stablecoin_mint test vectors");
}
