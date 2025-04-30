use clap::{App, Arg};
use serde_json::{json, Value};
use std::fs::{self, File};
use std::io::Write;
use std::path::Path;

use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::utils::recursive_prover::{aggregate_proofs, verify_aggregated_proof};

fn main() {
    let matches = App::new("0BTC Wire Audit Test Vector Generator")
        .version("1.0")
        .author("0BTC Wire Team")
        .about("Generates test vectors for the 0BTC Wire audit")
        .arg(
            Arg::with_name("output-dir")
                .long("output-dir")
                .value_name("DIR")
                .help("Directory to output test vectors")
                .required(true)
                .takes_value(true),
        )
        .get_matches();

    let output_dir = matches.value_of("output-dir").unwrap();
    let output_path = Path::new(output_dir);

    // Create output directory if it doesn't exist
    if !output_path.exists() {
        fs::create_dir_all(output_path).expect("Failed to create output directory");
    }

    // Generate test vectors
    generate_wrapped_mint_test_vectors(output_path);
    generate_wrapped_burn_test_vectors(output_path);
    generate_transfer_test_vectors(output_path);
    generate_recursive_aggregation_test_vectors(output_path);

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
    let signature_s = 0x99887766554433221100;

    // Generate proof
    let result = WrappedAssetMintCircuit::generate_proof_static(
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
        let json_str = serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes()).expect("Failed to write test vectors");

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
    let signature_s = 0x99887766554433221100;
    let destination_btc_address = vec![0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac];

    // Generate proof
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
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
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
        let json_str = serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes()).expect("Failed to write test vectors");

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
    let sender_pk_x = 0xfedcba0987654321;
    let sender_pk_y = 0x1122334455667788;
    let signature_r_x = 0xaabbccddeeff0011;
    let signature_r_y = 0x2233445566778899;
    let signature_s = 0x99887766554433221100;
    let recipient_pk_hash = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    let output_amount = amount / 2; // Split the amount
    let fee_amount = 1000; // 1000 satoshis fee
    let fee_reservoir_address_hash = vec![0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];
    let nonce = 123;

    // Create input UTXOs
    let input_utxos_data = vec![(owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone())];

    // Create recipient data
    let recipient_pk_hashes = vec![recipient_pk_hash];
    let output_amounts = vec![output_amount];

    // Create fee UTXO data (using the same UTXO for simplicity)
    let fee_input_utxo_data = (owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone());

    // Generate proof
    let result = TransferCircuit::generate_proof_static(
        input_utxos_data.clone(),
        recipient_pk_hashes.clone(),
        output_amounts.clone(),
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
        fee_input_utxo_data.clone(),
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
        let json_str = serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
        file.write_all(json_str.as_bytes()).expect("Failed to write test vectors");

        println!("Transfer test vectors written to {:?}", file_path);
    } else {
        println!("Failed to generate transfer proof: {:?}", result.err());
    }
}

fn generate_recursive_aggregation_test_vectors(output_path: &Path) {
    println!("Generating recursive aggregation test vectors...");

    let mut test_vectors = Vec::new();

    // Generate a wrapped mint proof
    let recipient_pk_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let amount = 1_000_000; // 0.01 BTC in satoshis
    let deposit_nonce = 42;
    let custodian_pk_x = 0xfedcba0987654321;
    let custodian_pk_y = 0x1122334455667788;
    let signature_r_x = 0xaabbccddeeff0011;
    let signature_r_y = 0x2233445566778899;
    let signature_s = 0x99887766554433221100;

    let mint_result = WrappedAssetMintCircuit::generate_proof_static(
        &recipient_pk_hash,
        amount,
        deposit_nonce,
        custodian_pk_x,
        custodian_pk_y,
        signature_r_x,
        signature_r_y,
        signature_s,
    );

    // Generate a wrapped burn proof
    let owner_pubkey_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    let asset_id = vec![0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
    let burn_amount = 500_000; // 0.005 BTC in satoshis
    let salt = vec![0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88];
    let sender_sk = 0x1234567890abcdef;
    let sender_pk_x = 0xfedcba0987654321;
    let sender_pk_y = 0x1122334455667788;
    let burn_signature_r_x = 0xaabbccddeeff0011;
    let burn_signature_r_y = 0x2233445566778899;
    let burn_signature_s = 0x99887766554433221100;
    let destination_btc_address = vec![0x76, 0xa9, 0x14, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x88, 0xac];

    let burn_result = WrappedAssetBurnCircuit::generate_proof_static(
        &owner_pubkey_hash,
        &asset_id,
        burn_amount,
        &salt,
        sender_sk,
        sender_pk_x,
        sender_pk_y,
        burn_signature_r_x,
        burn_signature_r_y,
        burn_signature_s,
        &destination_btc_address,
        None, // No fee
        None, // No expiry
        None, // No fee signature r_x
        None, // No fee signature r_y
        None, // No fee signature s
        None, // No custodian pk_x
        None, // No custodian pk_y
    );

    if let (Ok(mint_proof), Ok(burn_proof)) = (mint_result, burn_result) {
        // Aggregate the proofs
        let proofs = vec![mint_proof.clone(), burn_proof.clone()];
        let aggregation_result = aggregate_proofs(&proofs, "wrapped-mint", 2);

        if let Ok(aggregated_proof) = aggregation_result {
            // Verify the aggregated proof
            let verification_result = verify_aggregated_proof(&aggregated_proof, "wrapped-mint");

            // Create test vector
            let test_vector = json!({
                "name": "valid_recursive_aggregation",
                "description": "Valid recursive aggregation of wrapped mint and burn proofs",
                "inputs": {
                    "proofs": [
                        {
                            "type": "wrapped-mint",
                            "proof": mint_proof
                        },
                        {
                            "type": "wrapped-burn",
                            "proof": burn_proof
                        }
                    ],
                    "circuit_type": "wrapped-mint",
                    "batch_size": 2
                },
                "expected_result": {
                    "valid": true
                },
                "aggregated_proof": aggregated_proof,
                "verification_result": verification_result.is_ok()
            });

            test_vectors.push(test_vector);

            // Write test vectors to file
            let file_path = output_path.join("recursive_aggregation_test_vectors.json");
            let mut file = File::create(&file_path).expect("Failed to create file");
            let json_str = serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
            file.write_all(json_str.as_bytes()).expect("Failed to write test vectors");

            println!("Recursive aggregation test vectors written to {:?}", file_path);
        } else {
            println!("Failed to aggregate proofs: {:?}", aggregation_result.err());
        }
    } else {
        println!("Failed to generate proofs for aggregation");
    }
}
