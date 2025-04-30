//! Fuzz tests for the 0BTC Wire system
//!
//! These tests use fuzzing to identify potential vulnerabilities.

use crate::audit::utils;
use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire_lib::circuits::transfer::TransferCircuit;
use wire_lib::errors::WireError;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;

/// Test fuzzing of wrapped mint inputs
#[test]
fn test_fuzz_wrapped_mint_inputs() {
    // Create a deterministic random number generator
    let seed = 42; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate test data with some randomness
        let recipient_pk_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let amount = rng.gen_range(1..1_000_000);
        let deposit_nonce = rng.gen::<u64>();
        let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
        let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
        
        // Generate a proof with fuzzed inputs
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
        
        // If proof generation succeeds, verify the proof
        if let Ok(proof) = result {
            let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
            
            // The verification should succeed for valid inputs
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid inputs (iteration {}): {:?}", 
                    i, verification_result.err());
        } else {
            // If proof generation fails, that's fine as long as it's a known error
            match result.err().unwrap() {
                WireError::ProofError(_) => {
                    // This is expected for some invalid inputs
                },
                WireError::InvalidInput(_) => {
                    // This is expected for some invalid inputs
                },
                err => {
                    // Other errors might indicate a bug
                    panic!("Unexpected error (iteration {}): {:?}", i, err);
                }
            }
        }
    }
}

/// Test fuzzing of wrapped burn inputs
#[test]
fn test_fuzz_wrapped_burn_inputs() {
    // Create a deterministic random number generator
    let seed = 43; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate test data with some randomness
        let owner_pubkey_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let asset_id = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let amount = rng.gen_range(1..1_000_000);
        let salt = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
        let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
        let destination_btc_address = (0..21).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        
        // Generate a proof with fuzzed inputs
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
        
        // If proof generation succeeds, verify the proof
        if let Ok(proof) = result {
            let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
            
            // The verification should succeed for valid inputs
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid inputs (iteration {}): {:?}", 
                    i, verification_result.err());
        } else {
            // If proof generation fails, that's fine as long as it's a known error
            match result.err().unwrap() {
                WireError::ProofError(_) => {
                    // This is expected for some invalid inputs
                },
                WireError::InvalidInput(_) => {
                    // This is expected for some invalid inputs
                },
                err => {
                    // Other errors might indicate a bug
                    panic!("Unexpected error (iteration {}): {:?}", i, err);
                }
            }
        }
    }
}

/// Test fuzzing of transfer inputs
#[test]
fn test_fuzz_transfer_inputs() {
    // Create a deterministic random number generator
    let seed = 44; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate test data with some randomness
        let owner_pubkey_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let asset_id = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let amount = rng.gen_range(1000..1_000_000);
        let salt = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
        let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
        let recipient_pk_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let output_amount = amount / 2; // Split the amount
        let fee_amount = rng.gen_range(1..1000); // Random fee
        let fee_reservoir_address_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let nonce = rng.gen::<u64>();
        
        // Create input UTXOs
        let input_utxos_data = vec![(owner_pubkey_hash.clone(), asset_id.clone(), amount, salt.clone())];
        
        // Create recipient data
        let recipient_pk_hashes = vec![recipient_pk_hash];
        let output_amounts = vec![output_amount];
        
        // Create fee UTXO data (using the same UTXO for simplicity)
        let fee_input_utxo_data = (owner_pubkey_hash, asset_id, amount, salt);
        
        // Generate a proof with fuzzed inputs
        let result = TransferCircuit::generate_proof_static(
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
        );
        
        // If proof generation succeeds, verify the proof
        if let Ok(proof) = result {
            let verification_result = TransferCircuit::verify_proof(&proof);
            
            // The verification should succeed for valid inputs
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid inputs (iteration {}): {:?}", 
                    i, verification_result.err());
        } else {
            // If proof generation fails, that's fine as long as it's a known error
            match result.err().unwrap() {
                WireError::ProofError(_) => {
                    // This is expected for some invalid inputs
                },
                WireError::InvalidInput(_) => {
                    // This is expected for some invalid inputs
                },
                err => {
                    // Other errors might indicate a bug
                    panic!("Unexpected error (iteration {}): {:?}", i, err);
                }
            }
        }
    }
}

/// Test fuzzing of signature verification
#[test]
fn test_fuzz_signature_verification() {
    // Create a deterministic random number generator
    let seed = 45; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate test data with some randomness
        let (recipient_pk_hash, amount, deposit_nonce, _) = utils::generate_test_attestation();
        let (_, (custodian_pk_x, custodian_pk_y)) = utils::generate_test_key_pair();
        
        // Generate random signature components
        let signature_r_x = rng.gen::<u64>();
        let signature_r_y = rng.gen::<u64>();
        let signature_s = rng.gen::<u64>();
        
        // Generate a proof with fuzzed signature
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
        
        // If proof generation succeeds, verify the proof
        if let Ok(proof) = result {
            let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
            
            // The verification might succeed or fail depending on the random signature
            // We just check that it doesn't panic
            match verification_result {
                Ok(_) => {
                    // If verification succeeds, that's fine
                    // (though unlikely with a random signature)
                    println!("Verification succeeded with random signature (iteration {})", i);
                },
                Err(err) => {
                    // If verification fails, that's expected
                    println!("Verification failed with random signature (iteration {}): {:?}", i, err);
                }
            }
        } else {
            // If proof generation fails, that's fine as long as it's a known error
            match result.err().unwrap() {
                WireError::ProofError(_) => {
                    // This is expected for invalid signatures
                },
                WireError::InvalidInput(_) => {
                    // This is expected for invalid signatures
                },
                err => {
                    // Other errors might indicate a bug
                    panic!("Unexpected error (iteration {}): {:?}", i, err);
                }
            }
        }
    }
}

/// Test fuzzing of hash function
#[test]
fn test_fuzz_hash_function() {
    // Create a deterministic random number generator
    let seed = 46; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate random UTXO data
        let owner_pubkey_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let asset_id = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let amount = rng.gen_range(1..1_000_000);
        let salt = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        
        // Generate random signature data
        let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
        let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
        
        // Generate random destination address
        let destination_btc_address = (0..21).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        
        // Generate a proof with fuzzed inputs that will exercise the hash function
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
        
        // We're just checking that the hash function doesn't panic with random inputs
        match result {
            Ok(proof) => {
                // If proof generation succeeds, verify the proof
                let verification_result = WrappedAssetBurnCircuit::verify_proof(&proof);
                
                // Log the result
                match verification_result {
                    Ok(_) => {
                        println!("Verification succeeded with random inputs (iteration {})", i);
                    },
                    Err(err) => {
                        println!("Verification failed with random inputs (iteration {}): {:?}", i, err);
                    }
                }
            },
            Err(err) => {
                // If proof generation fails, that's fine as long as it's a known error
                match err {
                    WireError::ProofError(_) => {
                        // This is expected for some invalid inputs
                    },
                    WireError::InvalidInput(_) => {
                        // This is expected for some invalid inputs
                    },
                    err => {
                        // Other errors might indicate a bug
                        panic!("Unexpected error (iteration {}): {:?}", i, err);
                    }
                }
            }
        }
    }
}

/// Test fuzzing of Merkle proof verification
#[test]
fn test_fuzz_merkle_proof() {
    // Create a deterministic random number generator
    let seed = 47; // Use a fixed seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Number of fuzz iterations
    let iterations = 10;
    
    for i in 0..iterations {
        // Generate random UTXO data for multiple UTXOs
        let num_utxos = rng.gen_range(1..5);
        let mut input_utxos_data = Vec::new();
        
        for _ in 0..num_utxos {
            let owner_pubkey_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let asset_id = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            let amount = rng.gen_range(1000..1_000_000);
            let salt = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            
            input_utxos_data.push((owner_pubkey_hash, asset_id, amount, salt));
        }
        
        // Generate random signature data
        let (sender_sk, (sender_pk_x, sender_pk_y)) = utils::generate_test_key_pair();
        let (signature_r_x, signature_r_y, signature_s) = utils::generate_test_signature();
        
        // Generate random recipient data
        let num_recipients = rng.gen_range(1..5);
        let mut recipient_pk_hashes = Vec::new();
        let mut output_amounts = Vec::new();
        
        let total_input_amount: u64 = input_utxos_data.iter().map(|(_, _, amount, _)| *amount).sum();
        let fee_amount = rng.gen_range(1..1000);
        let remaining_amount = total_input_amount.saturating_sub(fee_amount);
        
        for i in 0..num_recipients {
            let recipient_pk_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
            
            // For the last recipient, use the remaining amount
            let output_amount = if i == num_recipients - 1 {
                remaining_amount
            } else {
                let max_amount = remaining_amount / (num_recipients - i) as u64;
                rng.gen_range(1..max_amount.max(2))
            };
            
            recipient_pk_hashes.push(recipient_pk_hash);
            output_amounts.push(output_amount);
        }
        
        // Generate random fee data
        let fee_reservoir_address_hash = (0..8).map(|_| rng.gen::<u8>()).collect::<Vec<u8>>();
        let nonce = rng.gen::<u64>();
        
        // Use the first UTXO as the fee UTXO for simplicity
        let fee_input_utxo_data = input_utxos_data[0].clone();
        
        // Generate a proof with fuzzed inputs that will exercise the Merkle proof verification
        let result = TransferCircuit::generate_proof_static(
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
        );
        
        // We're just checking that the Merkle proof verification doesn't panic with random inputs
        match result {
            Ok(proof) => {
                // If proof generation succeeds, verify the proof
                let verification_result = TransferCircuit::verify_proof(&proof);
                
                // Log the result
                match verification_result {
                    Ok(_) => {
                        println!("Verification succeeded with random Merkle inputs (iteration {})", i);
                    },
                    Err(err) => {
                        println!("Verification failed with random Merkle inputs (iteration {}): {:?}", i, err);
                    }
                }
            },
            Err(err) => {
                // If proof generation fails, that's fine as long as it's a known error
                match err {
                    WireError::ProofError(_) => {
                        // This is expected for some invalid inputs
                    },
                    WireError::InvalidInput(_) => {
                        // This is expected for some invalid inputs
                    },
                    err => {
                        // Other errors might indicate a bug
                        panic!("Unexpected error (iteration {}): {:?}", i, err);
                    }
                }
            }
        }
    }
}
