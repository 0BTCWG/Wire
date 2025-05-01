use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use std::sync::Arc;

use wire::circuits::native_asset_create::NativeAssetCreateCircuit;
use wire::circuits::native_asset_mint::NativeAssetMintCircuit;
use wire::circuits::native_asset_burn::NativeAssetBurnCircuit;
use wire::circuits::transfer::TransferCircuit;
use wire::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire::utils::signature::{generate_keypair, sign_message, Signature};
use wire::utils::hash::{compute_message_hash, compute_asset_id};
use wire::utils::nullifier::{calculate_nullifier};
use wire::utils::utxo::{UTXO, UTXOContent};
use wire::utils::fee::{FeeQuote, FEE_AMOUNT};
use wire::utils::proof::{generate_proof, verify_proof, aggregate_proofs};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Fuzzes the signature verification with random messages and keys
#[test]
fn fuzz_signature_verification() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..100 {
        // Generate random keypair
        let (sk, pk) = generate_keypair();
        
        // Generate random message of random length (1-1000 bytes)
        let message_length = rng.gen_range(1..1000);
        let mut message = vec![0u8; message_length];
        rng.fill(&mut message[..]);
        
        // Compute message hash and sign
        let message_hash = compute_message_hash(&message);
        let signature = sign_message(&sk, &message_hash);
        
        // Verify signature (should pass)
        let is_valid = wire::utils::signature::verify_signature(&pk, &message_hash, &signature);
        assert!(is_valid, "Valid signature verification failed");
        
        // Tamper with message (should fail)
        if !message.is_empty() {
            let idx = rng.gen_range(0..message.len());
            message[idx] = message[idx].wrapping_add(1);
            let tampered_hash = compute_message_hash(&message);
            let is_invalid = wire::utils::signature::verify_signature(&pk, &tampered_hash, &signature);
            assert!(!is_invalid, "Invalid signature verification passed");
        }
    }
    
    println!("Signature verification fuzz testing passed");
}

/// Fuzzes the nullifier generation with random UTXOs and keys
#[test]
fn fuzz_nullifier_generation() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    let mut nullifiers = Vec::new();
    
    for _ in 0..100 {
        // Generate random keypair
        let (sk, pk) = generate_keypair();
        
        // Generate random UTXO
        let mut asset_id = [0u8; 32];
        rng.fill(&mut asset_id);
        
        let amount = rng.gen::<u64>();
        
        let mut blinding_factor = [0u8; 32];
        rng.fill(&mut blinding_factor);
        
        let utxo = UTXO {
            asset_id,
            amount,
            owner_pubkey: pk,
            blinding_factor,
        };
        
        // Calculate nullifier
        let nullifier = calculate_nullifier(&utxo, &sk);
        
        // Ensure nullifier is unique
        assert!(!nullifiers.contains(&nullifier), "Nullifier collision detected");
        nullifiers.push(nullifier);
        
        // Ensure nullifier changes with any UTXO field change
        let mut modified_utxo = utxo.clone();
        modified_utxo.amount = amount.wrapping_add(1);
        let modified_nullifier = calculate_nullifier(&modified_utxo, &sk);
        assert_ne!(nullifier, modified_nullifier, "Nullifier did not change with amount change");
    }
    
    println!("Nullifier generation fuzz testing passed");
}

/// Fuzzes the fee enforcement with random fee quotes and amounts
#[test]
fn fuzz_fee_enforcement() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..100 {
        // Generate random keypairs
        let (user_sk, user_pk) = generate_keypair();
        let (fee_collector_sk, fee_collector_pk) = generate_keypair();
        
        // Generate random fee amount
        let fee_amount = rng.gen_range(1..1000000);
        
        // Generate random expiry timestamp
        let expiry_timestamp = rng.gen::<u64>();
        
        // Create fee quote
        let fee_quote = FeeQuote {
            fee_amount,
            fee_recipient_pk: fee_collector_pk,
            expiry_timestamp,
        };
        
        // Create fee message and signature
        let fee_message = format!("Fee payment of {}", fee_amount);
        let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
        let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
        
        // Create initial UTXO with sufficient funds
        let initial_amount = fee_amount + rng.gen_range(1..1000000);
        let mut asset_id = [0u8; 32];
        rng.fill(&mut asset_id);
        
        let initial_utxo = UTXO {
            asset_id,
            amount: initial_amount,
            owner_pubkey: user_pk,
            blinding_factor: [1; 32],
        };
        
        // Create transfer UTXOs
        let recipient_utxo = UTXO {
            asset_id,
            amount: initial_amount - fee_amount,
            owner_pubkey: user_pk, // Transfer to self
            blinding_factor: [2; 32],
        };
        
        let fee_utxo = UTXO {
            asset_id,
            amount: fee_amount,
            owner_pubkey: fee_collector_pk,
            blinding_factor: [3; 32],
        };
        
        // Create transfer circuit with fee payment
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk,
            sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
            input_utxo: initial_utxo,
            output_utxos: vec![recipient_utxo.clone(), fee_utxo.clone()],
            fee_quote: Some(fee_quote),
            fee_signature: Some(fee_signature),
        };
        
        // Generate and verify transfer proof
        let transfer_proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit))
            .expect("Failed to generate transfer proof");
        let transfer_verified = verify_proof::<F, C, D>(&transfer_proof)
            .expect("Failed to verify transfer proof");
        assert!(transfer_verified, "Transfer proof verification failed");
    }
    
    println!("Fee enforcement fuzz testing passed");
}

/// Fuzzes the asset ID generation with random asset parameters
#[test]
fn fuzz_asset_id_generation() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    let mut asset_ids = Vec::new();
    
    for _ in 0..100 {
        // Generate random asset parameters
        let name_length = rng.gen_range(1..100);
        let mut name = vec![0u8; name_length];
        rng.fill(&mut name[..]);
        
        let symbol_length = rng.gen_range(1..10);
        let mut symbol = vec![0u8; symbol_length];
        rng.fill(&mut symbol[..]);
        
        let decimals = rng.gen_range(0..18);
        
        // Compute asset ID
        let asset_id = compute_asset_id(&name, &symbol, decimals);
        
        // Ensure asset ID is unique
        assert!(!asset_ids.contains(&asset_id), "Asset ID collision detected");
        asset_ids.push(asset_id);
        
        // Ensure asset ID changes with any parameter change
        let mut modified_name = name.clone();
        if !modified_name.is_empty() {
            let idx = rng.gen_range(0..modified_name.len());
            modified_name[idx] = modified_name[idx].wrapping_add(1);
        }
        
        let modified_asset_id = compute_asset_id(&modified_name, &symbol, decimals);
        assert_ne!(asset_id, modified_asset_id, "Asset ID did not change with name change");
    }
    
    println!("Asset ID generation fuzz testing passed");
}

/// Fuzzes the proof aggregation with random proof combinations
#[test]
fn fuzz_proof_aggregation() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Generate a set of valid proofs
    let mut proofs = Vec::new();
    
    for _ in 0..5 {
        // Generate random keypair
        let (user_sk, user_pk) = generate_keypair();
        
        // Create a simple transfer circuit
        let initial_amount = rng.gen_range(1000..1000000);
        
        let initial_utxo = UTXO {
            asset_id: [0; 32],
            amount: initial_amount,
            owner_pubkey: user_pk,
            blinding_factor: [1; 32],
        };
        
        let recipient_utxo = UTXO {
            asset_id: [0; 32],
            amount: initial_amount,
            owner_pubkey: user_pk, // Transfer to self
            blinding_factor: [2; 32],
        };
        
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk,
            sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
            input_utxo: initial_utxo,
            output_utxos: vec![recipient_utxo],
            fee_quote: None,
            fee_signature: None,
        };
        
        // Generate proof
        let proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit))
            .expect("Failed to generate transfer proof");
        proofs.push(proof);
    }
    
    // Test aggregation with different combinations
    for _ in 0..10 {
        // Select a random number of proofs to aggregate
        let num_proofs = rng.gen_range(2..=proofs.len());
        let indices: Vec<usize> = (0..proofs.len()).collect();
        let selected_indices: Vec<usize> = indices
            .choose_multiple(&mut rng, num_proofs)
            .cloned()
            .collect();
        
        let selected_proofs: Vec<_> = selected_indices
            .iter()
            .map(|&i| proofs[i].clone())
            .collect();
        
        // Aggregate proofs
        let aggregated_proof = aggregate_proofs::<F, C, D>(&selected_proofs)
            .expect("Failed to aggregate proofs");
        
        // Verify aggregated proof
        let aggregated_verified = verify_proof::<F, C, D>(&aggregated_proof)
            .expect("Failed to verify aggregated proof");
        assert!(aggregated_verified, "Aggregated proof verification failed");
    }
    
    println!("Proof aggregation fuzz testing passed");
}

/// Fuzzes edge cases in circuit inputs
#[test]
fn fuzz_circuit_edge_cases() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Test edge cases for amounts
    let edge_amounts = vec![
        0,                  // Zero
        1,                  // Minimum
        u64::MAX,           // Maximum
        u64::MAX - 1,       // Near maximum
        u64::MAX / 2,       // Half maximum
        FEE_AMOUNT,         // Exact fee amount
        FEE_AMOUNT + 1,     // Just above fee amount
        FEE_AMOUNT - 1,     // Just below fee amount (should fail for fee payment)
    ];
    
    for amount in edge_amounts {
        if amount < FEE_AMOUNT {
            // Skip amounts less than fee amount for transfer tests
            continue;
        }
        
        // Generate keypairs
        let (user_sk, user_pk) = generate_keypair();
        let (recipient_sk, recipient_pk) = generate_keypair();
        let (fee_collector_sk, fee_collector_pk) = generate_keypair();
        
        // Create fee quote
        let fee_quote = FeeQuote {
            fee_amount: FEE_AMOUNT,
            fee_recipient_pk: fee_collector_pk,
            expiry_timestamp: 0xFFFFFFFF,
        };
        let fee_message = format!("Fee payment of {}", FEE_AMOUNT);
        let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
        let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
        
        // Create initial UTXO
        let initial_utxo = UTXO {
            asset_id: [0; 32],
            amount,
            owner_pubkey: user_pk,
            blinding_factor: [1; 32],
        };
        
        // Create transfer UTXOs
        let recipient_utxo = UTXO {
            asset_id: [0; 32],
            amount: amount - FEE_AMOUNT,
            owner_pubkey: recipient_pk,
            blinding_factor: [2; 32],
        };
        
        let fee_utxo = UTXO {
            asset_id: [0; 32],
            amount: FEE_AMOUNT,
            owner_pubkey: fee_collector_pk,
            blinding_factor: [3; 32],
        };
        
        // Create transfer circuit
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk,
            sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
            input_utxo: initial_utxo,
            output_utxos: vec![recipient_utxo, fee_utxo],
            fee_quote: Some(fee_quote),
            fee_signature: Some(fee_signature),
        };
        
        // Generate and verify transfer proof
        let transfer_proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit))
            .expect("Failed to generate transfer proof");
        let transfer_verified = verify_proof::<F, C, D>(&transfer_proof)
            .expect("Failed to verify transfer proof");
        assert!(transfer_verified, "Transfer proof verification failed for amount {}", amount);
    }
    
    println!("Circuit edge case fuzz testing passed");
}

/// Fuzzes invalid inputs to ensure proper error handling
#[test]
fn fuzz_invalid_inputs() {
    let seed = 42; // Deterministic seed for reproducibility
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Generate keypairs
    let (user_sk, user_pk) = generate_keypair();
    let (recipient_sk, recipient_pk) = generate_keypair();
    let (fee_collector_sk, fee_collector_pk) = generate_keypair();
    
    // Create valid UTXO
    let valid_amount = 1000000;
    let valid_utxo = UTXO {
        asset_id: [0; 32],
        amount: valid_amount,
        owner_pubkey: user_pk,
        blinding_factor: [1; 32],
    };
    
    // Test 1: Invalid signature (wrong signer)
    {
        let wrong_signature = sign_message(&recipient_sk, &compute_message_hash(&b"transfer".to_vec()));
        
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk, // Correct public key
            sender_sig: wrong_signature, // Wrong signature
            input_utxo: valid_utxo.clone(),
            output_utxos: vec![UTXO {
                asset_id: [0; 32],
                amount: valid_amount,
                owner_pubkey: recipient_pk,
                blinding_factor: [2; 32],
            }],
            fee_quote: None,
            fee_signature: None,
        };
        
        // This should fail to generate a valid proof
        let result = generate_proof::<F, C, D>(Arc::new(transfer_circuit));
        assert!(result.is_err() || !verify_proof::<F, C, D>(&result.unwrap()).unwrap_or(false),
                "Invalid signature was accepted");
    }
    
    // Test 2: Invalid conservation of value (output > input)
    {
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk,
            sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
            input_utxo: valid_utxo.clone(),
            output_utxos: vec![UTXO {
                asset_id: [0; 32],
                amount: valid_amount + 1, // More than input
                owner_pubkey: recipient_pk,
                blinding_factor: [2; 32],
            }],
            fee_quote: None,
            fee_signature: None,
        };
        
        // This should fail to generate a valid proof
        let result = generate_proof::<F, C, D>(Arc::new(transfer_circuit));
        assert!(result.is_err() || !verify_proof::<F, C, D>(&result.unwrap()).unwrap_or(false),
                "Invalid conservation of value was accepted");
    }
    
    // Test 3: Invalid fee quote (expired)
    {
        let expired_fee_quote = FeeQuote {
            fee_amount: FEE_AMOUNT,
            fee_recipient_pk: fee_collector_pk,
            expiry_timestamp: 0, // Expired timestamp
        };
        let fee_message = format!("Fee payment of {}", FEE_AMOUNT);
        let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
        let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
        
        let transfer_circuit = TransferCircuit {
            sender_pk: user_pk,
            sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
            input_utxo: valid_utxo.clone(),
            output_utxos: vec![
                UTXO {
                    asset_id: [0; 32],
                    amount: valid_amount - FEE_AMOUNT,
                    owner_pubkey: recipient_pk,
                    blinding_factor: [2; 32],
                },
                UTXO {
                    asset_id: [0; 32],
                    amount: FEE_AMOUNT,
                    owner_pubkey: fee_collector_pk,
                    blinding_factor: [3; 32],
                },
            ],
            fee_quote: Some(expired_fee_quote),
            fee_signature: Some(fee_signature),
        };
        
        // This should fail to generate a valid proof
        let result = generate_proof::<F, C, D>(Arc::new(transfer_circuit));
        assert!(result.is_err() || !verify_proof::<F, C, D>(&result.unwrap()).unwrap_or(false),
                "Expired fee quote was accepted");
    }
    
    println!("Invalid input fuzz testing passed");
}
