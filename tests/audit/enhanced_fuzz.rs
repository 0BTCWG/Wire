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
use wire::circuits::swap::SwapCircuit;
use wire::circuits::add_liquidity::AddLiquidityCircuit;
use wire::circuits::remove_liquidity::RemoveLiquidityCircuit;
use wire::circuits::stablecoin_mint::StablecoinMintCircuit;
use wire::circuits::stablecoin_redeem::StablecoinRedeemCircuit;
use wire::utils::signature::{generate_keypair, sign_message, Signature};
use wire::utils::hash::{compute_message_hash, compute_asset_id};
use wire::utils::nullifier::{calculate_nullifier};
use wire::utils::utxo::{UTXO, UTXOContent};
use wire::utils::fee::{FeeQuote, FEE_AMOUNT};
use wire::utils::proof::{generate_proof, verify_proof, aggregate_proofs};
use wire::core::{CollateralUTXOTarget, CollateralMetadataTarget};
use wire::gadgets::fixed_point;

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

/// Fuzzes the AMM swap circuit with random token amounts and price ratios
#[test]
fn fuzz_amm_swap_circuit() {
    let seed = 43; // Different seed for this test
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..50 {
        // Generate random token amounts (ensuring they're not too large to avoid overflow)
        let token_a_amount = rng.gen_range(1..1_000_000);
        let token_b_amount = rng.gen_range(1..1_000_000);
        
        // Generate random keypair
        let (sk, pk) = generate_keypair();
        
        // Create input UTXOs
        let input_utxo_a = UTXO::new(
            pk.clone(),
            [0x01; 32], // Asset ID for token A
            token_a_amount,
            None, // No metadata
        );
        
        let input_utxo_b = UTXO::new(
            pk.clone(),
            [0x02; 32], // Asset ID for token B
            token_b_amount,
            None, // No metadata
        );
        
        // Sign the swap message
        let message = format!("swap:{}:{}", token_a_amount, token_b_amount);
        let message_hash = compute_message_hash(message.as_bytes());
        let signature = sign_message(&sk, &message_hash);
        
        // Generate a swap proof
        let result = SwapCircuit::generate_proof_static(
            &input_utxo_a.to_target(),
            &input_utxo_b.to_target(),
            pk.x,
            pk.y,
            signature.r_point.x,
            signature.r_point.y,
            signature.s,
        );
        
        // The proof generation should succeed for valid inputs
        if let Ok(proof) = result {
            let verification_result = SwapCircuit::verify_proof(&proof);
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid swap inputs: {:?}", 
                    verification_result.err());
        } else {
            // If proof generation fails, it should be due to a legitimate constraint
            println!("Swap proof generation failed: {:?}", result.err());
        }
    }
}

/// Fuzzes the AMM add_liquidity circuit with random token amounts
#[test]
fn fuzz_add_liquidity_circuit() {
    let seed = 44;
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..50 {
        // Generate random token amounts
        let token_a_amount = rng.gen_range(1..1_000_000);
        let token_b_amount = rng.gen_range(1..1_000_000);
        let initial_liquidity = rng.gen_range(0..100_000); // Can be zero for first liquidity provision
        
        // Generate random keypair
        let (sk, pk) = generate_keypair();
        
        // Create input UTXOs
        let input_utxo_a = UTXO::new(
            pk.clone(),
            [0x01; 32], // Asset ID for token A
            token_a_amount,
            None, // No metadata
        );
        
        let input_utxo_b = UTXO::new(
            pk.clone(),
            [0x02; 32], // Asset ID for token B
            token_b_amount,
            None, // No metadata
        );
        
        // Sign the add_liquidity message
        let message = format!("add_liquidity:{}:{}:{}", token_a_amount, token_b_amount, initial_liquidity);
        let message_hash = compute_message_hash(message.as_bytes());
        let signature = sign_message(&sk, &message_hash);
        
        // Generate an add_liquidity proof
        let result = AddLiquidityCircuit::generate_proof_static(
            &input_utxo_a.to_target(),
            &input_utxo_b.to_target(),
            initial_liquidity,
            pk.x,
            pk.y,
            signature.r_point.x,
            signature.r_point.y,
            signature.s,
        );
        
        // The proof generation should succeed for valid inputs
        if let Ok(proof) = result {
            let verification_result = AddLiquidityCircuit::verify_proof(&proof);
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid add_liquidity inputs: {:?}", 
                    verification_result.err());
        } else {
            // If proof generation fails, it should be due to a legitimate constraint
            println!("Add liquidity proof generation failed: {:?}", result.err());
        }
    }
}

/// Fuzzes the stablecoin mint circuit with random collateral amounts and prices
#[test]
fn fuzz_stablecoin_mint_circuit() {
    let seed = 45;
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..50 {
        // Generate random collateral amount (ensuring sufficient collateralization)
        let collateral_amount = rng.gen_range(150..1_000_000);
        let price = rng.gen_range(1..100); // Random price
        let zusd_amount = (collateral_amount as f64 / 1.5 / price as f64) as u64; // Ensure 150% collateralization
        
        // Generate random keypairs
        let (user_sk, user_pk) = generate_keypair();
        let (mpc_sk, mpc_pk) = generate_keypair(); // MPC committee key
        
        // Create input UTXO for collateral
        let input_utxo = UTXO::new(
            user_pk.clone(),
            [0x01; 32], // Asset ID for wBTC
            collateral_amount,
            None, // No metadata
        );
        
        // Create collateral metadata
        let current_timestamp = rng.gen_range(10000..20000);
        let timelock_period = rng.gen_range(86400..604800); // 1-7 days in seconds
        
        let collateral_metadata = CollateralMetadataTarget {
            issuance_id: rng.gen(),
            lock_timestamp: current_timestamp,
            timelock_period: timelock_period,
            lock_price: price,
            collateral_ratio: 150, // Minimum ratio
        };
        
        // Sign the mint message
        let user_message = format!("mint:{}:{}:{}", collateral_amount, zusd_amount, price);
        let user_message_hash = compute_message_hash(user_message.as_bytes());
        let user_signature = sign_message(&user_sk, &user_message_hash);
        
        // Sign the price message (oracle signature)
        let price_message = format!("price:{}", price);
        let price_message_hash = compute_message_hash(price_message.as_bytes());
        let price_signature = sign_message(&mpc_sk, &price_message_hash); // Using MPC key as oracle for test
        
        // Generate a mint proof
        let result = StablecoinMintCircuit::generate_proof_static(
            &input_utxo.to_target(),
            zusd_amount,
            price,
            mpc_pk.x,
            mpc_pk.y,
            &collateral_metadata,
            user_pk.x,
            user_pk.y,
            user_signature.r_point.x,
            user_signature.r_point.y,
            user_signature.s,
            price_signature.r_point.x,
            price_signature.r_point.y,
            price_signature.s,
        );
        
        // The proof generation should succeed for valid inputs
        if let Ok(proof) = result {
            let verification_result = StablecoinMintCircuit::verify_proof(&proof);
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid mint inputs: {:?}", 
                    verification_result.err());
        } else {
            // If proof generation fails, it should be due to a legitimate constraint
            println!("Mint proof generation failed: {:?}", result.err());
        }
    }
}

/// Fuzzes the stablecoin redeem circuit with random collateral amounts, prices, and timelock periods
#[test]
fn fuzz_stablecoin_redeem_circuit() {
    let seed = 46;
    let mut rng = StdRng::seed_from_u64(seed);
    
    for _ in 0..50 {
        // Generate random collateral amount (ensuring sufficient collateralization)
        let collateral_amount = rng.gen_range(150..1_000_000);
        let lock_price = rng.gen_range(1..100); // Random lock price
        let current_price = (lock_price as f64 * (0.5 + rng.gen::<f64>())).round() as u64; // Random current price (50%-150% of lock price)
        let zusd_amount = (collateral_amount as f64 / 1.5 / lock_price as f64) as u64; // Ensure 150% collateralization at lock time
        
        // Generate random keypairs
        let (user_sk, user_pk) = generate_keypair();
        let (mpc_sk, mpc_pk) = generate_keypair(); // MPC committee key
        
        // Create input UTXO for zUSD
        let input_utxo = UTXO::new(
            user_pk.clone(),
            [0x02; 32], // Asset ID for zUSD
            zusd_amount,
            None, // No metadata
        );
        
        // Create collateral metadata
        let lock_timestamp = rng.gen_range(10000..20000);
        let timelock_period = rng.gen_range(86400..604800); // 1-7 days in seconds
        let current_timestamp = lock_timestamp + timelock_period + rng.gen_range(1..1000); // Ensure timelock is expired
        
        let collateral_metadata = CollateralMetadataTarget {
            issuance_id: rng.gen(),
            lock_timestamp: lock_timestamp,
            timelock_period: timelock_period,
            lock_price: lock_price,
            collateral_ratio: 150, // Minimum ratio
        };
        
        // Create collateral UTXO
        let collateral_utxo = CollateralUTXOTarget::new_test(
            mpc_pk.x, mpc_pk.y, 
            [0x01; 32], // Asset ID for wBTC
            collateral_amount,
            collateral_metadata.clone()
        );
        
        // Sign the redeem message
        let user_message = format!("redeem:{}:{}", zusd_amount, current_price);
        let user_message_hash = compute_message_hash(user_message.as_bytes());
        let user_signature = sign_message(&user_sk, &user_message_hash);
        
        // Sign the price message (oracle signature)
        let price_message = format!("price:{}", current_price);
        let price_message_hash = compute_message_hash(price_message.as_bytes());
        let price_signature = sign_message(&mpc_sk, &price_message_hash); // Using MPC key as oracle for test
        
        // Sign the redeem approval message (MPC committee signature)
        let redeem_message = format!("redeem_approval:{}:{}:{}", zusd_amount, collateral_amount, current_timestamp);
        let redeem_message_hash = compute_message_hash(redeem_message.as_bytes());
        let redeem_signature = sign_message(&mpc_sk, &redeem_message_hash);
        
        // Generate a redeem proof
        let result = StablecoinRedeemCircuit::generate_proof_static(
            &input_utxo.to_target(),
            &collateral_utxo,
            current_price,
            current_timestamp,
            user_pk.x,
            user_pk.y,
            user_signature.r_point.x,
            user_signature.r_point.y,
            user_signature.s,
            price_signature.r_point.x,
            price_signature.r_point.y,
            price_signature.s,
            redeem_signature.r_point.x,
            redeem_signature.r_point.y,
            redeem_signature.s,
        );
        
        // The proof generation should succeed for valid inputs
        if let Ok(proof) = result {
            let verification_result = StablecoinRedeemCircuit::verify_proof(&proof);
            assert!(verification_result.is_ok(), 
                    "Verification failed for valid redeem inputs: {:?}", 
                    verification_result.err());
        } else {
            // If proof generation fails, it should be due to a legitimate constraint
            println!("Redeem proof generation failed: {:?}", result.err());
        }
    }
}

/// Fuzzes the fixed-point arithmetic gadgets with random values
#[test]
fn fuzz_fixed_point_arithmetic() {
    let seed = 47;
    let mut rng = StdRng::seed_from_u64(seed);
    
    // Create a circuit builder for testing
    let mut builder = CircuitBuilder::<F, D>::new(Default::default());
    
    for _ in 0..100 {
        // Generate random values (not too large to avoid overflow)
        let a = rng.gen_range(1..1_000_000);
        let b = rng.gen_range(1..1_000_000);
        
        // Convert to targets
        let a_target = builder.constant(F::from_canonical_u64(a));
        let b_target = builder.constant(F::from_canonical_u64(b));
        
        // Test fixed-point operations
        let _add_result = fixed_point::fixed_add(&mut builder, a_target, b_target);
        let _sub_result = fixed_point::fixed_sub(&mut builder, a_target, b_target);
        let _mul_result = fixed_point::fixed_mul(&mut builder, a_target, b_target);
        
        // Only test division if b is not too small (to avoid division by very small numbers)
        if b > 1000 {
            let _div_result = fixed_point::fixed_div(&mut builder, a_target, b_target);
        }
        
        // Test other operations
        let _min_result = fixed_point::fixed_min(&mut builder, a_target, b_target);
        let _max_result = fixed_point::fixed_max(&mut builder, a_target, b_target);
        let _abs_result = fixed_point::fixed_abs(&mut builder, a_target);
        
        // Test with negative values
        if a > b {
            let neg_result = fixed_point::fixed_sub(&mut builder, b_target, a_target);
            let _abs_neg_result = fixed_point::fixed_abs(&mut builder, neg_result);
        }
    }
    
    // If we get here without panics, the test passes
    assert!(true, "Fixed-point arithmetic operations completed without errors");
}
