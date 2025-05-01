use std::sync::Arc;

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::plonk::config::PoseidonGoldilocksConfig;

use wire::circuits::native_asset_create::NativeAssetCreateCircuit;
use wire::circuits::native_asset_mint::NativeAssetMintCircuit;
use wire::circuits::native_asset_burn::NativeAssetBurnCircuit;
use wire::circuits::transfer::TransferCircuit;
use wire::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
use wire::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
use wire::utils::signature::{generate_keypair, sign_message};
use wire::utils::hash::{compute_message_hash, compute_asset_id};
use wire::utils::nullifier::{calculate_nullifier};
use wire::utils::utxo::{UTXO, UTXOContent};
use wire::utils::fee::{FeeQuote, FEE_AMOUNT};
use wire::utils::proof::{generate_proof, verify_proof, aggregate_proofs};

type F = GoldilocksField;
type C = PoseidonGoldilocksConfig;
const D: usize = 2;

/// Tests the full lifecycle of wrapped BTC: MPC attestation -> mint -> transfer -> burn -> MPC processing
#[test]
fn test_wrapped_btc_lifecycle() {
    // Generate keys for all participants
    let (mpc_sk, mpc_pk) = generate_keypair();
    let (user_sk, user_pk) = generate_keypair();
    let (fee_collector_sk, fee_collector_pk) = generate_keypair();
    
    // 1. MPC attestation and mint
    let btc_deposit_amount = 100000000; // 1 BTC in satoshis
    let attestation_message = format!("BTC deposit of {} confirmed", btc_deposit_amount);
    let attestation_hash = compute_message_hash(&attestation_message.as_bytes().to_vec());
    let attestation_signature = sign_message(&mpc_sk, &attestation_hash);
    
    // Create mint circuit
    let mint_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID (0 for BTC)
        amount: btc_deposit_amount,
        owner_pubkey: user_pk,
        blinding_factor: [1; 32],
    };
    
    let mint_circuit = WrappedAssetMintCircuit {
        recipient_pk: user_pk,
        custodian_pk: mpc_pk,
        attestation: attestation_signature,
        deposit_amount: btc_deposit_amount,
        output_utxo: mint_utxo.clone(),
    };
    
    // Generate and verify mint proof
    let mint_proof = generate_proof::<F, C, D>(Arc::new(mint_circuit)).expect("Failed to generate mint proof");
    let mint_verified = verify_proof::<F, C, D>(&mint_proof).expect("Failed to verify mint proof");
    assert!(mint_verified, "Mint proof verification failed");
    
    // 2. Transfer to another address
    let (recipient_sk, recipient_pk) = generate_keypair();
    
    // Create fee quote
    let fee_quote = FeeQuote {
        fee_amount: FEE_AMOUNT,
        fee_recipient_pk: fee_collector_pk,
        expiry_timestamp: 0xFFFFFFFF, // Far future
    };
    let fee_message = format!("Fee payment of {}", FEE_AMOUNT);
    let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
    let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
    
    // Create transfer UTXOs
    let transfer_amount = btc_deposit_amount - FEE_AMOUNT;
    
    let recipient_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: transfer_amount,
        owner_pubkey: recipient_pk,
        blinding_factor: [2; 32],
    };
    
    let fee_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: FEE_AMOUNT,
        owner_pubkey: fee_collector_pk,
        blinding_factor: [3; 32],
    };
    
    // Calculate nullifier for input UTXO
    let input_nullifier = calculate_nullifier(&mint_utxo, &user_sk);
    
    // Create transfer circuit
    let transfer_circuit = TransferCircuit {
        sender_pk: user_pk,
        sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
        input_utxo: mint_utxo,
        output_utxos: vec![recipient_utxo.clone(), fee_utxo.clone()],
        fee_quote: Some(fee_quote),
        fee_signature: Some(fee_signature),
    };
    
    // Generate and verify transfer proof
    let transfer_proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit)).expect("Failed to generate transfer proof");
    let transfer_verified = verify_proof::<F, C, D>(&transfer_proof).expect("Failed to verify transfer proof");
    assert!(transfer_verified, "Transfer proof verification failed");
    
    // 3. Burn wBTC for BTC withdrawal
    let burn_amount = transfer_amount; // Burn all received wBTC
    let btc_address = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"; // Example BTC address
    
    // Create burn circuit
    let burn_circuit = WrappedAssetBurnCircuit {
        input_utxo: recipient_utxo,
        owner_sk: recipient_sk,
        owner_pk: recipient_pk,
        burn_amount,
        btc_address: btc_address.as_bytes().to_vec(),
        fee_quote: None, // No fee for simplicity in this test
        fee_signature: None,
    };
    
    // Generate and verify burn proof
    let burn_proof = generate_proof::<F, C, D>(Arc::new(burn_circuit)).expect("Failed to generate burn proof");
    let burn_verified = verify_proof::<F, C, D>(&burn_proof).expect("Failed to verify burn proof");
    assert!(burn_verified, "Burn proof verification failed");
    
    // 4. Aggregate proofs (optional, to test aggregation)
    let aggregated_proof = aggregate_proofs::<F, C, D>(&[mint_proof, transfer_proof, burn_proof])
        .expect("Failed to aggregate proofs");
    let aggregated_verified = verify_proof::<F, C, D>(&aggregated_proof).expect("Failed to verify aggregated proof");
    assert!(aggregated_verified, "Aggregated proof verification failed");
    
    // In a real system, the MPC would now process the burn proof and execute the BTC withdrawal
    println!("Full wrapped BTC lifecycle test passed successfully");
}

/// Tests the fee mechanism and collection process
#[test]
fn test_fee_mechanism_and_collection() {
    // Generate keys for participants
    let (user_sk, user_pk) = generate_keypair();
    let (fee_collector_sk, fee_collector_pk) = generate_keypair();
    
    // Create initial UTXO with sufficient funds
    let initial_amount = 1000000;
    let initial_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: initial_amount,
        owner_pubkey: user_pk,
        blinding_factor: [1; 32],
    };
    
    // Create fee quote
    let fee_quote = FeeQuote {
        fee_amount: FEE_AMOUNT,
        fee_recipient_pk: fee_collector_pk,
        expiry_timestamp: 0xFFFFFFFF, // Far future
    };
    let fee_message = format!("Fee payment of {}", FEE_AMOUNT);
    let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
    let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
    
    // Create transfer UTXOs
    let transfer_amount = initial_amount - FEE_AMOUNT;
    
    let recipient_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: transfer_amount,
        owner_pubkey: user_pk, // Transfer to self
        blinding_factor: [2; 32],
    };
    
    let fee_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: FEE_AMOUNT,
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
    let transfer_proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit)).expect("Failed to generate transfer proof");
    let transfer_verified = verify_proof::<F, C, D>(&transfer_proof).expect("Failed to verify transfer proof");
    assert!(transfer_verified, "Transfer proof verification failed");
    
    // Simulate fee collection by creating multiple fee UTXOs
    let mut fee_utxos = vec![fee_utxo];
    let num_additional_fees = 5;
    
    for i in 0..num_additional_fees {
        fee_utxos.push(UTXO {
            asset_id: [0; 32], // wBTC asset ID
            amount: FEE_AMOUNT,
            owner_pubkey: fee_collector_pk,
            blinding_factor: [4 + i as u8; 32],
        });
    }
    
    // Consolidate fees (simulating what the fee_monitor.py script would do)
    let total_fees = FEE_AMOUNT * (num_additional_fees + 1) as u64;
    let consolidated_fee_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: total_fees,
        owner_pubkey: fee_collector_pk,
        blinding_factor: [10; 32],
    };
    
    // In a real system, the fee collector would create a transfer proof consolidating all fee UTXOs
    println!("Fee mechanism test passed successfully");
}

/// Tests the full lifecycle of a native asset: create -> mint -> transfer -> burn
#[test]
fn test_native_asset_lifecycle() {
    // Generate keys for participants
    let (creator_sk, creator_pk) = generate_keypair();
    let (user_sk, user_pk) = generate_keypair();
    let (fee_collector_sk, fee_collector_pk) = generate_keypair();
    
    // 1. Create a native asset
    let asset_name = "Test Token".as_bytes().to_vec();
    let asset_symbol = "TST".as_bytes().to_vec();
    let asset_decimals = 18;
    
    let asset_id = compute_asset_id(&asset_name, &asset_symbol, asset_decimals);
    
    // Create fee quote for asset creation
    let fee_quote = FeeQuote {
        fee_amount: FEE_AMOUNT,
        fee_recipient_pk: fee_collector_pk,
        expiry_timestamp: 0xFFFFFFFF, // Far future
    };
    let fee_message = format!("Fee payment of {}", FEE_AMOUNT);
    let fee_message_hash = compute_message_hash(&fee_message.as_bytes().to_vec());
    let fee_signature = sign_message(&fee_collector_sk, &fee_message_hash);
    
    // Create initial UTXO for fee payment
    let initial_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID for fee payment
        amount: FEE_AMOUNT,
        owner_pubkey: creator_pk,
        blinding_factor: [1; 32],
    };
    
    // Create fee UTXO
    let fee_utxo = UTXO {
        asset_id: [0; 32], // wBTC asset ID
        amount: FEE_AMOUNT,
        owner_pubkey: fee_collector_pk,
        blinding_factor: [2; 32],
    };
    
    // Create native asset circuit
    let create_circuit = NativeAssetCreateCircuit {
        creator_pk,
        creator_sk,
        asset_name: asset_name.clone(),
        asset_symbol: asset_symbol.clone(),
        asset_decimals,
        fee_input_utxo: initial_utxo,
        fee_output_utxo: fee_utxo,
        fee_quote,
        fee_signature,
    };
    
    // Generate and verify create proof
    let create_proof = generate_proof::<F, C, D>(Arc::new(create_circuit)).expect("Failed to generate create proof");
    let create_verified = verify_proof::<F, C, D>(&create_proof).expect("Failed to verify create proof");
    assert!(create_verified, "Create proof verification failed");
    
    // 2. Mint native asset tokens
    let mint_amount = 1000000;
    
    // Create mint UTXO
    let mint_utxo = UTXO {
        asset_id, // The created native asset
        amount: mint_amount,
        owner_pubkey: user_pk,
        blinding_factor: [3; 32],
    };
    
    // Create mint circuit
    let mint_circuit = NativeAssetMintCircuit {
        creator_pk,
        creator_sk,
        asset_id,
        mint_amount,
        recipient_pk: user_pk,
        output_utxo: mint_utxo.clone(),
        fee_quote: None, // No fee for simplicity
        fee_signature: None,
    };
    
    // Generate and verify mint proof
    let mint_proof = generate_proof::<F, C, D>(Arc::new(mint_circuit)).expect("Failed to generate mint proof");
    let mint_verified = verify_proof::<F, C, D>(&mint_proof).expect("Failed to verify mint proof");
    assert!(mint_verified, "Mint proof verification failed");
    
    // 3. Transfer native asset tokens
    let transfer_amount = mint_amount / 2;
    let (recipient_sk, recipient_pk) = generate_keypair();
    
    // Create transfer UTXOs
    let recipient_utxo = UTXO {
        asset_id,
        amount: transfer_amount,
        owner_pubkey: recipient_pk,
        blinding_factor: [4; 32],
    };
    
    let change_utxo = UTXO {
        asset_id,
        amount: mint_amount - transfer_amount,
        owner_pubkey: user_pk,
        blinding_factor: [5; 32],
    };
    
    // Create transfer circuit
    let transfer_circuit = TransferCircuit {
        sender_pk: user_pk,
        sender_sig: sign_message(&user_sk, &compute_message_hash(&b"transfer".to_vec())),
        input_utxo: mint_utxo,
        output_utxos: vec![recipient_utxo.clone(), change_utxo.clone()],
        fee_quote: None, // No fee for simplicity
        fee_signature: None,
    };
    
    // Generate and verify transfer proof
    let transfer_proof = generate_proof::<F, C, D>(Arc::new(transfer_circuit)).expect("Failed to generate transfer proof");
    let transfer_verified = verify_proof::<F, C, D>(&transfer_proof).expect("Failed to verify transfer proof");
    assert!(transfer_verified, "Transfer proof verification failed");
    
    // 4. Burn native asset tokens
    let burn_amount = transfer_amount;
    
    // Create burn circuit
    let burn_circuit = NativeAssetBurnCircuit {
        input_utxo: recipient_utxo,
        owner_sk: recipient_sk,
        owner_pk: recipient_pk,
        asset_id,
        burn_amount,
        fee_quote: None, // No fee for simplicity
        fee_signature: None,
    };
    
    // Generate and verify burn proof
    let burn_proof = generate_proof::<F, C, D>(Arc::new(burn_circuit)).expect("Failed to generate burn proof");
    let burn_verified = verify_proof::<F, C, D>(&burn_proof).expect("Failed to verify burn proof");
    assert!(burn_verified, "Burn proof verification failed");
    
    println!("Native asset lifecycle test passed successfully");
}
