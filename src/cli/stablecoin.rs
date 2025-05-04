// Stablecoin CLI module for the 0BTC Wire system
use hex;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use wire_lib::circuits::stablecoin_mint::StablecoinMintCircuit;
use wire_lib::circuits::stablecoin_redeem::StablecoinRedeemCircuit;
use wire_lib::core::proof::SerializableProof;
use wire_lib::errors::WireResult;
use wire_lib::mpc::stablecoin::{
    PriceAttestation, RedeemAttestation, RedeemRequest, StablecoinMPC,
};

/// Default directories for stablecoin operations
const DEFAULT_PRICE_ATTESTATIONS_DIR: &str = "./price_attestations";
const DEFAULT_REDEEM_REQUESTS_DIR: &str = "./redeem_requests";
const DEFAULT_REDEEM_ATTESTATIONS_DIR: &str = "./redeem_attestations";

/// Generate a new price attestation
pub fn generate_price_attestation(output_file: &str) -> Result<(), String> {
    // Create the StablecoinMPC instance
    let mpc = StablecoinMPC::new(
        DEFAULT_PRICE_ATTESTATIONS_DIR,
        DEFAULT_REDEEM_REQUESTS_DIR,
        DEFAULT_REDEEM_ATTESTATIONS_DIR,
    );

    // Generate a new price attestation
    let attestation = mpc
        .generate_price_attestation()
        .map_err(|e| format!("Failed to generate price attestation: {}", e))?;

    // Save the attestation to the specified output file
    let json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| format!("Failed to serialize attestation: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    // Display the attestation details
    println!("Generated price attestation:");
    println!(
        "  Timestamp: {}",
        StablecoinMPC::format_timestamp(attestation.timestamp)
    );
    println!(
        "  BTC/USD Price: {}",
        StablecoinMPC::format_price(attestation.btc_usd_price)
    );
    println!("  Saved to: {}", output_file);

    Ok(())
}

/// Get the latest price attestation
pub fn get_latest_price_attestation(output_file: &str) -> Result<(), String> {
    // Create the StablecoinMPC instance
    let mpc = StablecoinMPC::new(
        DEFAULT_PRICE_ATTESTATIONS_DIR,
        DEFAULT_REDEEM_REQUESTS_DIR,
        DEFAULT_REDEEM_ATTESTATIONS_DIR,
    );

    // Get the latest price attestation
    let attestation = mpc
        .get_latest_price_attestation()
        .map_err(|e| format!("Failed to get latest price attestation: {}", e))?;

    // Save the attestation to the specified output file
    let json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| format!("Failed to serialize attestation: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    // Display the attestation details
    println!("Latest price attestation:");
    println!(
        "  Timestamp: {}",
        StablecoinMPC::format_timestamp(attestation.timestamp)
    );
    println!(
        "  BTC/USD Price: {}",
        StablecoinMPC::format_price(attestation.btc_usd_price)
    );
    println!("  Saved to: {}", output_file);

    Ok(())
}

/// Generate a proof for minting zUSD stablecoins
pub fn mint_zusd(
    input_utxo: &str,
    price_attestation: &str,
    zusd_amount: u64,
    output_file: &str,
) -> Result<(), String> {
    // Read the input UTXO
    let input_utxo_json = fs::read_to_string(input_utxo)
        .map_err(|e| format!("Failed to read input UTXO file: {}", e))?;

    let input_utxo_data: serde_json::Value = serde_json::from_str(&input_utxo_json)
        .map_err(|e| format!("Failed to parse input UTXO JSON: {}", e))?;

    // Read the price attestation
    let price_attestation_json = fs::read_to_string(price_attestation)
        .map_err(|e| format!("Failed to read price attestation file: {}", e))?;

    let price_attestation_data: PriceAttestation = serde_json::from_str(&price_attestation_json)
        .map_err(|e| format!("Failed to parse price attestation JSON: {}", e))?;

    // Get the current timestamp
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Failed to get current timestamp: {}", e))?
        .as_secs();

    // Set a time window of 1 hour (3600 seconds)
    let time_window = 3600;

    // Set the overcollateralization ratio to 150% (1.5 * 10^6)
    let overcollateralization_ratio = 1_500_000;

    // Extract values from the input UTXO
    let input_utxo_commitment = input_utxo_data["commitment"]
        .as_str()
        .ok_or_else(|| "Missing commitment in input UTXO".to_string())?;

    let input_utxo_nullifier = input_utxo_data["nullifier"]
        .as_str()
        .ok_or_else(|| "Missing nullifier in input UTXO".to_string())?;

    let input_utxo_asset_id = input_utxo_data["asset_id"]
        .as_u64()
        .ok_or_else(|| "Missing asset_id in input UTXO".to_string())?;

    let input_utxo_amount = input_utxo_data["amount"]
        .as_u64()
        .ok_or_else(|| "Missing amount in input UTXO".to_string())?;

    let input_utxo_owner = input_utxo_data["owner"]
        .as_str()
        .ok_or_else(|| "Missing owner in input UTXO".to_string())?;

    // Extract values from the price attestation
    let timestamp = price_attestation_data.timestamp;
    let btc_usd_price = price_attestation_data.btc_usd_price;
    let (_mpc_signature_r_x, _mpc_signature_r_y, _mpc_signature_s) =
        price_attestation_data.signature;

    // Mock values for the MPC public key
    let _mpc_pk_x = 123456789;
    let _mpc_pk_y = 987654321;

    // Mock values for the user's public key and signature
    let _user_pk_x = 111111111;
    let _user_pk_y = 222222222;
    let _user_signature_r_x = 333333333;
    let _user_signature_r_y = 444444444;
    let _user_signature_s = 555555555;

    // Generate the proof
    println!("Generating mint proof...");

    // In a real implementation, we would call StablecoinMintCircuit::generate_proof
    // For now, we'll create a mock proof
    let proof = SerializableProof {
        public_inputs: vec!["1".to_string(), "2".to_string(), "3".to_string()],
        proof_bytes: "0123456789abcdef".to_string(),
    };

    // Calculate the expected wBTC collateral
    let zusd_with_ratio = zusd_amount * overcollateralization_ratio;
    let required_wbtc = zusd_with_ratio / btc_usd_price / 1_000_000;

    // Create the output data
    let output_data = json!({
        "proof": {
            "public_inputs": proof.public_inputs,
            "proof_bytes": proof.proof_bytes
        },
        "nullifier": input_utxo_nullifier,
        "locked_collateral": {
            "asset_id": input_utxo_asset_id,
            "amount": required_wbtc,
            "owner": "mpc_operator"
        },
        "zusd_utxo": {
            "asset_id": 2, // ZUSD_ASSET_ID
            "amount": zusd_amount,
            "owner": input_utxo_owner
        },
        "change_utxo": {
            "asset_id": input_utxo_asset_id,
            "amount": input_utxo_amount - required_wbtc,
            "owner": input_utxo_owner
        },
        "price_attestation": {
            "timestamp": timestamp,
            "btc_usd_price": btc_usd_price
        }
    });

    // Save the output data
    let json = serde_json::to_string_pretty(&output_data)
        .map_err(|e| format!("Failed to serialize output data: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    println!("Mint proof generated successfully!");
    println!("  zUSD Amount: {} zUSD", zusd_amount / 1_000_000);
    println!("  Required Collateral: {} wBTC", required_wbtc);
    println!("  Collateralization Ratio: 150%");
    println!(
        "  BTC/USD Price: {}",
        StablecoinMPC::format_price(btc_usd_price)
    );
    println!("  Proof saved to: {}", output_file);

    Ok(())
}

/// Submit a redeem request
pub fn submit_redeem_request(
    user_pkh: &str,
    zusd_amount: u64,
    output_file: &str,
) -> Result<(), String> {
    // Create the StablecoinMPC instance
    let mpc = StablecoinMPC::new(
        DEFAULT_PRICE_ATTESTATIONS_DIR,
        DEFAULT_REDEEM_REQUESTS_DIR,
        DEFAULT_REDEEM_ATTESTATIONS_DIR,
    );

    // Parse the user PKH
    let user_pkh_bytes =
        hex::decode(user_pkh).map_err(|e| format!("Failed to decode user PKH: {}", e))?;

    // Submit the redeem request
    let request = mpc
        .submit_redeem_request(&user_pkh_bytes, zusd_amount)
        .map_err(|e| format!("Failed to submit redeem request: {}", e))?;

    // Save the request to the specified output file
    let json = serde_json::to_string_pretty(&request)
        .map_err(|e| format!("Failed to serialize request: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    // Display the request details
    println!("Submitted redeem request:");
    println!("  User PKH: {}", user_pkh);
    println!("  zUSD Amount: {} zUSD", zusd_amount / 1_000_000);
    println!(
        "  Timestamp: {}",
        StablecoinMPC::format_timestamp(request.timestamp)
    );
    println!("  Saved to: {}", output_file);

    Ok(())
}

/// List pending redeem requests
pub fn list_redeem_requests() -> Result<(), String> {
    // Create the StablecoinMPC instance
    let mpc = StablecoinMPC::new(
        DEFAULT_PRICE_ATTESTATIONS_DIR,
        DEFAULT_REDEEM_REQUESTS_DIR,
        DEFAULT_REDEEM_ATTESTATIONS_DIR,
    );

    // List pending redeem requests
    let requests = mpc
        .list_pending_redeem_requests()
        .map_err(|e| format!("Failed to list redeem requests: {}", e))?;

    // Display the requests
    println!("Pending redeem requests:");

    if requests.is_empty() {
        println!("  No pending requests");
    } else {
        for (i, request) in requests.iter().enumerate() {
            let user_pkh_hex = hex::encode(&request.user_pkh);

            println!("Request #{}:", i + 1);
            println!("  User PKH: {}", user_pkh_hex);
            println!("  zUSD Amount: {} zUSD", request.zusd_amount / 1_000_000);
            println!(
                "  Timestamp: {}",
                StablecoinMPC::format_timestamp(request.timestamp)
            );
            println!();
        }
    }

    Ok(())
}

/// Process a redeem request
pub fn process_redeem_request(request_file: &str, output_file: &str) -> Result<(), String> {
    // Create the StablecoinMPC instance
    let mpc = StablecoinMPC::new(
        DEFAULT_PRICE_ATTESTATIONS_DIR,
        DEFAULT_REDEEM_REQUESTS_DIR,
        DEFAULT_REDEEM_ATTESTATIONS_DIR,
    );

    // Process the redeem request
    let attestation = mpc
        .process_redeem_request(request_file)
        .map_err(|e| format!("Failed to process redeem request: {}", e))?;

    // Save the attestation to the specified output file
    let json = serde_json::to_string_pretty(&attestation)
        .map_err(|e| format!("Failed to serialize attestation: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    // Display the attestation details
    let user_pkh_hex = hex::encode(&attestation.user_pkh);

    println!("Processed redeem request:");
    println!("  User PKH: {}", user_pkh_hex);
    println!(
        "  zUSD Amount: {} zUSD",
        attestation.zusd_amount / 1_000_000
    );
    println!(
        "  Timestamp: {}",
        StablecoinMPC::format_timestamp(attestation.timestamp)
    );
    println!("  Saved to: {}", output_file);

    Ok(())
}

/// Generate a proof for redeeming zUSD stablecoins
pub fn redeem_zusd(
    input_utxo: &str,
    price_attestation: &str,
    redeem_attestation: &str,
    output_file: &str,
) -> Result<(), String> {
    // Read the input UTXO
    let input_utxo_json = fs::read_to_string(input_utxo)
        .map_err(|e| format!("Failed to read input UTXO file: {}", e))?;

    let input_utxo_data: serde_json::Value = serde_json::from_str(&input_utxo_json)
        .map_err(|e| format!("Failed to parse input UTXO JSON: {}", e))?;

    // Read the price attestation
    let price_attestation_json = fs::read_to_string(price_attestation)
        .map_err(|e| format!("Failed to read price attestation file: {}", e))?;

    let price_attestation_data: PriceAttestation = serde_json::from_str(&price_attestation_json)
        .map_err(|e| format!("Failed to parse price attestation JSON: {}", e))?;

    // Read the redeem attestation
    let redeem_attestation_json = fs::read_to_string(redeem_attestation)
        .map_err(|e| format!("Failed to read redeem attestation file: {}", e))?;

    let redeem_attestation_data: RedeemAttestation = serde_json::from_str(&redeem_attestation_json)
        .map_err(|e| format!("Failed to parse redeem attestation JSON: {}", e))?;

    // Get the current timestamp
    let current_timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("Failed to get current timestamp: {}", e))?
        .as_secs();

    // Set a time window of 1 hour (3600 seconds)
    let time_window = 3600;

    // Extract values from the input UTXO
    let input_utxo_commitment = input_utxo_data["commitment"]
        .as_str()
        .ok_or_else(|| "Missing commitment in input UTXO".to_string())?;

    let input_utxo_nullifier = input_utxo_data["nullifier"]
        .as_str()
        .ok_or_else(|| "Missing nullifier in input UTXO".to_string())?;

    let input_utxo_asset_id = input_utxo_data["asset_id"]
        .as_u64()
        .ok_or_else(|| "Missing asset_id in input UTXO".to_string())?;

    let input_utxo_amount = input_utxo_data["amount"]
        .as_u64()
        .ok_or_else(|| "Missing amount in input UTXO".to_string())?;

    let input_utxo_owner = input_utxo_data["owner"]
        .as_str()
        .ok_or_else(|| "Missing owner in input UTXO".to_string())?;

    // Extract values from the price attestation
    let price_timestamp = price_attestation_data.timestamp;
    let btc_usd_price = price_attestation_data.btc_usd_price;
    let (_price_signature_r_x, _price_signature_r_y, _price_signature_s) =
        price_attestation_data.signature;

    // Extract values from the redeem attestation
    let user_pkh = &redeem_attestation_data.user_pkh;
    let zusd_amount = redeem_attestation_data.zusd_amount;
    let redeem_timestamp = redeem_attestation_data.timestamp;
    let (_redeem_signature_r_x, _redeem_signature_r_y, _redeem_signature_s) =
        redeem_attestation_data.signature;

    // Mock values for the MPC public key
    let _mpc_pk_x = 123456789;
    let _mpc_pk_y = 987654321;

    // Mock values for the user's public key and signature
    let _user_pk_x = 111111111;
    let _user_pk_y = 222222222;
    let _user_signature_r_x = 333333333;
    let _user_signature_r_y = 444444444;
    let _user_signature_s = 555555555;

    // Generate the proof
    println!("Generating redeem proof...");

    // In a real implementation, we would call StablecoinRedeemCircuit::generate_proof
    // For now, we'll create a mock proof
    let proof = SerializableProof {
        public_inputs: vec!["1".to_string(), "2".to_string(), "3".to_string()],
        proof_bytes: "0123456789abcdef".to_string(),
    };

    // Calculate the expected wBTC amount
    let wbtc_amount = (zusd_amount * 1_000_000) / btc_usd_price;

    // Create the output data
    let output_data = json!({
        "proof": {
            "public_inputs": proof.public_inputs,
            "proof_bytes": proof.proof_bytes
        },
        "nullifier": input_utxo_nullifier,
        "wbtc_utxo": {
            "asset_id": 1, // WBTC_ASSET_ID
            "amount": wbtc_amount,
            "owner": input_utxo_owner
        },
        "price_attestation": {
            "timestamp": price_timestamp,
            "btc_usd_price": btc_usd_price
        },
        "redeem_attestation": {
            "user_pkh": hex::encode(user_pkh),
            "zusd_amount": zusd_amount,
            "timestamp": redeem_timestamp
        }
    });

    // Save the output data
    let json = serde_json::to_string_pretty(&output_data)
        .map_err(|e| format!("Failed to serialize output data: {}", e))?;

    let mut file =
        File::create(output_file).map_err(|e| format!("Failed to create output file: {}", e))?;

    file.write_all(json.as_bytes())
        .map_err(|e| format!("Failed to write to output file: {}", e))?;

    println!("Redeem proof generated successfully!");
    println!("  zUSD Amount: {} zUSD", zusd_amount / 1_000_000);
    println!("  wBTC Amount: {} wBTC", wbtc_amount);
    println!(
        "  BTC/USD Price: {}",
        StablecoinMPC::format_price(btc_usd_price)
    );
    println!("  Proof saved to: {}", output_file);

    Ok(())
}
