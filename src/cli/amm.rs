// AMM CLI commands for the 0BTC Wire system
use hex;
use log::{error, info, warn};
use serde_json::{json, Value};
use std::fs;
use std::path::Path;

use crate::cli::validation::{validate_file_path, validate_output_file_path, ValidationError};
use wire_lib::circuits::{
    AddLiquidityCircuit, PoolStateTarget, RemoveLiquidityCircuit, SwapCircuit,
};
use wire_lib::errors::{WireError, WireResult};

/// Create a new liquidity pool
pub fn create_pool(
    token_a_asset_id: &str,
    token_b_asset_id: &str,
    output_path: &str,
) -> Result<(), String> {
    // Validate the output path
    validate_output_file_path(output_path).map_err(|e| format!("Invalid output path: {}", e))?;

    info!(
        "Creating new liquidity pool for tokens {} and {}",
        token_a_asset_id, token_b_asset_id
    );

    // Parse the asset IDs
    let token_a_id = u64::from_str_radix(token_a_asset_id, 16)
        .map_err(|e| format!("Invalid token A asset ID: {}", e))?;
    let token_b_id = u64::from_str_radix(token_b_asset_id, 16)
        .map_err(|e| format!("Invalid token B asset ID: {}", e))?;

    // Ensure token A ID is less than token B ID (for consistent pool IDs)
    let (token_a_id, token_b_id) = if token_a_id > token_b_id {
        (token_b_id, token_a_id)
    } else {
        (token_a_id, token_b_id)
    };

    // Generate a pool ID (hash of the two asset IDs)
    let pool_id = format!("{:x}", token_a_id ^ token_b_id);

    // Create a new pool state
    let pool_state = json!({
        "pool_id": pool_id,
        "token_a_asset_id": format!("{:x}", token_a_id),
        "token_b_asset_id": format!("{:x}", token_b_id),
        "reserve_a": 0,
        "reserve_b": 0,
        "total_lp_shares": 0,
        "has_transitioned": false,
        "current_supply": 0,
        "target_reserve": 0
    });

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&pool_state)
        .map_err(|e| format!("Failed to serialize pool state: {}", e))?;

    // Write to file
    fs::write(output_path, json_data)
        .map_err(|e| format!("Failed to write pool state to file: {}", e))?;

    info!("New liquidity pool created with ID: {}", pool_id);
    info!("Pool state saved to {}", output_path);

    Ok(())
}

/// Swap tokens in a liquidity pool
pub fn swap_tokens(
    input_utxo_path: &str,
    pool_state_path: &str,
    output_asset_id: &str,
    min_output_amount: u64,
    output_path: &str,
) -> Result<(), String> {
    // Validate paths
    validate_file_path(input_utxo_path, true)
        .map_err(|e| format!("Invalid input UTXO path: {}", e))?;
    validate_file_path(pool_state_path, true)
        .map_err(|e| format!("Invalid pool state path: {}", e))?;
    validate_output_file_path(output_path).map_err(|e| format!("Invalid output path: {}", e))?;

    // Read the input UTXO file
    let input_utxo_data = fs::read_to_string(input_utxo_path)
        .map_err(|e| format!("Failed to read input UTXO file: {}", e))?;

    // Parse the input UTXO
    let input_utxo: Value = serde_json::from_str(&input_utxo_data)
        .map_err(|e| format!("Failed to parse input UTXO: {}", e))?;

    // Read the pool state file
    let pool_state_data = fs::read_to_string(pool_state_path)
        .map_err(|e| format!("Failed to read pool state file: {}", e))?;

    // Parse the pool state
    let pool_state: Value = serde_json::from_str(&pool_state_data)
        .map_err(|e| format!("Failed to parse pool state: {}", e))?;

    info!(
        "Swapping tokens in pool {}",
        pool_state["pool_id"].as_str().unwrap_or("unknown")
    );

    // Extract UTXO values
    let _commitment = hex::decode(input_utxo["commitment"].as_str().unwrap_or(""))
        .map_err(|e| format!("Invalid commitment: {}", e))?;
    let _nullifier = hex::decode(input_utxo["nullifier"].as_str().unwrap_or(""))
        .map_err(|e| format!("Invalid nullifier: {}", e))?;
    let asset_id_str = input_utxo["asset_id"].as_str().unwrap_or("");
    let asset_id =
        u64::from_str_radix(asset_id_str, 16).map_err(|e| format!("Invalid asset ID: {}", e))?;
    let amount = input_utxo["amount"].as_u64().unwrap_or(0);
    let _owner = hex::decode(input_utxo["owner"].as_str().unwrap_or(""))
        .map_err(|e| format!("Invalid owner: {}", e))?;

    // Extract pool state values
    let _pool_id = hex::decode(pool_state["pool_id"].as_str().unwrap_or(""))
        .map_err(|e| format!("Invalid pool ID: {}", e))?;
    let token_a_asset_id_str = pool_state["token_a_asset_id"].as_str().unwrap_or("");
    let token_a_asset_id = u64::from_str_radix(token_a_asset_id_str, 16)
        .map_err(|e| format!("Invalid token A asset ID: {}", e))?;
    let token_b_asset_id_str = pool_state["token_b_asset_id"].as_str().unwrap_or("");
    let token_b_asset_id = u64::from_str_radix(token_b_asset_id_str, 16)
        .map_err(|e| format!("Invalid token B asset ID: {}", e))?;
    let reserve_a = pool_state["reserve_a"].as_u64().unwrap_or(0);
    let reserve_b = pool_state["reserve_b"].as_u64().unwrap_or(0);
    let total_lp_shares = pool_state["total_lp_shares"].as_u64().unwrap_or(0);
    let has_transitioned = pool_state["has_transitioned"].as_bool().unwrap_or(false);
    let current_supply = pool_state["current_supply"].as_u64().unwrap_or(0);
    let target_reserve = pool_state["target_reserve"].as_u64().unwrap_or(0);

    // Convert string asset IDs to numeric values for comparison
    let token_a_asset_id_str = format!("{:x}", token_a_asset_id);
    let token_b_asset_id_str = format!("{:x}", token_b_asset_id);
    
    // Check if output asset is one of the pool assets
    if output_asset_id != token_a_asset_id_str && output_asset_id != token_b_asset_id_str {
        return Err("Output asset must be one of the pool assets".to_string());
    }

    // Determine input and output assets
    let _asset_id_str = if output_asset_id == token_a_asset_id_str {
        token_b_asset_id_str
    } else {
        token_a_asset_id_str
    };
    
    // Parse the output asset ID from hex string to bytes
    let _output_asset_id_bytes = hex::decode(output_asset_id.trim_start_matches("0x"))
        .map_err(|e| format!("Invalid output asset ID: {}", e))?;

    // Example user public key values
    let _user_pk_x = 12345;
    let _user_pk_y = 67890;

    // Example signature values
    let _signature_r_x = 11111;
    let _signature_r_y = 22222;
    let _signature_s = 33333;

    // Generate the proof
    // In a real implementation, this would call SwapCircuit::generate_proof
    // For now, we'll create a mock proof result

    // Calculate the expected output amount using the constant product formula
    let (input_reserve, output_reserve) = if asset_id == token_a_asset_id {
        (reserve_a, reserve_b)
    } else {
        (reserve_b, reserve_a)
    };

    // k = x * y
    let k = input_reserve * output_reserve;

    // new_input_reserve = input_reserve + amount
    let new_input_reserve = input_reserve + amount;

    // new_output_reserve = k / new_input_reserve
    let new_output_reserve = k / new_input_reserve;

    // output_amount = output_reserve - new_output_reserve
    let output_amount = output_reserve - new_output_reserve;

    // Ensure the output amount is at least the minimum requested
    if output_amount < min_output_amount {
        return Err(format!(
            "Output amount {} is less than minimum requested {}",
            output_amount, min_output_amount
        ));
    }

    // Create the new pool state
    let new_reserve_a = if asset_id == token_a_asset_id {
        reserve_a + amount
    } else {
        reserve_a - output_amount
    };

    let new_reserve_b = if asset_id == token_b_asset_id {
        reserve_b + amount
    } else {
        reserve_b - output_amount
    };

    let new_pool_state = json!({
        "pool_id": pool_state["pool_id"],
        "token_a_asset_id": pool_state["token_a_asset_id"],
        "token_b_asset_id": pool_state["token_b_asset_id"],
        "reserve_a": new_reserve_a,
        "reserve_b": new_reserve_b,
        "total_lp_shares": total_lp_shares,
        "has_transitioned": has_transitioned,
        "current_supply": current_supply,
        "target_reserve": target_reserve
    });

    // Create the output UTXO
    let output_utxo = json!({
        "asset_id": output_asset_id,
        "amount": output_amount,
        "owner": input_utxo["owner"],
        "nullifier": format!("{:x}", rand::random::<u64>()),
        "commitment": format!("{:x}", rand::random::<u64>())
    });

    // Create the result
    let result = json!({
        "nullifier": input_utxo["nullifier"],
        "output_utxo": output_utxo,
        "new_pool_state": new_pool_state
    });

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Failed to serialize result: {}", e))?;

    // Write to file
    fs::write(output_path, json_data)
        .map_err(|e| format!("Failed to write result to file: {}", e))?;

    info!("Swap successful");
    info!("Input amount: {}", amount);
    info!("Output amount: {}", output_amount);
    info!("Result saved to {}", output_path);

    Ok(())
}

/// Add liquidity to a pool
pub fn add_liquidity(
    input_utxo_a_path: &str,
    input_utxo_b_path: &str,
    pool_state_path: &str,
    min_lp_tokens: u64,
    output_path: &str,
) -> Result<(), String> {
    // Validate the input and output paths
    validate_file_path(input_utxo_a_path, true)
        .map_err(|e| format!("Invalid input UTXO A path: {}", e))?;
    validate_file_path(input_utxo_b_path, true)
        .map_err(|e| format!("Invalid input UTXO B path: {}", e))?;
    validate_file_path(pool_state_path, true)
        .map_err(|e| format!("Invalid pool state path: {}", e))?;
    validate_output_file_path(output_path).map_err(|e| format!("Invalid output path: {}", e))?;

    // Read the input UTXO files
    let input_utxo_a_data = fs::read_to_string(input_utxo_a_path)
        .map_err(|e| format!("Failed to read input UTXO A file: {}", e))?;
    let input_utxo_b_data = fs::read_to_string(input_utxo_b_path)
        .map_err(|e| format!("Failed to read input UTXO B file: {}", e))?;

    // Parse the input UTXOs
    let input_utxo_a: Value = serde_json::from_str(&input_utxo_a_data)
        .map_err(|e| format!("Failed to parse input UTXO A: {}", e))?;
    let input_utxo_b: Value = serde_json::from_str(&input_utxo_b_data)
        .map_err(|e| format!("Failed to parse input UTXO B: {}", e))?;

    // Read the pool state file
    let pool_state_data = fs::read_to_string(pool_state_path)
        .map_err(|e| format!("Failed to read pool state file: {}", e))?;

    // Parse the pool state
    let pool_state: Value = serde_json::from_str(&pool_state_data)
        .map_err(|e| format!("Failed to parse pool state: {}", e))?;

    info!(
        "Adding liquidity to pool {}",
        pool_state["pool_id"].as_str().unwrap_or("unknown")
    );

    // Extract UTXO values
    let asset_id_a_str = input_utxo_a["asset_id"].as_str().unwrap_or("");
    let _asset_id_a = u64::from_str_radix(asset_id_a_str, 16)
        .map_err(|e| format!("Invalid asset ID A: {}", e))?;
    let amount_a = input_utxo_a["amount"].as_u64().unwrap_or(0);

    let asset_id_b_str = input_utxo_b["asset_id"].as_str().unwrap_or("");
    let _asset_id_b = u64::from_str_radix(asset_id_b_str, 16)
        .map_err(|e| format!("Invalid asset ID B: {}", e))?;
    let amount_b = input_utxo_b["amount"].as_u64().unwrap_or(0);

    // Extract pool state values
    let token_a_asset_id_str = pool_state["token_a_asset_id"].as_str().unwrap_or("");
    let token_a_asset_id = u64::from_str_radix(token_a_asset_id_str, 16)
        .map_err(|e| format!("Invalid token A asset ID: {}", e))?;
    let token_b_asset_id_str = pool_state["token_b_asset_id"].as_str().unwrap_or("");
    let token_b_asset_id = u64::from_str_radix(token_b_asset_id_str, 16)
        .map_err(|e| format!("Invalid token B asset ID: {}", e))?;
    let reserve_a = pool_state["reserve_a"].as_u64().unwrap_or(0);
    let reserve_b = pool_state["reserve_b"].as_u64().unwrap_or(0);
    let total_lp_shares = pool_state["total_lp_shares"].as_u64().unwrap_or(0);

    // Convert string asset IDs to numeric values for comparison
    let token_a_asset_id_str = format!("{:x}", token_a_asset_id);
    let token_b_asset_id_str = format!("{:x}", token_b_asset_id);
    
    // Ensure the input tokens match the pool tokens
    let (input_a_is_token_a, input_b_is_token_b) =
        if asset_id_a_str == token_a_asset_id_str && asset_id_b_str == token_b_asset_id_str {
            (true, true)
        } else if asset_id_a_str == token_b_asset_id_str && asset_id_b_str == token_a_asset_id_str {
            (false, false)
        } else {
            return Err("Input token asset IDs do not match pool tokens".to_string());
        };

    // Calculate the LP tokens to mint
    let lp_tokens;

    if total_lp_shares == 0 {
        // If the pool is empty, use the geometric mean of the input amounts
        lp_tokens = (amount_a as f64 * amount_b as f64).sqrt() as u64;
    } else {
        // For non-empty pool, use the minimum of the two calculations
        let lp_tokens_a = amount_a * total_lp_shares / reserve_a;
        let lp_tokens_b = amount_b * total_lp_shares / reserve_b;
        lp_tokens = std::cmp::min(lp_tokens_a, lp_tokens_b);
    }

    // Ensure the LP tokens minted are at least the minimum requested
    if lp_tokens < min_lp_tokens {
        return Err(format!(
            "LP tokens minted {} is less than minimum requested {}",
            lp_tokens, min_lp_tokens
        ));
    }

    // Create the new pool state
    let new_pool_state = json!({
        "pool_id": pool_state["pool_id"],
        "token_a_asset_id": pool_state["token_a_asset_id"],
        "token_b_asset_id": pool_state["token_b_asset_id"],
        "reserve_a": reserve_a + (if input_a_is_token_a { amount_a } else { amount_b }),
        "reserve_b": reserve_b + (if input_b_is_token_b { amount_b } else { amount_a }),
        "total_lp_shares": total_lp_shares + lp_tokens,
        "has_transitioned": pool_state["has_transitioned"],
        "current_supply": pool_state["current_supply"],
        "target_reserve": pool_state["target_reserve"]
    });

    // Create the LP share
    let lp_share = json!({
        "pool_id": pool_state["pool_id"],
        "owner": input_utxo_a["owner"],
        "amount": lp_tokens,
        "nullifier": format!("{:x}", rand::random::<u64>()),
        "commitment": format!("{:x}", rand::random::<u64>())
    });

    // Create the result
    let result = json!({
        "nullifier_a": input_utxo_a["nullifier"],
        "nullifier_b": input_utxo_b["nullifier"],
        "lp_share": lp_share,
        "new_pool_state": new_pool_state
    });

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Failed to serialize result: {}", e))?;

    // Write to file
    fs::write(output_path, json_data)
        .map_err(|e| format!("Failed to write result to file: {}", e))?;

    info!("Liquidity added successfully");
    info!("Token A amount: {}", amount_a);
    info!("Token B amount: {}", amount_b);
    info!("LP tokens minted: {}", lp_tokens);
    info!("Result saved to {}", output_path);

    Ok(())
}

/// Remove liquidity from a pool
pub fn remove_liquidity(
    lp_share_path: &str,
    pool_state_path: &str,
    min_amount_a: u64,
    min_amount_b: u64,
    output_path: &str,
) -> Result<(), String> {
    // Validate the input and output paths
    validate_file_path(lp_share_path, true).map_err(|e| format!("Invalid LP share path: {}", e))?;
    validate_file_path(pool_state_path, true)
        .map_err(|e| format!("Invalid pool state path: {}", e))?;
    validate_output_file_path(output_path).map_err(|e| format!("Invalid output path: {}", e))?;

    // Read the LP share file
    let lp_share_data = fs::read_to_string(lp_share_path)
        .map_err(|e| format!("Failed to read LP share file: {}", e))?;

    // Parse the LP share
    let lp_share: Value = serde_json::from_str(&lp_share_data)
        .map_err(|e| format!("Failed to parse LP share: {}", e))?;

    // Read the pool state file
    let pool_state_data = fs::read_to_string(pool_state_path)
        .map_err(|e| format!("Failed to read pool state file: {}", e))?;

    // Parse the pool state
    let pool_state: Value = serde_json::from_str(&pool_state_data)
        .map_err(|e| format!("Failed to parse pool state: {}", e))?;

    info!(
        "Removing liquidity from pool {}",
        pool_state["pool_id"].as_str().unwrap_or("unknown")
    );

    // Extract LP share values
    let lp_share_pool_id = lp_share["pool_id"].as_str().unwrap_or("");
    let lp_share_amount = lp_share["amount"].as_u64().unwrap_or(0);

    // Extract pool state values
    let pool_id = pool_state["pool_id"].as_str().unwrap_or("");
    let reserve_a = pool_state["reserve_a"].as_u64().unwrap_or(0);
    let reserve_b = pool_state["reserve_b"].as_u64().unwrap_or(0);
    let total_lp_shares = pool_state["total_lp_shares"].as_u64().unwrap_or(0);

    // Ensure the LP share belongs to the correct pool
    if lp_share_pool_id != pool_id {
        return Err(format!(
            "LP share pool ID {} does not match pool ID {}",
            lp_share_pool_id, pool_id
        ));
    }

    // Calculate the token amounts to return
    let amount_a = lp_share_amount * reserve_a / total_lp_shares;
    let amount_b = lp_share_amount * reserve_b / total_lp_shares;

    // Ensure the token amounts are at least the minimum requested
    if amount_a < min_amount_a {
        return Err(format!(
            "Token A amount {} is less than minimum requested {}",
            amount_a, min_amount_a
        ));
    }
    if amount_b < min_amount_b {
        return Err(format!(
            "Token B amount {} is less than minimum requested {}",
            amount_b, min_amount_b
        ));
    }

    // Create the new pool state
    let new_pool_state = json!({
        "pool_id": pool_state["pool_id"],
        "token_a_asset_id": pool_state["token_a_asset_id"],
        "token_b_asset_id": pool_state["token_b_asset_id"],
        "reserve_a": reserve_a - amount_a,
        "reserve_b": reserve_b - amount_b,
        "total_lp_shares": total_lp_shares - lp_share_amount,
        "has_transitioned": pool_state["has_transitioned"],
        "current_supply": pool_state["current_supply"],
        "target_reserve": pool_state["target_reserve"]
    });

    // Create the output UTXOs
    let output_utxo_a = json!({
        "asset_id": pool_state["token_a_asset_id"],
        "amount": amount_a,
        "owner": lp_share["owner"],
        "nullifier": format!("{:x}", rand::random::<u64>()),
        "commitment": format!("{:x}", rand::random::<u64>())
    });

    let output_utxo_b = json!({
        "asset_id": pool_state["token_b_asset_id"],
        "amount": amount_b,
        "owner": lp_share["owner"],
        "nullifier": format!("{:x}", rand::random::<u64>()),
        "commitment": format!("{:x}", rand::random::<u64>())
    });

    // Create the result
    let result = json!({
        "lp_share_nullifier": lp_share["nullifier"],
        "output_utxo_a": output_utxo_a,
        "output_utxo_b": output_utxo_b,
        "new_pool_state": new_pool_state
    });

    // Serialize to JSON
    let json_data = serde_json::to_string_pretty(&result)
        .map_err(|e| format!("Failed to serialize result: {}", e))?;

    // Write to file
    fs::write(output_path, json_data)
        .map_err(|e| format!("Failed to write result to file: {}", e))?;

    info!("Liquidity removed successfully");
    info!("LP tokens burned: {}", lp_share_amount);
    info!("Token A amount: {}", amount_a);
    info!("Token B amount: {}", amount_b);
    info!("Result saved to {}", output_path);

    Ok(())
}

/// Execute the swap command
pub fn execute_swap_command(matches: &clap::ArgMatches) -> wire_lib::errors::WireResult<()> {
    let input_utxo = matches.get_one::<String>("input-utxo").unwrap();
    let pool_id = matches.get_one::<String>("pool-id").unwrap();
    let min_output_amount = matches.get_one::<String>("min-output-amount").unwrap();
    let output_asset_id = matches.get_one::<String>("output-asset-id").unwrap();
    let output_path = matches.get_one::<String>("output-path").unwrap();
    
    // Convert min_output_amount to u64
    let min_output_amount_u64 = min_output_amount.parse::<u64>()
        .map_err(|_| wire_lib::errors::WireError::GenericError("Invalid min output amount".to_string()))?;
    
    // Call the swap_tokens function
    swap_tokens(input_utxo, pool_id, output_asset_id, min_output_amount_u64, output_path)
        .map_err(|e| wire_lib::errors::WireError::GenericError(e))
}

/// Execute the add liquidity command
pub fn execute_add_liquidity_command(matches: &clap::ArgMatches) -> wire_lib::errors::WireResult<()> {
    let input_utxo_a = matches.get_one::<String>("input-utxo-a").unwrap();
    let input_utxo_b = matches.get_one::<String>("input-utxo-b").unwrap();
    let pool_id = matches.get_one::<String>("pool-id").unwrap();
    let min_lp_tokens = matches.get_one::<String>("min-lp-tokens").unwrap();
    let output_path = matches.get_one::<String>("output-path").unwrap();
    
    // Convert min_lp_tokens to u64
    let min_lp_tokens_u64 = min_lp_tokens.parse::<u64>()
        .map_err(|_| wire_lib::errors::WireError::GenericError("Invalid min LP tokens".to_string()))?;
    
    // Call the add_liquidity function
    add_liquidity(input_utxo_a, input_utxo_b, pool_id, min_lp_tokens_u64, output_path)
        .map_err(|e| wire_lib::errors::WireError::GenericError(e))
}

/// Execute the remove liquidity command
pub fn execute_remove_liquidity_command(matches: &clap::ArgMatches) -> wire_lib::errors::WireResult<()> {
    let lp_share = matches.get_one::<String>("lp-share").unwrap();
    let pool_id = matches.get_one::<String>("pool-id").unwrap();
    let min_amount_a = matches.get_one::<String>("min-amount-a").unwrap();
    let min_amount_b = matches.get_one::<String>("min-amount-b").unwrap();
    let output_path = matches.get_one::<String>("output-path").unwrap();
    
    // Convert min amounts to u64
    let min_amount_a_u64 = min_amount_a.parse::<u64>()
        .map_err(|_| wire_lib::errors::WireError::GenericError("Invalid min amount A".to_string()))?;
    let min_amount_b_u64 = min_amount_b.parse::<u64>()
        .map_err(|_| wire_lib::errors::WireError::GenericError("Invalid min amount B".to_string()))?;
    
    // Call the remove_liquidity function
    remove_liquidity(lp_share, pool_id, min_amount_a_u64, min_amount_b_u64, output_path)
        .map_err(|e| wire_lib::errors::WireError::GenericError(e))
}
