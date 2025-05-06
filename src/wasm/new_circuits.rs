// WASM bindings for the new circuits in the 0BTC Wire system
// This file provides WASM bindings for the AMM, Stablecoin V2, ICO, and Airdrop circuits

use wasm_bindgen::prelude::*;
use serde::{Deserialize, Serialize};

use crate::circuits::swap::SwapCircuit;
use crate::circuits::stablecoin_mint_v2::StablecoinMintV2Circuit;
use crate::circuits::stablecoin_redeem_v2::StablecoinRedeemV2Circuit;
use crate::circuits::liquidation::LiquidationCircuit;
use crate::circuits::ico_config::ICOConfigCircuit;
use crate::circuits::ico_contribute::ICOContributeCircuit;
use crate::circuits::ico_success_settle::ICOSuccessSettleCircuit;
use crate::circuits::ico_failure_refund::ICOFailureRefundCircuit;
use crate::circuits::airdrop_lock::AirdropLockCircuit;
use crate::circuits::airdrop_claim::AirdropClaimCircuit;
use crate::core::proof::SerializableProof;
use crate::errors::WireResult;

// ===== AMM Circuit WASM Bindings =====

/// Input parameters for the swap proof generation
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct SwapProofInput {
    /// The input UTXO owner's public key hash
    pub input_utxo_owner_pubkey_hash: Vec<u8>,
    /// The input UTXO amount
    pub input_utxo_amount: u64,
    /// The input UTXO asset ID
    pub input_utxo_asset_id: Vec<u8>,
    /// The input UTXO owner
    pub input_utxo_owner: Vec<u8>,
    /// The input UTXO salt
    pub input_utxo_salt: Vec<u8>,
    /// The token A ID
    pub token_a_id: Vec<u8>,
    /// The token B ID
    pub token_b_id: Vec<u8>,
    /// The reserve A amount
    pub reserve_a: u64,
    /// The reserve B amount
    pub reserve_b: u64,
    /// The output asset ID
    pub output_asset_id: Vec<u8>,
    /// The minimum output amount
    pub min_output_amount: u64,
    /// The user's public key X coordinate
    pub user_pk_x: u64,
    /// The user's public key Y coordinate
    pub user_pk_y: u64,
    /// The signature R point X coordinate
    pub signature_r_x: u64,
    /// The signature R point Y coordinate
    pub signature_r_y: u64,
    /// The signature scalar S
    pub signature_s: u64,
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<u8>,
}

/// Generate a swap proof with LP fees and protocol fees
#[wasm_bindgen]
pub fn generate_swap_proof(input: JsValue) -> Result<String, JsValue> {
    let input: SwapProofInput = input.into_serde().map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let result = SwapCircuit::generate_proof(
        &input.input_utxo_owner_pubkey_hash,
        input.input_utxo_amount,
        &input.input_utxo_asset_id,
        &input.input_utxo_owner,
        &input.input_utxo_salt,
        &input.token_a_id,
        &input.token_b_id,
        input.reserve_a,
        input.reserve_b,
        &input.output_asset_id,
        input.min_output_amount,
        input.user_pk_x,
        input.user_pk_y,
        input.signature_r_x,
        input.signature_r_y,
        input.signature_s,
        &input.fee_reservoir_address_hash,
    ).map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let serialized = serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

/// Verify a swap proof
#[wasm_bindgen]
pub fn verify_swap_proof(proof_str: String) -> Result<bool, JsValue> {
    let proof: SerializableProof = serde_json::from_str(&proof_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    let result = SwapCircuit::verify_proof(&proof)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    Ok(result)
}

// ===== Stablecoin V2 Circuit WASM Bindings =====

/// Input parameters for the stablecoin mint v2 proof generation
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct StablecoinMintV2ProofInput {
    /// The wBTC input UTXO hash
    pub wbtc_input_utxo_hash: Vec<u8>,
    /// The wBTC input UTXO amount
    pub wbtc_input_utxo_amount: u64,
    /// The wBTC input UTXO asset ID
    pub wbtc_input_utxo_asset_id: Vec<u8>,
    /// The wBTC input UTXO owner
    pub wbtc_input_utxo_owner: Vec<u8>,
    
    /// The ZERO input UTXO hash
    pub zero_input_utxo_hash: Vec<u8>,
    /// The ZERO input UTXO amount
    pub zero_input_utxo_amount: u64,
    /// The ZERO input UTXO asset ID
    pub zero_input_utxo_asset_id: Vec<u8>,
    /// The ZERO input UTXO owner
    pub zero_input_utxo_owner: Vec<u8>,
    
    /// The zUSD amount to mint
    pub zusd_amount: u64,
    /// The BTC/USD price
    pub btc_usd_price: u64,
    /// The ZERO/USD price
    pub zero_usd_price: u64,
    /// The price attestation timestamp
    pub price_timestamp: u64,
    
    /// The MPC public key X coordinate
    pub mpc_pk_x: u64,
    /// The MPC public key Y coordinate
    pub mpc_pk_y: u64,
    
    /// The MPC signature R point X coordinate
    pub mpc_signature_r_x: u64,
    /// The MPC signature R point Y coordinate
    pub mpc_signature_r_y: u64,
    /// The MPC signature scalar S
    pub mpc_signature_s: u64,
    
    /// The user's public key X coordinate
    pub user_pk_x: u64,
    /// The user's public key Y coordinate
    pub user_pk_y: u64,
    
    /// The user's signature R point X coordinate
    pub user_signature_r_x: u64,
    /// The user's signature R point Y coordinate
    pub user_signature_r_y: u64,
    /// The user's signature scalar S
    pub user_signature_s: u64,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<u8>,
    
    /// The current timestamp
    pub current_timestamp: u64,
}

/// Generate a stablecoin mint v2 proof
#[wasm_bindgen]
pub fn generate_stablecoin_mint_v2_proof(input: JsValue) -> Result<String, JsValue> {
    let input: StablecoinMintV2ProofInput = input.into_serde().map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof generation
    // This is a placeholder for the actual implementation
    let result = SerializableProof {
        proof: vec![0u8; 32],
        public_inputs: vec![0u8; 32],
    };
    
    let serialized = serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

/// Verify a stablecoin mint v2 proof
#[wasm_bindgen]
pub fn verify_stablecoin_mint_v2_proof(proof_str: String) -> Result<bool, JsValue> {
    let proof: SerializableProof = serde_json::from_str(&proof_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof verification
    // This is a placeholder for the actual implementation
    Ok(true)
}

/// Input parameters for the stablecoin redeem v2 proof generation
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct StablecoinRedeemV2ProofInput {
    /// The zUSD input UTXO hash
    pub zusd_input_utxo_hash: Vec<u8>,
    /// The zUSD input UTXO amount
    pub zusd_input_utxo_amount: u64,
    /// The zUSD input UTXO asset ID
    pub zusd_input_utxo_asset_id: Vec<u8>,
    /// The zUSD input UTXO owner
    pub zusd_input_utxo_owner: Vec<u8>,
    
    /// The BTC/USD price
    pub btc_usd_price: u64,
    /// The ZERO/USD price
    pub zero_usd_price: u64,
    /// The price attestation timestamp
    pub price_timestamp: u64,
    
    /// The redemption approval timestamp
    pub approval_timestamp: u64,
    /// The redemption approval zUSD amount
    pub approval_zusd_amount: u64,
    /// The redemption approval issuance ID
    pub approval_issuance_id: Vec<u8>,
    
    /// The MPC public key X coordinate
    pub mpc_pk_x: u64,
    /// The MPC public key Y coordinate
    pub mpc_pk_y: u64,
    
    /// The MPC price signature R point X coordinate
    pub mpc_price_signature_r_x: u64,
    /// The MPC price signature R point Y coordinate
    pub mpc_price_signature_r_y: u64,
    /// The MPC price signature scalar S
    pub mpc_price_signature_s: u64,
    
    /// The MPC approval signature R point X coordinate
    pub mpc_approval_signature_r_x: u64,
    /// The MPC approval signature R point Y coordinate
    pub mpc_approval_signature_r_y: u64,
    /// The MPC approval signature scalar S
    pub mpc_approval_signature_s: u64,
    
    /// The user's public key X coordinate
    pub user_pk_x: u64,
    /// The user's public key Y coordinate
    pub user_pk_y: u64,
    
    /// The user's signature R point X coordinate
    pub user_signature_r_x: u64,
    /// The user's signature R point Y coordinate
    pub user_signature_r_y: u64,
    /// The user's signature scalar S
    pub user_signature_s: u64,
    
    /// The fee reservoir address hash
    pub fee_reservoir_address_hash: Vec<u8>,
    
    /// The current timestamp
    pub current_timestamp: u64,
}

/// Generate a stablecoin redeem v2 proof
#[wasm_bindgen]
pub fn generate_stablecoin_redeem_v2_proof(input: JsValue) -> Result<String, JsValue> {
    let input: StablecoinRedeemV2ProofInput = input.into_serde().map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof generation
    // This is a placeholder for the actual implementation
    let result = SerializableProof {
        proof: vec![0u8; 32],
        public_inputs: vec![0u8; 32],
    };
    
    let serialized = serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

/// Verify a stablecoin redeem v2 proof
#[wasm_bindgen]
pub fn verify_stablecoin_redeem_v2_proof(proof_str: String) -> Result<bool, JsValue> {
    let proof: SerializableProof = serde_json::from_str(&proof_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof verification
    // This is a placeholder for the actual implementation
    Ok(true)
}

// ===== ICO Circuit WASM Bindings =====

/// Input parameters for the ICO contribute proof generation
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct ICOContributeProofInput {
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<u8>,
    
    /// The payment UTXO hash
    pub payment_utxo_hash: Vec<u8>,
    /// The payment UTXO amount
    pub payment_utxo_amount: u64,
    /// The payment UTXO asset ID
    pub payment_utxo_asset_id: Vec<u8>,
    /// The payment UTXO owner
    pub payment_utxo_owner: Vec<u8>,
    
    /// The contribution amount
    pub contribution_amount: u64,
    
    /// The contributor's public key X coordinate
    pub contributor_pk_x: u64,
    /// The contributor's public key Y coordinate
    pub contributor_pk_y: u64,
    
    /// The contributor's signature R point X coordinate
    pub contributor_signature_r_x: u64,
    /// The contributor's signature R point Y coordinate
    pub contributor_signature_r_y: u64,
    /// The contributor's signature scalar S
    pub contributor_signature_s: u64,
    
    /// The current timestamp
    pub current_timestamp: u64,
}

/// Generate an ICO contribute proof
#[wasm_bindgen]
pub fn generate_ico_contribute_proof(input: JsValue) -> Result<String, JsValue> {
    let input: ICOContributeProofInput = input.into_serde().map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof generation
    // This is a placeholder for the actual implementation
    let result = SerializableProof {
        proof: vec![0u8; 32],
        public_inputs: vec![0u8; 32],
    };
    
    let serialized = serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

/// Verify an ICO contribute proof
#[wasm_bindgen]
pub fn verify_ico_contribute_proof(proof_str: String) -> Result<bool, JsValue> {
    let proof: SerializableProof = serde_json::from_str(&proof_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof verification
    // This is a placeholder for the actual implementation
    Ok(true)
}

// ===== Airdrop Circuit WASM Bindings =====

/// Input parameters for the airdrop claim proof generation
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct AirdropClaimProofInput {
    /// The airdrop parameters hash
    pub airdrop_parameters_hash: Vec<u8>,
    
    /// The recipient's public key hash
    pub recipient_pubkey_hash: Vec<u8>,
    /// The token amount to claim
    pub token_amount: u64,
    /// The leaf salt
    pub leaf_salt: u64,
    
    /// The Merkle proof leaf index
    pub leaf_index: u64,
    /// The Merkle proof siblings
    pub siblings: Vec<Vec<u8>>,
    
    /// The recipient's public key X coordinate
    pub recipient_pk_x: u64,
    /// The recipient's public key Y coordinate
    pub recipient_pk_y: u64,
    
    /// The recipient's signature R point X coordinate
    pub recipient_signature_r_x: u64,
    /// The recipient's signature R point Y coordinate
    pub recipient_signature_r_y: u64,
    /// The recipient's signature scalar S
    pub recipient_signature_s: u64,
    
    /// The current timestamp
    pub current_timestamp: u64,
}

/// Generate an airdrop claim proof
#[wasm_bindgen]
pub fn generate_airdrop_claim_proof(input: JsValue) -> Result<String, JsValue> {
    let input: AirdropClaimProofInput = input.into_serde().map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof generation
    // This is a placeholder for the actual implementation
    let result = SerializableProof {
        proof: vec![0u8; 32],
        public_inputs: vec![0u8; 32],
    };
    
    let serialized = serde_json::to_string(&result).map_err(|e| JsValue::from_str(&e.to_string()))?;
    Ok(serialized)
}

/// Verify an airdrop claim proof
#[wasm_bindgen]
pub fn verify_airdrop_claim_proof(proof_str: String) -> Result<bool, JsValue> {
    let proof: SerializableProof = serde_json::from_str(&proof_str)
        .map_err(|e| JsValue::from_str(&e.to_string()))?;
    
    // TODO: Implement the actual proof verification
    // This is a placeholder for the actual implementation
    Ok(true)
}
