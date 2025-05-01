// Fee enforcement gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::iop::target::BoolTarget;

use crate::core::{PublicKeyTarget, UTXOTarget, SignatureTarget};
use crate::errors::{ValidationError, WireError, WireResult};
use crate::gadgets::hash::hash_utxo_commitment;
use crate::utils::nullifier::compute_utxo_commitment_hash as nullifier_hash_utxo_target;

/// Represents a signed fee quote from the custodian
#[derive(Debug, Clone)]
pub struct SignedQuoteTarget {
    /// The fee amount in BTC
    pub fee_btc: Target,
    
    /// The quote expiry timestamp
    pub expiry: Target,
    
    /// The custodian's signature
    pub signature: SignatureTarget,
}

/// Enforce fee payment for a transaction
///
/// This gadget verifies that:
/// 1. The fee payer owns the input UTXO (by verifying their signature)
/// 2. The input UTXO has enough funds to pay the fee
/// 3. The input UTXO is of the correct asset type (wBTC)
/// 4. The fee is sent to the reservoir address
///
/// Returns the change amount for the fee payer and the fee UTXO
pub fn enforce_fee_payment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_payer_pk: &PublicKeyTarget,
    input_wbtc_utxo: &UTXOTarget,
    fee_amount: Target,
    reservoir_address_hash: &[Target],
    signature: &SignatureTarget,
    expected_asset_id: &[Target],
) -> (Target, UTXOTarget) {
    // Verify that the input UTXO is owned by the fee payer
    // Convert the UTXO target first
    let converted_utxo = convert_utxo_target(input_wbtc_utxo);
    let message_hash = nullifier_hash_utxo_target(builder, &converted_utxo);
    
    // Verify the signature
    let is_valid = crate::utils::signature::verify_signature_in_circuit_with_targets(
        builder,
        fee_payer_pk,
        message_hash,
        signature,
    );
    
    // Ensure the signature is valid
    builder.assert_one(is_valid.target);
    
    // Verify that the input UTXO asset ID matches the expected asset ID (wBTC)
    for i in 0..expected_asset_id.len() {
        let is_equal = builder.is_equal(
            input_wbtc_utxo.asset_id_target[i],
            expected_asset_id[i],
        );
        builder.assert_one(is_equal.target);
    }
    
    // Verify that the input UTXO has enough funds to pay the fee
    let input_amount = input_wbtc_utxo.amount_target;
    
    // Get zero target
    let zero_target = builder.zero();
    
    // Check if fee_amount <= input_amount (sufficient funds)
    let fee_lte_input = validate_fee_amount(builder, fee_amount, zero_target, input_amount);
    builder.assert_one(fee_lte_input);
    
    // Calculate the change amount
    let change_amount = builder.sub(input_amount, fee_amount);
    
    // Create the fee UTXO
    let fee_utxo = UTXOTarget {
        owner_pubkey_hash_target: reservoir_address_hash.to_vec(),
        asset_id_target: expected_asset_id.to_vec(),
        amount_target: fee_amount,
        salt_target: vec![zero_target], // Use a deterministic salt for fee UTXOs
    };
    
    (change_amount, fee_utxo)
}

/// Enforce fee payment with a change UTXO
///
/// This gadget verifies fee payment and creates a change UTXO for the fee payer
/// Returns the change UTXO
pub fn enforce_fee_payment_with_change<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_payer_pk: &PublicKeyTarget,
    input_wbtc_utxo: &UTXOTarget,
    fee_amount: Target,
    reservoir_address_hash: &[Target],
    signature: &SignatureTarget,
    expected_asset_id: &[Target],
    change_salt: &[Target],
) -> UTXOTarget {
    // First enforce the fee payment
    let (change_amount, _) = enforce_fee_payment(
        builder,
        fee_payer_pk,
        input_wbtc_utxo,
        fee_amount,
        reservoir_address_hash,
        signature,
        expected_asset_id,
    );
    
    // Create the change UTXO
    let change_utxo = UTXOTarget {
        owner_pubkey_hash_target: input_wbtc_utxo.owner_pubkey_hash_target.clone(),
        asset_id_target: input_wbtc_utxo.asset_id_target.clone(),
        amount_target: change_amount,
        salt_target: change_salt.to_vec(),
    };
    
    // Calculate and register the change UTXO hash
    let change_utxo_hash_result = hash_utxo_commitment(
        builder,
        &change_utxo.owner_pubkey_hash_target,
        &change_utxo.asset_id_target,
        change_utxo.amount_target,
        &change_utxo.salt_target,
    );
    
    // Register the change UTXO hash as a public input if available
    if let Ok(hash_targets) = change_utxo_hash_result {
        for target in hash_targets {
            builder.register_public_input(target);
        }
    }
    
    change_utxo
}

/// Convert a core::UTXOTarget to a utils::nullifier::UTXOTarget
pub fn convert_utxo_target(utxo: &crate::core::UTXOTarget) -> crate::utils::nullifier::UTXOTarget {
    // Extract the first element of each vector, or panic if empty
    let owner_pubkey_hash = utxo.owner_pubkey_hash_target.get(0).copied().unwrap_or_else(|| panic!("Owner pubkey hash is empty"));
    let asset_id = utxo.asset_id_target.get(0).copied().unwrap_or_else(|| panic!("Asset ID is empty"));
    let amount = utxo.amount_target;
    let salt = utxo.salt_target.get(0).copied().unwrap_or_else(|| panic!("Salt is empty"));
    
    // Create a new UTXOTarget for the nullifier module
    crate::utils::nullifier::UTXOTarget {
        owner_pubkey_hash_target: vec![owner_pubkey_hash],
        asset_id_target: vec![asset_id],
        amount_target: vec![amount],
        salt_target: vec![salt],
    }
}

/// Validate a fee amount
///
/// This gadget validates that a fee amount is within acceptable bounds
pub fn validate_fee_amount<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_amount: Target,
    min_fee: Target,
    max_fee: Target,
) -> Target {
    // Check if fee_amount >= min_fee
    let min_diff = builder.sub(fee_amount, min_fee);
    let min_bits = builder.split_le(min_diff, 64);
    // If the sign bit is 0, then fee_amount >= min_fee
    // The sign bit is at index 63
    // The bits from split_le are already BoolTargets
    let sign_bit_min = min_bits[63];
    // We need to negate the sign bit (if sign bit is 0, then value is non-negative)
    let is_above_min = builder.not(sign_bit_min);
    
    // Check if fee_amount <= max_fee
    let max_diff = builder.sub(max_fee, fee_amount);
    let max_bits = builder.split_le(max_diff, 64);
    // If the sign bit is 0, then fee_amount <= max_fee
    let sign_bit_max = max_bits[63];
    // We need to negate the sign bit (if sign bit is 0, then value is non-negative)
    let is_below_max = builder.not(sign_bit_max);
    
    // Both conditions must be true
    let is_valid = builder.and(is_above_min, is_below_max);
    
    is_valid.target
}

/// Verify that a fee payment is valid
///
/// This function verifies that:
/// 1. The fee amount is at least the minimum required fee
/// 2. The fee is paid in the correct asset type
/// 3. The fee is sent to the correct reservoir address
///
/// Returns a boolean target indicating whether the fee payment is valid
pub fn verify_fee_payment<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    fee_amount: Target,
    min_required_fee: Target,
    fee_asset_id: Target,
    expected_asset_id: Target,
    fee_recipient: Target,
    expected_recipient: Target,
) -> Target {
    // Check if the fee is sufficient
    // We can implement this as !(min_required_fee > fee_amount)
    let min_diff = builder.sub(fee_amount, min_required_fee);
    let min_bits = builder.split_le(min_diff, 64);
    let fee_sufficient = builder.not(min_bits[63]);
    
    // Check if the asset ID is correct
    let correct_asset = builder.is_equal(fee_asset_id, expected_asset_id);
    
    // Check if the recipient is correct
    let correct_recipient = builder.is_equal(fee_recipient, expected_recipient);
    
    // All conditions must be true
    let asset_and_recipient = builder.and(correct_asset, correct_recipient);
    
    // Convert BoolTarget to Target for the final result
    let result = builder.and(fee_sufficient, asset_and_recipient);
    result.target
}

/// Calculate the fee for a transaction
///
/// This function calculates the fee for a transaction based on:
/// 1. The base fee
/// 2. The transaction size
/// 3. The current network congestion
///
/// Returns the calculated fee amount
pub fn calculate_fee<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    base_fee: Target,
    tx_size: Target,
    congestion_factor: Target,
) -> Target {
    // Calculate the size component: tx_size * size_multiplier
    let size_multiplier = builder.constant(F::from_canonical_u64(10)); // 10 satoshis per byte
    let size_component = builder.mul(tx_size, size_multiplier);
    
    // Calculate the congestion component: base_fee * congestion_factor
    let congestion_component = builder.mul(base_fee, congestion_factor);
    
    // Total fee = base_fee + size_component + congestion_component
    let temp_sum = builder.add(base_fee, size_component);
    builder.add(temp_sum, congestion_component)
}
