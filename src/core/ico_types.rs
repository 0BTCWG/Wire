// ICO Types for the 0BTC Wire system
// This file defines the core types for the ICO mechanism

use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{HASH_SIZE, UTXOTarget};
use crate::utils::hash::compute_hash_targets;

/// ICO status enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ICOStatus {
    /// ICO is active and accepting contributions
    Active = 0,
    /// ICO has ended successfully (reached minimum funding goal)
    Successful = 1,
    /// ICO has failed (didn't reach minimum funding goal by deadline)
    Failed = 2,
    /// ICO has been canceled by the creator
    Canceled = 3,
}

/// ICO parameters target for use in circuits
#[derive(Clone)]
pub struct ICOParametersTarget {
    /// The creator's public key hash
    pub creator_pubkey_hash: Vec<Target>,
    
    /// The token asset ID being sold in the ICO
    pub token_asset_id: Vec<Target>,
    
    /// The payment asset ID accepted for contributions (e.g., wBTC)
    pub payment_asset_id: Vec<Target>,
    
    /// The total supply of tokens being sold
    pub token_supply: Target,
    
    /// The price per token in payment asset units
    pub price_per_token: Target,
    
    /// The minimum funding goal (in payment asset units)
    pub min_funding_goal: Target,
    
    /// The maximum funding cap (in payment asset units)
    pub max_funding_cap: Target,
    
    /// The start timestamp of the ICO
    pub start_timestamp: Target,
    
    /// The end timestamp of the ICO
    pub end_timestamp: Target,
    
    /// The protocol fee percentage (e.g., 1% = 10000)
    pub fee_percentage: Target,
}

/// ICO parameters struct for native Rust code
#[derive(Debug, Clone)]
pub struct ICOParameters {
    /// The creator's public key hash
    pub creator_pubkey_hash: [u8; HASH_SIZE],
    
    /// The token asset ID being sold in the ICO
    pub token_asset_id: [u8; HASH_SIZE],
    
    /// The payment asset ID accepted for contributions (e.g., wBTC)
    pub payment_asset_id: [u8; HASH_SIZE],
    
    /// The total supply of tokens being sold
    pub token_supply: u64,
    
    /// The price per token in payment asset units
    pub price_per_token: u64,
    
    /// The minimum funding goal (in payment asset units)
    pub min_funding_goal: u64,
    
    /// The maximum funding cap (in payment asset units)
    pub max_funding_cap: u64,
    
    /// The start timestamp of the ICO
    pub start_timestamp: u64,
    
    /// The end timestamp of the ICO
    pub end_timestamp: u64,
    
    /// The protocol fee percentage (e.g., 1% = 10000)
    pub fee_percentage: u64,
}

impl ICOParametersTarget {
    /// Create a new ICOParametersTarget with virtual targets
    pub fn add_virtual<F: RichField>(builder: &mut CircuitBuilder<F, D>, hash_size: usize) -> Self
    where
        F: RichField,
        D: usize,
    {
        Self {
            creator_pubkey_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            token_asset_id: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            payment_asset_id: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            token_supply: builder.add_virtual_target(),
            price_per_token: builder.add_virtual_target(),
            min_funding_goal: builder.add_virtual_target(),
            max_funding_cap: builder.add_virtual_target(),
            start_timestamp: builder.add_virtual_target(),
            end_timestamp: builder.add_virtual_target(),
            fee_percentage: builder.add_virtual_target(),
        }
    }
    
    /// Compute the hash of the ICO parameters
    pub fn compute_hash<F: RichField, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut hash_inputs = Vec::new();
        
        // Add all parameters to the hash inputs
        hash_inputs.extend_from_slice(&self.creator_pubkey_hash);
        hash_inputs.extend_from_slice(&self.token_asset_id);
        hash_inputs.extend_from_slice(&self.payment_asset_id);
        hash_inputs.push(self.token_supply);
        hash_inputs.push(self.price_per_token);
        hash_inputs.push(self.min_funding_goal);
        hash_inputs.push(self.max_funding_cap);
        hash_inputs.push(self.start_timestamp);
        hash_inputs.push(self.end_timestamp);
        hash_inputs.push(self.fee_percentage);
        
        compute_hash_targets(builder, &hash_inputs)
    }
}

/// ICO contribution target for use in circuits
#[derive(Clone)]
pub struct ICOContributionTarget {
    /// The contributor's public key hash
    pub contributor_pubkey_hash: Vec<Target>,
    
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The contribution amount in payment asset units
    pub contribution_amount: Target,
    
    /// The timestamp of the contribution
    pub timestamp: Target,
}

/// ICO settlement attestation target for use in circuits
#[derive(Clone)]
pub struct ICOSettlementAttestationTarget {
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The ICO status (0 = Active, 1 = Successful, 2 = Failed, 3 = Canceled)
    pub ico_status: Target,
    
    /// The total amount raised in payment asset units
    pub total_raised: Target,
    
    /// The timestamp of the settlement
    pub timestamp: Target,
    
    /// The MPC operators' signature
    pub signature: Target,
}

/// ICO escrow UTXO metadata target for use in circuits
#[derive(Clone)]
pub struct ICOEscrowMetadataTarget {
    /// The ICO parameters hash
    pub ico_parameters_hash: Vec<Target>,
    
    /// The contributor's public key hash
    pub contributor_pubkey_hash: Vec<Target>,
    
    /// The contribution amount in payment asset units
    pub contribution_amount: Target,
    
    /// The timestamp of the contribution
    pub timestamp: Target,
}

/// ICO escrow UTXO with metadata for tracking contributions
#[derive(Clone)]
pub struct ICOEscrowUTXOTarget {
    /// The base UTXO
    pub utxo: UTXOTarget,
    
    /// The ICO escrow metadata
    pub metadata: ICOEscrowMetadataTarget,
}

impl ICOEscrowUTXOTarget {
    /// Create a new ICOEscrowUTXOTarget with virtual targets
    pub fn add_virtual<F: RichField, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        Self {
            utxo: UTXOTarget::add_virtual(builder, hash_size),
            metadata: ICOEscrowMetadataTarget {
                ico_parameters_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
                contributor_pubkey_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
                contribution_amount: builder.add_virtual_target(),
                timestamp: builder.add_virtual_target(),
            },
        }
    }
}

/// Protocol fee percentage (1%)
pub const ICO_PROTOCOL_FEE_PERCENTAGE: u64 = 10000; // 1% = 10000 / 1_000_000
