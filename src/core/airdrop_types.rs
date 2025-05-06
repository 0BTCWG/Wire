// Airdrop Types for the 0BTC Wire system
// This file defines the core types for the Airdrop mechanism

use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::core::{HASH_SIZE, UTXOTarget};
use crate::utils::hash::compute_hash_targets;

/// Airdrop leaf data target for use in circuits
#[derive(Clone)]
pub struct AirdropLeafDataTarget {
    /// The recipient's public key hash
    pub recipient_pubkey_hash: Vec<Target>,
    
    /// The token amount to be claimed
    pub token_amount: Target,
    
    /// A random salt to prevent correlation of leaf indices with recipient identities
    pub salt: Target,
}

/// Airdrop leaf data struct for native Rust code
#[derive(Debug, Clone)]
pub struct AirdropLeafData {
    /// The recipient's public key hash
    pub recipient_pubkey_hash: [u8; HASH_SIZE],
    
    /// The token amount to be claimed
    pub token_amount: u64,
    
    /// A random salt to prevent correlation of leaf indices with recipient identities
    pub salt: u64,
}

impl AirdropLeafDataTarget {
    /// Create a new AirdropLeafDataTarget with virtual targets
    pub fn add_virtual<F: RichField, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        Self {
            recipient_pubkey_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            token_amount: builder.add_virtual_target(),
            salt: builder.add_virtual_target(),
        }
    }
    
    /// Compute the hash of the leaf data
    pub fn compute_hash<F: RichField, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut hash_inputs = Vec::new();
        
        // Add all leaf data to the hash inputs
        hash_inputs.extend_from_slice(&self.recipient_pubkey_hash);
        hash_inputs.push(self.token_amount);
        hash_inputs.push(self.salt);
        
        compute_hash_targets(builder, &hash_inputs)
    }
}

/// Airdrop parameters target for use in circuits
#[derive(Clone)]
pub struct AirdropParametersTarget {
    /// The creator's public key hash
    pub creator_pubkey_hash: Vec<Target>,
    
    /// The token asset ID being airdropped
    pub token_asset_id: Vec<Target>,
    
    /// The total supply of tokens being airdropped
    pub token_supply: Target,
    
    /// The Merkle root of the airdrop recipients tree
    pub merkle_root: Vec<Target>,
    
    /// The start timestamp of the airdrop
    pub start_timestamp: Target,
    
    /// The end timestamp of the airdrop
    pub end_timestamp: Target,
}

/// Airdrop parameters struct for native Rust code
#[derive(Debug, Clone)]
pub struct AirdropParameters {
    /// The creator's public key hash
    pub creator_pubkey_hash: [u8; HASH_SIZE],
    
    /// The token asset ID being airdropped
    pub token_asset_id: [u8; HASH_SIZE],
    
    /// The total supply of tokens being airdropped
    pub token_supply: u64,
    
    /// The Merkle root of the airdrop recipients tree
    pub merkle_root: [u8; HASH_SIZE],
    
    /// The start timestamp of the airdrop
    pub start_timestamp: u64,
    
    /// The end timestamp of the airdrop
    pub end_timestamp: u64,
}

impl AirdropParametersTarget {
    /// Create a new AirdropParametersTarget with virtual targets
    pub fn add_virtual<F: RichField, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        Self {
            creator_pubkey_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            token_asset_id: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            token_supply: builder.add_virtual_target(),
            merkle_root: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            start_timestamp: builder.add_virtual_target(),
            end_timestamp: builder.add_virtual_target(),
        }
    }
    
    /// Compute the hash of the airdrop parameters
    pub fn compute_hash<F: RichField, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut hash_inputs = Vec::new();
        
        // Add all parameters to the hash inputs
        hash_inputs.extend_from_slice(&self.creator_pubkey_hash);
        hash_inputs.extend_from_slice(&self.token_asset_id);
        hash_inputs.push(self.token_supply);
        hash_inputs.extend_from_slice(&self.merkle_root);
        hash_inputs.push(self.start_timestamp);
        hash_inputs.push(self.end_timestamp);
        
        compute_hash_targets(builder, &hash_inputs)
    }
}

/// Merkle proof target for use in circuits
#[derive(Clone)]
pub struct MerkleProofTarget {
    /// The leaf index (position in the tree)
    pub leaf_index: Target,
    
    /// The sibling nodes along the path from leaf to root
    pub siblings: Vec<Vec<Target>>,
}

/// Merkle proof struct for native Rust code
#[derive(Debug, Clone)]
pub struct MerkleProof {
    /// The leaf index (position in the tree)
    pub leaf_index: u64,
    
    /// The sibling nodes along the path from leaf to root
    pub siblings: Vec<[u8; HASH_SIZE]>,
}

impl MerkleProofTarget {
    /// Create a new MerkleProofTarget with virtual targets
    pub fn add_virtual<F: RichField, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
        tree_depth: usize,
    ) -> Self {
        Self {
            leaf_index: builder.add_virtual_target(),
            siblings: (0..tree_depth)
                .map(|_| (0..hash_size).map(|_| builder.add_virtual_target()).collect())
                .collect(),
        }
    }
    
    /// Verify a Merkle proof
    pub fn verify<F: RichField, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        leaf_hash: Vec<Target>,
        merkle_root: &[Target],
    ) -> Target {
        let one = builder.one();
        let zero = builder.zero();
        
        // Start with the leaf hash
        let mut current_hash = leaf_hash;
        
        // Convert leaf_index to binary
        let mut leaf_index_bits = Vec::new();
        let mut temp_index = self.leaf_index;
        
        for _ in 0..self.siblings.len() {
            // Get the least significant bit
            let bit = builder.add_virtual_bool_target_safe();
            
            // Connect the bit to the result of leaf_index % 2
            let bit_target = builder.select(bit, one, zero);
            let index_mod_2 = builder.add_virtual_target();
            builder.connect(index_mod_2, temp_index);
            
            // Shift right by 1 (divide by 2)
            temp_index = builder.div_const(temp_index, F::from_canonical_u64(2));
            
            leaf_index_bits.push(bit);
        }
        
        // Compute the path from leaf to root
        for (i, sibling) in self.siblings.iter().enumerate() {
            // Determine if the current node is a left or right child
            let is_right = leaf_index_bits[i];
            
            // Create a new hash based on the position (left or right)
            let mut combined_hash_inputs = Vec::new();
            
            // If is_right is true, sibling comes first, then current_hash
            // If is_right is false, current_hash comes first, then sibling
            let left_hash = builder.select_vec(is_right, sibling, &current_hash);
            let right_hash = builder.select_vec(is_right, &current_hash, sibling);
            
            combined_hash_inputs.extend_from_slice(&left_hash);
            combined_hash_inputs.extend_from_slice(&right_hash);
            
            // Hash the combined inputs
            current_hash = compute_hash_targets(builder, &combined_hash_inputs);
        }
        
        // Check if the computed root matches the expected root
        let mut root_match = builder.one();
        for (computed, expected) in current_hash.iter().zip(merkle_root.iter()) {
            let hash_match = builder.is_equal(*computed, *expected);
            root_match = builder.and(root_match, hash_match);
        }
        
        root_match
    }
}

/// Airdrop claim nullifier target for use in circuits
#[derive(Clone)]
pub struct AirdropClaimNullifierTarget {
    /// The airdrop parameters hash
    pub airdrop_parameters_hash: Vec<Target>,
    
    /// The recipient's public key hash
    pub recipient_pubkey_hash: Vec<Target>,
}

impl AirdropClaimNullifierTarget {
    /// Create a new AirdropClaimNullifierTarget with virtual targets
    pub fn add_virtual<F: RichField, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        Self {
            airdrop_parameters_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
            recipient_pubkey_hash: (0..hash_size).map(|_| builder.add_virtual_target()).collect(),
        }
    }
    
    /// Compute the nullifier hash
    pub fn compute_hash<F: RichField, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let mut hash_inputs = Vec::new();
        
        // Add all nullifier data to the hash inputs
        hash_inputs.extend_from_slice(&self.airdrop_parameters_hash);
        hash_inputs.extend_from_slice(&self.recipient_pubkey_hash);
        
        compute_hash_targets(builder, &hash_inputs)
    }
}
