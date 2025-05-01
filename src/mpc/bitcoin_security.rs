// Bitcoin Security for MPC
//
// This module provides security enhancements for Bitcoin integration,
// including fork detection and double-spend protection.

use crate::mpc::{MPCError, MPCResult};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bitcoin node information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitcoinNode {
    /// Node URL
    pub url: String,
    
    /// Node type (e.g., "bitcoind", "btcd")
    pub node_type: String,
    
    /// Last check timestamp
    pub last_check: u64,
    
    /// Is the node responsive
    pub is_responsive: bool,
}

/// Bitcoin block information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockInfo {
    /// Block hash
    pub hash: String,
    
    /// Block height
    pub height: u64,
    
    /// Block timestamp
    pub timestamp: u64,
    
    /// Number of confirmations
    pub confirmations: u64,
    
    /// Previous block hash
    pub prev_block_hash: String,
}

/// Fork detection status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkStatus {
    /// No fork detected
    NoFork,
    
    /// Potential fork detected
    PotentialFork,
    
    /// Confirmed fork
    ConfirmedFork,
}

/// Fork detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkDetectionResult {
    /// Fork status
    pub status: ForkStatus,
    
    /// Block height where the fork was detected
    pub fork_height: Option<u64>,
    
    /// Divergent block hashes at the fork height
    pub divergent_hashes: Option<Vec<String>>,
    
    /// Timestamp when the fork was detected
    pub detected_at: u64,
    
    /// Nodes reporting each hash
    pub nodes_per_hash: Option<HashMap<String, Vec<String>>>,
}

/// Transaction double-spend status
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DoubleSpendStatus {
    /// No double-spend detected
    NoDoubleSpend,
    
    /// Potential double-spend detected
    PotentialDoubleSpend,
    
    /// Confirmed double-spend
    ConfirmedDoubleSpend,
}

/// Double-spend detection result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoubleSpendResult {
    /// Double-spend status
    pub status: DoubleSpendStatus,
    
    /// Transaction ID
    pub txid: String,
    
    /// Conflicting transaction IDs
    pub conflicting_txids: Vec<String>,
    
    /// Timestamp when the double-spend was detected
    pub detected_at: u64,
}

/// Bitcoin security manager
pub struct BitcoinSecurityManager {
    /// Bitcoin nodes
    nodes: Vec<BitcoinNode>,
    
    /// Path to the security database
    db_path: String,
    
    /// Current fork detection result
    current_fork: Option<ForkDetectionResult>,
    
    /// Double-spend detections
    double_spends: HashMap<String, DoubleSpendResult>,
    
    /// Minimum number of nodes required for consensus
    min_consensus_nodes: usize,
    
    /// Normal confirmation threshold
    normal_confirmations: u64,
    
    /// Increased confirmation threshold during potential forks
    fork_confirmations: u64,
}

impl BitcoinSecurityManager {
    /// Create a new Bitcoin security manager
    pub fn new(
        nodes: Vec<BitcoinNode>,
        db_path: String,
        min_consensus_nodes: usize,
        normal_confirmations: u64,
        fork_confirmations: u64,
    ) -> MPCResult<Self> {
        if nodes.len() < min_consensus_nodes {
            return Err(MPCError::InternalError(format!(
                "Not enough Bitcoin nodes: {} provided, {} required for consensus",
                nodes.len(), min_consensus_nodes
            )));
        }
        
        let mut manager = Self {
            nodes,
            db_path,
            current_fork: None,
            double_spends: HashMap::new(),
            min_consensus_nodes,
            normal_confirmations,
            fork_confirmations,
        };
        
        // Load security database if it exists
        if Path::new(&db_path).exists() {
            manager.load_database()?;
        }
        
        Ok(manager)
    }
    
    /// Load the security database
    fn load_database(&mut self) -> MPCResult<()> {
        let data = fs::read(&self.db_path)
            .map_err(|e| MPCError::InternalError(format!("Failed to read security database: {}", e)))?;
        
        let db: SecurityDatabase = serde_json::from_slice(&data)
            .map_err(|e| MPCError::InternalError(format!("Failed to parse security database: {}", e)))?;
        
        self.current_fork = db.current_fork;
        self.double_spends = db.double_spends;
        
        Ok(())
    }
    
    /// Save the security database
    fn save_database(&self) -> MPCResult<()> {
        let db = SecurityDatabase {
            current_fork: self.current_fork.clone(),
            double_spends: self.double_spends.clone(),
        };
        
        let data = serde_json::to_vec(&db)
            .map_err(|e| MPCError::InternalError(format!("Failed to serialize security database: {}", e)))?;
        
        // Create parent directories if they don't exist
        if let Some(parent) = Path::new(&self.db_path).parent() {
            fs::create_dir_all(parent)
                .map_err(|e| MPCError::InternalError(format!("Failed to create directories: {}", e)))?;
        }
        
        fs::write(&self.db_path, data)
            .map_err(|e| MPCError::InternalError(format!("Failed to write security database: {}", e)))?;
        
        Ok(())
    }
    
    /// Check for Bitcoin network forks
    pub fn check_for_forks(&mut self) -> MPCResult<ForkDetectionResult> {
        // This is a placeholder implementation
        // In a real implementation, this would:
        // 1. Query all Bitcoin nodes for their current block hash at the same height
        // 2. Compare the block hashes
        // 3. If there are divergent hashes, detect a potential fork
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        // Get the current block height from all nodes
        let mut block_infos = Vec::new();
        let mut responsive_nodes = 0;
        
        for node in &mut self.nodes {
            // In a real implementation, this would query the Bitcoin node
            // For now, we'll just simulate a response
            
            // Simulate node response
            let is_responsive = true; // In a real implementation, this would be based on the actual response
            
            if is_responsive {
                responsive_nodes += 1;
                
                // Simulate block info
                let block_info = BlockInfo {
                    hash: format!("block-hash-{}", node.url),
                    height: 700_000, // Simulated block height
                    timestamp,
                    confirmations: 1,
                    prev_block_hash: "prev-block-hash".to_string(),
                };
                
                block_infos.push((node.url.clone(), block_info));
            }
            
            // Update node status
            node.last_check = timestamp;
            node.is_responsive = is_responsive;
        }
        
        // Check if we have enough responsive nodes
        if responsive_nodes < self.min_consensus_nodes {
            return Err(MPCError::InternalError(format!(
                "Not enough responsive Bitcoin nodes: {} responsive, {} required for consensus",
                responsive_nodes, self.min_consensus_nodes
            )));
        }
        
        // Check for divergent block hashes
        let mut hash_counts: HashMap<String, Vec<String>> = HashMap::new();
        
        for (node_url, block_info) in &block_infos {
            hash_counts
                .entry(block_info.hash.clone())
                .or_insert_with(Vec::new)
                .push(node_url.clone());
        }
        
        let fork_result = if hash_counts.len() > 1 {
            // Divergent block hashes detected
            let fork_height = block_infos.first().map(|(_, info)| info.height);
            let divergent_hashes = Some(hash_counts.keys().cloned().collect());
            
            ForkDetectionResult {
                status: ForkStatus::PotentialFork,
                fork_height,
                divergent_hashes,
                detected_at: timestamp,
                nodes_per_hash: Some(hash_counts),
            }
        } else {
            // No fork detected
            ForkDetectionResult {
                status: ForkStatus::NoFork,
                fork_height: None,
                divergent_hashes: None,
                detected_at: timestamp,
                nodes_per_hash: None,
            }
        };
        
        // Update the current fork status
        self.current_fork = Some(fork_result.clone());
        self.save_database()?;
        
        Ok(fork_result)
    }
    
    /// Get the required confirmation threshold based on the current fork status
    pub fn get_confirmation_threshold(&self) -> u64 {
        match &self.current_fork {
            Some(fork) if fork.status != ForkStatus::NoFork => self.fork_confirmations,
            _ => self.normal_confirmations,
        }
    }
    
    /// Check for double-spend attempts
    pub fn check_for_double_spend(&mut self, txid: &str) -> MPCResult<DoubleSpendResult> {
        // This is a placeholder implementation
        // In a real implementation, this would:
        // 1. Query all Bitcoin nodes for the transaction
        // 2. Check if there are conflicting transactions spending the same inputs
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        // For now, we'll just simulate no double-spend
        let result = DoubleSpendResult {
            status: DoubleSpendStatus::NoDoubleSpend,
            txid: txid.to_string(),
            conflicting_txids: Vec::new(),
            detected_at: timestamp,
        };
        
        // Store the result
        self.double_spends.insert(txid.to_string(), result.clone());
        self.save_database()?;
        
        Ok(result)
    }
    
    /// Get the current fork status
    pub fn get_current_fork_status(&self) -> ForkStatus {
        match &self.current_fork {
            Some(fork) => fork.status,
            None => ForkStatus::NoFork,
        }
    }
    
    /// Get the double-spend status for a transaction
    pub fn get_double_spend_status(&self, txid: &str) -> DoubleSpendStatus {
        match self.double_spends.get(txid) {
            Some(result) => result.status,
            None => DoubleSpendStatus::NoDoubleSpend,
        }
    }
    
    /// Add a Bitcoin node
    pub fn add_node(&mut self, url: &str, node_type: &str) -> MPCResult<()> {
        // Check if the node already exists
        if self.nodes.iter().any(|node| node.url == url) {
            return Err(MPCError::InternalError(format!("Node {} already exists", url)));
        }
        
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| MPCError::InternalError(format!("Failed to get timestamp: {}", e)))?
            .as_secs();
        
        let node = BitcoinNode {
            url: url.to_string(),
            node_type: node_type.to_string(),
            last_check: timestamp,
            is_responsive: false,
        };
        
        self.nodes.push(node);
        
        Ok(())
    }
    
    /// Remove a Bitcoin node
    pub fn remove_node(&mut self, url: &str) -> MPCResult<bool> {
        let initial_len = self.nodes.len();
        self.nodes.retain(|node| node.url != url);
        
        let removed = self.nodes.len() < initial_len;
        
        if removed && self.nodes.len() < self.min_consensus_nodes {
            return Err(MPCError::InternalError(format!(
                "Not enough Bitcoin nodes after removal: {} remaining, {} required for consensus",
                self.nodes.len(), self.min_consensus_nodes
            )));
        }
        
        Ok(removed)
    }
    
    /// Get all Bitcoin nodes
    pub fn get_nodes(&self) -> &[BitcoinNode] {
        &self.nodes
    }
}

/// Security database structure
#[derive(Debug, Clone, Serialize, Deserialize)]
struct SecurityDatabase {
    /// Current fork detection result
    current_fork: Option<ForkDetectionResult>,
    
    /// Double-spend detections
    double_spends: HashMap<String, DoubleSpendResult>,
}
