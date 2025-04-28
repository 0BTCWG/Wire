// Core types for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use serde::{Deserialize, Serialize};

/// Represents a UTXO in the 0BTC Wire system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UTXO {
    /// The public key hash of the owner
    pub owner_pubkey_hash: Vec<u8>,
    
    /// The asset ID (0 for wBTC)
    pub asset_id: Vec<u8>,
    
    /// The amount of the asset
    pub amount: u64,
    
    /// A random salt for privacy
    pub salt: Vec<u8>,
}

/// Represents a UTXO with circuit targets
#[derive(Debug, Clone)]
pub struct UTXOTarget {
    /// The public key hash of the owner
    pub owner_pubkey_hash_target: Vec<Target>,
    
    /// The asset ID (0 for wBTC)
    pub asset_id_target: Vec<Target>,
    
    /// The amount of the asset
    pub amount_target: Target,
    
    /// A random salt for privacy
    pub salt_target: Vec<Target>,
}

impl UTXOTarget {
    /// Create a new UTXOTarget with virtual targets
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
        hash_size: usize,
    ) -> Self {
        let owner_pubkey_hash_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let asset_id_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        let amount_target = builder.add_virtual_target();
        
        let salt_target = (0..hash_size)
            .map(|_| builder.add_virtual_target())
            .collect();
            
        Self {
            owner_pubkey_hash_target,
            asset_id_target,
            amount_target,
            salt_target,
        }
    }
    
    /// Connect this UTXOTarget to another one
    pub fn connect<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        other: &Self,
    ) {
        for (a, b) in self.owner_pubkey_hash_target.iter().zip(other.owner_pubkey_hash_target.iter()) {
            builder.connect(*a, *b);
        }
        
        for (a, b) in self.asset_id_target.iter().zip(other.asset_id_target.iter()) {
            builder.connect(*a, *b);
        }
        
        builder.connect(self.amount_target, other.amount_target);
        
        for (a, b) in self.salt_target.iter().zip(other.salt_target.iter()) {
            builder.connect(*a, *b);
        }
    }
}

/// Represents a point on an elliptic curve
#[derive(Debug, Clone)]
pub struct PointTarget {
    pub x: Target,
    pub y: Target,
}

impl PointTarget {
    /// Create a new PointTarget with virtual targets
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let x = builder.add_virtual_target();
        let y = builder.add_virtual_target();
        
        Self { x, y }
    }
}

/// Represents a public key in the circuit
#[derive(Debug, Clone)]
pub struct PublicKeyTarget {
    pub point: PointTarget,
}

impl PublicKeyTarget {
    /// Create a new PublicKeyTarget with virtual targets
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let point = PointTarget::add_virtual(builder);
        
        Self { point }
    }
}

/// Represents a signature in the circuit
#[derive(Debug, Clone)]
pub struct SignatureTarget {
    pub r_point: PointTarget,
    pub s_scalar: Target,
}

impl SignatureTarget {
    /// Create a new SignatureTarget with virtual targets
    pub fn add_virtual<F: RichField + Extendable<D>, const D: usize>(
        builder: &mut CircuitBuilder<F, D>,
    ) -> Self {
        let r_point = PointTarget::add_virtual(builder);
        let s_scalar = builder.add_virtual_target();
        
        Self { r_point, s_scalar }
    }
}
