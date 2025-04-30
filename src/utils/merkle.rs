// Merkle tree utility functions for the 0BTC Wire system

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2_field::extension::Extendable;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::utils::hash::{poseidon_hash_two, poseidon_hash_two_targets, poseidon_hash_with_domain, poseidon_hash_with_domain_targets};

/// Domain separation constant for Merkle tree hashing
pub const MERKLE_DOMAIN: u64 = 0x03;

/// Represents a Merkle proof
#[derive(Debug, Clone)]
pub struct MerkleProof<F: Field> {
    pub leaf: F,
    pub index: usize,
    pub siblings: Vec<F>,
    pub root: F,
}

/// Represents a Merkle proof in the circuit
#[derive(Debug, Clone)]
pub struct MerkleProofTarget {
    pub leaf: Target,
    pub index_bits: Vec<BoolTarget>,
    pub siblings: Vec<Target>,
    pub root: Target,
}

/// Computes the root of a Merkle tree given a leaf and a Merkle proof
pub fn compute_merkle_root<F: RichField>(leaf: F, index: usize, siblings: &[F], height: usize) -> F {
    let index_bits = index_to_bits(index, height);
    
    let mut current = leaf;
    for i in 0..height {
        let sibling = siblings[i];
        if index_bits[i] {
            // If index bit is 1, current is the right child
            current = poseidon_hash_two(sibling, current);
        } else {
            // If index bit is 0, current is the left child
            current = poseidon_hash_two(current, sibling);
        }
    }
    
    current
}

/// Computes the root of a Merkle tree given a leaf and a Merkle proof in the circuit
pub fn compute_merkle_root_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index_bits: &[BoolTarget],
    siblings: &[Target],
) -> Target {
    let mut current = leaf;
    
    for (i, sibling) in siblings.iter().enumerate() {
        let index_bit = index_bits[i];
        
        // Select the order of hashing based on the index bit
        let left = builder.select(index_bit, *sibling, current);
        let right = builder.select(index_bit, current, *sibling);
        
        // Hash the two children to get the parent
        current = poseidon_hash_two_targets(builder, left, right);
    }
    
    current
}

/// Builds a Merkle tree from leaves and returns the flattened tree
pub fn build_merkle_tree<F: RichField>(leaves: &[F]) -> Vec<F> {
    let (_, tree) = build_merkle_tree_full(leaves);
    
    // Flatten the tree
    let mut flattened = Vec::new();
    for level in tree {
        flattened.extend(level);
    }
    
    flattened
}

/// Verifies a Merkle proof
pub fn verify_merkle_proof<F: RichField>(proof: &MerkleProof<F>) -> bool {
    let computed_root = compute_merkle_root(
        proof.leaf,
        proof.index,
        &proof.siblings,
        proof.siblings.len(),
    );
    
    computed_root == proof.root
}

/// Verifies a Merkle proof in the circuit
pub fn verify_merkle_proof_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    proof: &MerkleProofTarget,
) -> BoolTarget {
    let computed_root = compute_merkle_root_targets(
        builder,
        proof.leaf,
        &proof.index_bits,
        &proof.siblings,
    );
    
    builder.is_equal(computed_root, proof.root)
}

/// Builds a complete Merkle tree from a list of leaves and returns the root and tree structure
pub fn build_merkle_tree_full<F: RichField>(leaves: &[F]) -> (F, Vec<Vec<F>>) {
    let num_leaves = leaves.len();
    if num_leaves == 0 {
        return (F::ZERO, vec![]);
    }
    
    // Find the smallest power of 2 that is >= num_leaves
    let mut height = 0;
    let mut n = 1;
    while n < num_leaves {
        n *= 2;
        height += 1;
    }
    
    // Initialize the tree
    let mut tree = Vec::with_capacity(height + 1);
    
    // Add the leaves level
    let mut level = Vec::with_capacity(n);
    level.extend_from_slice(leaves);
    
    // Pad with zeros if necessary
    while level.len() < n {
        level.push(F::ZERO);
    }
    
    tree.push(level);
    
    // Build the tree bottom-up
    for _ in 0..height {
        let prev_level = tree.last().unwrap();
        let mut new_level = Vec::with_capacity(prev_level.len() / 2);
        
        for i in (0..prev_level.len()).step_by(2) {
            let left = prev_level[i];
            let right = prev_level[i + 1];
            let parent = poseidon_hash_two(left, right);
            new_level.push(parent);
        }
        
        tree.push(new_level);
    }
    
    // The root is the only element in the last level
    let root = tree.last().unwrap()[0];
    
    (root, tree)
}

/// Generates a Merkle proof for a leaf at a given index
pub fn generate_merkle_proof<F: RichField>(
    tree: &[Vec<F>],
    leaf_index: usize,
) -> MerkleProof<F> {
    let height = tree.len() - 1;
    let leaf = tree[0][leaf_index];
    let root = tree[height][0];
    
    let mut siblings = Vec::with_capacity(height);
    let mut current_index = leaf_index;
    
    for i in 0..height {
        let sibling_index = current_index ^ 1; // Flip the least significant bit
        siblings.push(tree[i][sibling_index]);
        current_index >>= 1; // Move up one level
    }
    
    MerkleProof {
        leaf,
        index: leaf_index,
        siblings,
        root,
    }
}

/// Converts a leaf index to a sequence of boolean values representing the path
pub fn index_to_bits(index: usize, height: usize) -> Vec<bool> {
    let mut bits = Vec::with_capacity(height);
    
    for i in 0..height {
        bits.push(((index >> i) & 1) == 1);
    }
    
    bits
}

/// Converts a sequence of boolean values to a leaf index
pub fn bits_to_index(bits: &[bool]) -> usize {
    let mut index = 0;
    
    for (i, &bit) in bits.iter().enumerate() {
        if bit {
            index |= 1 << i;
        }
    }
    
    index
}

/// Creates a Merkle proof target in the circuit
pub fn create_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: usize,
    height: usize,
) -> MerkleProofTarget {
    let root = builder.add_virtual_target();
    
    let mut siblings = Vec::with_capacity(height);
    for _ in 0..height {
        siblings.push(builder.add_virtual_target());
    }
    
    let index_bits = index_to_bits(index, height);
    let mut index_bit_targets = Vec::with_capacity(height);
    for bit in index_bits {
        index_bit_targets.push(builder.constant_bool(bit));
    }
    
    MerkleProofTarget {
        leaf,
        index_bits: index_bit_targets,
        siblings,
        root,
    }
}

/// Computes a leaf hash with domain separation
pub fn compute_leaf_hash<F: RichField>(value: F) -> F {
    poseidon_hash_with_domain(&[value], MERKLE_DOMAIN)
}

/// Computes a leaf hash with domain separation in the circuit
pub fn compute_leaf_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> Target {
    poseidon_hash_with_domain_targets(builder, &[value], MERKLE_DOMAIN)
}
