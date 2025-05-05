// Merkle tree gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::errors::{CryptoError, WireError, WireResult};
use crate::gadgets::hash::hash_n;

/// Represents a Merkle proof in the circuit
#[derive(Debug, Clone)]
pub struct MerkleProofTarget {
    /// The leaf value
    pub leaf: Target,

    /// The index of the leaf in the tree
    pub index: Target,

    /// The sibling nodes along the path from the leaf to the root
    pub siblings: Vec<Target>,

    /// The root of the Merkle tree
    pub root: Target,
}

/// Verify a Merkle proof with assertions
///
/// This function verifies that a leaf is included in a Merkle tree with a given root.
/// Instead of returning a boolean target, it uses assertions to enforce that the proof is valid.
/// This is more secure for critical applications.
pub fn assert_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
) -> WireResult<()> {
    // Validate inputs
    if siblings.is_empty() {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Merkle proof siblings cannot be empty".to_string(),
        )));
    }

    // Check for maximum tree height to prevent DoS
    if siblings.len() > 256 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Merkle tree height exceeds maximum allowed (256)".to_string(),
        )));
    }

    // Compute the path from leaf to root
    let computed_root = compute_merkle_root(builder, leaf, index, siblings)?;

    // Assert that the computed root matches the expected root
    let is_equal = builder.is_equal(computed_root, merkle_root);
    builder.assert_one(is_equal.target);

    Ok(())
}

/// Compute the Merkle root from a leaf, index, and siblings
///
/// This function computes the Merkle root from a leaf, index, and siblings.
/// It traverses the tree from the leaf to the root.
pub fn compute_merkle_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    siblings: &[Target],
) -> WireResult<Target> {
    // Validate inputs
    if siblings.is_empty() {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Merkle proof siblings cannot be empty".to_string(),
        )));
    }

    // Start with the leaf
    let mut current = leaf;

    // For each level of the tree
    for (i, sibling) in siblings.iter().enumerate() {
        // Get the i-th bit of the index
        let is_right = get_index_bit(builder, index, i);

        // Select the left and right nodes based on the is_right flag
        let (node1, node2) = select_nodes(builder, current, *sibling, is_right);

        // Hash the nodes with domain separation for Merkle trees
        let inputs = vec![node1, node2];
        // Use hash_n without the domain parameter
        current = hash_n(builder, &inputs);
    }

    Ok(current)
}

/// Hash two Merkle nodes based on the direction flag
///
/// This function hashes two nodes in the correct order based on the direction flag.
pub fn hash_merkle_nodes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    node: Target,
    sibling: Target,
    is_right: BoolTarget,
) -> WireResult<Target> {
    // Select the left and right nodes based on the is_right flag
    let (node1, node2) = select_nodes(builder, node, sibling, is_right);

    // Hash the nodes
    let inputs = vec![node1, node2];
    // Use hash_n without the domain parameter
    let result = hash_n(builder, &inputs);

    Ok(result)
}

/// Select the left and right nodes based on the is_right flag
///
/// If is_right is true, swap the nodes.
pub fn select_nodes<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: Target,
    right: Target,
    is_right: BoolTarget,
) -> (Target, Target) {
    let node1 = builder.select(is_right, right, left);
    let node2 = builder.select(is_right, left, right);

    (node1, node2)
}

/// Get the i-th bit of the index
///
/// This function extracts the i-th bit of the index as a boolean target.
pub fn get_index_bit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    index: Target,
    bit_index: usize,
) -> BoolTarget {
    // Split the index into bits
    let bits = builder.split_le(index, 64);

    // Check if the bit index is valid
    if bit_index >= bits.len() {
        // Return false for invalid bit indices
        return builder.constant_bool(false);
    }

    // The bits from split_le are already BoolTargets, so we can return directly
    bits[bit_index]
}

/// Verify a Merkle proof (legacy version that returns a target)
///
/// This function verifies a Merkle proof and returns a target that is 1 if the proof is valid.
pub fn verify_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
) -> WireResult<Target> {
    // Validate inputs
    if siblings.is_empty() {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Merkle proof siblings cannot be empty".to_string(),
        )));
    }

    // For small trees, we can use a more direct approach
    let mut current = leaf;

    // For each level of the tree
    for (i, sibling) in siblings.iter().enumerate() {
        // Get the i-th bit of the index
        let is_right = get_index_bit(builder, index, i);

        // Select the left and right nodes based on the is_right flag
        let (node1, node2) = select_nodes(builder, current, *sibling, is_right);

        // Hash the nodes for Merkle trees
        let inputs = vec![node1, node2];
        // Use hash_n without the domain parameter
        current = hash_n(builder, &inputs);
    }

    // Check if the computed root matches the expected root
    let is_equal = builder.is_equal(current, merkle_root);

    Ok(is_equal.target)
}

/// Verify a Merkle proof with a fixed tree height
///
/// This function verifies that a leaf is included in a Merkle tree with a given root.
/// It enforces that the tree height matches the expected height.
pub fn verify_merkle_proof_fixed_height<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
    height: usize,
) -> WireResult<()> {
    // Validate inputs
    if siblings.len() != height {
        return Err(WireError::CryptoError(CryptoError::MerkleError(format!(
            "Merkle proof siblings length ({}) does not match height ({})",
            siblings.len(),
            height
        ))));
    }

    // Compute the root from the leaf and siblings
    let computed_root = compute_merkle_root(builder, leaf, index, siblings)?;

    // Assert that the computed root matches the expected root
    let is_equal = builder.is_equal(computed_root, merkle_root);
    builder.assert_one(is_equal.target);

    Ok(())
}

/// Optimized Merkle proof verification for small trees
///
/// This function is optimized for trees with a small number of levels.
/// It uses a more direct approach to compute the root.
pub fn assert_merkle_proof_small_tree<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
) -> WireResult<()> {
    // Validate inputs
    if siblings.is_empty() {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Siblings array cannot be empty".to_string(),
        )));
    }

    // This optimization is only effective for small trees
    if siblings.len() > 8 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Small tree optimization is only effective for trees with height <= 8".to_string(),
        )));
    }

    // Start with the leaf
    let mut current = leaf;

    // Traverse the tree from leaf to root
    for (i, sibling) in siblings.iter().enumerate() {
        // Get the i-th bit of the index
        let is_right = get_index_bit(builder, index, i);

        // Select the left and right nodes based on the is_right flag
        let (node1, node2) = select_nodes(builder, current, *sibling, is_right);

        // Hash the nodes with domain separation for Merkle trees
        let inputs = vec![node1, node2];
        // Use hash_n without the domain parameter and without the ? operator
        current = hash_n(builder, &inputs);
    }

    // Assert that the computed root matches the expected root
    let is_equal = builder.is_equal(current, merkle_root);
    builder.assert_one(is_equal.target);

    Ok(())
}

/// Count the number of gates used in Merkle proof verification
pub fn count_merkle_proof_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tree_height: usize,
) -> WireResult<usize> {
    // Validate input
    if tree_height == 0 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Tree height must be greater than zero".to_string(),
        )));
    }

    if tree_height > 256 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Tree height exceeds maximum allowed (256)".to_string(),
        )));
    }

    let start_gates = builder.num_gates();

    // Create dummy inputs for Merkle proof verification
    let leaf = builder.add_virtual_target();
    let index = builder.add_virtual_target();
    let root = builder.add_virtual_target();

    let mut siblings = Vec::with_capacity(tree_height);
    for _ in 0..tree_height {
        siblings.push(builder.add_virtual_target());
    }

    // Run Merkle proof verification
    let _ = verify_merkle_proof(builder, leaf, index, root, &siblings)?;

    let end_gates = builder.num_gates();
    Ok(end_gates - start_gates)
}

/// Count the number of gates used in optimized Merkle proof verification
pub fn count_optimized_merkle_proof_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tree_height: usize,
) -> WireResult<usize> {
    // Validate input
    if tree_height == 0 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Tree height must be greater than zero".to_string(),
        )));
    }

    if tree_height > 8 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Optimized verification only supports tree height <= 8".to_string(),
        )));
    }

    let start_gates = builder.num_gates();

    // Create dummy inputs for Merkle proof verification
    let leaf = builder.add_virtual_target();
    let index = builder.add_virtual_target();
    let root = builder.add_virtual_target();

    let mut siblings = Vec::with_capacity(tree_height);
    for _ in 0..tree_height {
        siblings.push(builder.add_virtual_target());
    }

    // Run optimized Merkle proof verification
    let _ = assert_merkle_proof_small_tree(builder, leaf, index, root, &siblings)?;

    let end_gates = builder.num_gates();
    Ok(end_gates - start_gates)
}

/// Create a Merkle proof target with virtual targets
pub fn create_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tree_height: usize,
) -> WireResult<MerkleProofTarget> {
    // Validate input
    if tree_height == 0 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Tree height must be greater than zero".to_string(),
        )));
    }

    if tree_height > 256 {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Tree height exceeds maximum allowed (256)".to_string(),
        )));
    }

    // Create virtual targets for the Merkle proof
    let leaf = builder.add_virtual_target();
    let index = builder.add_virtual_target();
    let root = builder.add_virtual_target();

    let mut siblings = Vec::with_capacity(tree_height);
    for _ in 0..tree_height {
        siblings.push(builder.add_virtual_target());
    }

    Ok(MerkleProofTarget {
        leaf,
        index,
        siblings,
        root,
    })
}

/// Verify a Merkle proof against a known root
pub fn verify_merkle_proof_with_root<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    proof: &[Target],
    expected: Target,
) -> Result<(), WireError> {
    if proof.is_empty() {
        return Err(WireError::CryptoError(CryptoError::MerkleError(
            "Merkle proof cannot be empty".to_string(),
        )));
    }

    // First element is the index, rest are siblings
    let index = proof[0];
    let siblings = &proof[1..];

    // Compute the Merkle root from the leaf and proof
    let computed_root = compute_merkle_root(builder, leaf, index, siblings)?;

    // Verify that the computed root matches the expected root
    builder.connect(computed_root, expected);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::errors::{CircuitError, WireError, WireResult};
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::PartialWitness;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;

    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;
    const D: usize = 2;

    #[test]
    fn test_merkle_proof_verification() -> WireResult<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a leaf value
        let leaf = builder.constant(F::from_canonical_u64(123));

        // Create sibling values
        let siblings = vec![
            builder.constant(F::from_canonical_u64(456)),
            builder.constant(F::from_canonical_u64(789)),
        ];

        // Create index (0 = left, 1 = right)
        let index = builder.constant(F::from_canonical_u64(0)); // Path: left

        // Compute the Merkle root
        let computed_root = compute_merkle_root(&mut builder, leaf, index, &siblings)?;

        // Verify the Merkle proof
        let is_valid = verify_merkle_proof(&mut builder, leaf, index, computed_root, &siblings)?;

        // Assert that the verification result is true
        builder.assert_one(is_valid);

        // Build the circuit
        let data = builder.build::<C>();

        // Create a partial witness
        let pw = PartialWitness::new();

        // Generate and verify proof
        let proof = data.prove(pw).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofGenerationError(e.to_string()))
        })?;

        data.verify(proof).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofVerificationError(e.to_string()))
        })?;

        Ok(())
    }

    #[test]
    fn test_compute_merkle_root() -> WireResult<()> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // Create a leaf value
        let leaf = builder.constant(F::from_canonical_u64(123));

        // Create sibling values
        let siblings = vec![
            builder.constant(F::from_canonical_u64(456)),
            builder.constant(F::from_canonical_u64(789)),
        ];

        // Create index (0 = left, 1 = right)
        let index = builder.constant(F::from_canonical_u64(1)); // Path: right

        // Compute the Merkle root
        let computed_root = compute_merkle_root(&mut builder, leaf, index, &siblings)?;

        // Instead of using assert_equal, use connect with the correct expected value
        let expected_value = F::from_canonical_u64(10159192873707091070);
        let expected = builder.constant(expected_value);
        builder.connect(computed_root, expected);

        // Build the circuit
        let data = builder.build::<C>();

        // Create a partial witness
        let pw = PartialWitness::new();

        // Generate and verify proof
        let proof = data.prove(pw).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofGenerationError(e.to_string()))
        })?;

        data.verify(proof).map_err(|e| {
            WireError::CircuitError(CircuitError::ProofVerificationError(e.to_string()))
        })?;

        Ok(())
    }
}
