// Merkle tree gadgets for the 0BTC Wire system
use plonky2::field::extension::Extendable;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

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

/// Verify a Merkle proof in the circuit
/// 
/// This is an optimized implementation that reduces the number of constraints
/// by using our optimized hash gadget and efficient boolean operations.
pub fn verify_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    proof: &MerkleProofTarget,
) -> Target {
    // Start with the leaf value
    let mut current = proof.leaf;
    
    // Extract the bits of the index
    let index_bits = builder.split_le(proof.index, proof.siblings.len());
    
    // Compute the path from leaf to root
    for (i, sibling) in proof.siblings.iter().enumerate() {
        // Determine if the current node is on the left or right
        // If index_bit is 0, current is on the left; if 1, current is on the right
        let index_bit = index_bits[i];
        
        // Create left and right nodes based on the index bit
        // We use select to avoid conditional logic, which is more efficient
        let left = builder.select(index_bit, *sibling, current);
        let right = builder.select(index_bit, current, *sibling);
        
        // Hash the pair to get the parent node
        let inputs = vec![left, right];
        current = hash_n(builder, &inputs);
    }
    
    // Check if the computed root matches the expected root
    let is_valid_bool = builder.is_equal(current, proof.root);
    let one = builder.one();
    let zero = builder.zero();
    let is_valid = builder.select(is_valid_bool, one, zero);
    
    is_valid
}

/// Create a Merkle proof target with virtual targets
pub fn create_merkle_proof_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tree_height: usize,
) -> MerkleProofTarget {
    // Create virtual targets for the proof components
    let leaf = builder.add_virtual_target();
    let index = builder.add_virtual_target();
    let root = builder.add_virtual_target();
    
    // Create virtual targets for the siblings
    let siblings = (0..tree_height)
        .map(|_| builder.add_virtual_target())
        .collect();
    
    MerkleProofTarget {
        leaf,
        index,
        siblings,
        root,
    }
}

/// Count the number of gates used in the Merkle proof verification gadget
pub fn count_merkle_proof_gates<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tree_height: usize,
) -> usize {
    // Store the initial gate count
    let initial_gates = builder.num_gates();
    
    // Create a Merkle proof target
    let proof = create_merkle_proof_target(builder, tree_height);
    
    // Verify the proof
    verify_merkle_proof(builder, &proof);
    
    // Return the number of gates added
    builder.num_gates() - initial_gates
}

#[cfg(test)]
mod tests {
    use super::*;
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    type F = GoldilocksField;
    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    
    #[test]
    fn test_merkle_proof_verification() {
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create leaf values as constants
        let leaf1 = builder.constant(F::from_canonical_u64(1));
        let leaf2 = builder.constant(F::from_canonical_u64(2));
        let leaf3 = builder.constant(F::from_canonical_u64(3));
        let leaf4 = builder.constant(F::from_canonical_u64(4));
        
        // Compute level 2 nodes
        let level2_0_inputs = vec![leaf1, leaf2];
        let level2_1_inputs = vec![leaf3, leaf4];
        let level2_0 = hash_n(&mut builder, &level2_0_inputs);
        let level2_1 = hash_n(&mut builder, &level2_1_inputs);
        
        // Compute the root
        let root_inputs = vec![level2_0, level2_1];
        let root = hash_n(&mut builder, &root_inputs);
        
        // Create a Merkle proof for leaf 3 (index 2)
        let leaf_index = 2;
        let leaf = leaf3;
        let index = builder.constant(F::from_canonical_u64(leaf_index as u64));
        
        // The siblings for leaf 3 are: leaf 4 (at level 1) and hash(1,2) (at level 2)
        let siblings = vec![leaf4, level2_0];
        
        // Create the Merkle proof target
        let proof = MerkleProofTarget {
            leaf,
            index,
            siblings,
            root,
        };
        
        // Verify the proof
        let is_valid = verify_merkle_proof(&mut builder, &proof);
        
        // The proof should be valid
        builder.assert_one(is_valid);
        
        // Register the result as a public input
        builder.register_public_input(is_valid);
        
        // Build the circuit
        let circuit = builder.build::<C>();
        
        // Create a partial witness
        let pw = PartialWitness::new();
        
        // Generate a proof
        let proof = circuit.prove(pw).unwrap();
        
        // Verify the proof
        circuit.verify(proof).unwrap();
    }
    
    #[test]
    fn test_merkle_proof_gates() {
        // Create a circuit
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Count the gates for a Merkle proof with height 10
        let gates = count_merkle_proof_gates(&mut builder, 10);
        
        println!("Merkle proof verification gate count (height 10): {}", gates);
        
        // Count the gates for a Merkle proof with height 20
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        let gates = count_merkle_proof_gates(&mut builder, 20);
        
        println!("Merkle proof verification gate count (height 20): {}", gates);
    }
    
    #[test]
    fn benchmark_merkle_proof_verification() {
        use std::time::Instant;
        
        println!("Benchmarking Merkle proof verification...");
        
        // Create a circuit with a Merkle proof verification
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        // Create a Merkle proof with height 10
        let proof = create_merkle_proof_target(&mut builder, 10);
        
        // Verify the proof
        let is_valid = verify_merkle_proof(&mut builder, &proof);
        
        // Register the result as a public input
        builder.register_public_input(is_valid);
        
        // Build the circuit
        let start = Instant::now();
        let circuit = builder.build::<C>();
        let circuit_creation_time = start.elapsed();
        
        // Create a partial witness
        let mut pw = PartialWitness::new();
        
        // Set values for the proof components
        pw.set_target(proof.leaf, F::from_canonical_u64(3));
        pw.set_target(proof.index, F::from_canonical_u64(2));
        pw.set_target(proof.root, F::from_canonical_u64(123));
        
        // Set values for the siblings
        for (i, sibling) in proof.siblings.iter().enumerate() {
            pw.set_target(*sibling, F::from_canonical_u64(1000 + i as u64));
        }
        
        // Generate a proof
        let start = Instant::now();
        let proof = circuit.prove(pw).unwrap();
        let proof_generation_time = start.elapsed();
        
        // Verify the proof
        let start = Instant::now();
        circuit.verify(proof).unwrap();
        let verification_time = start.elapsed();
        
        println!("Merkle proof verification benchmark results:");
        println!("  Circuit creation time: {:?}", circuit_creation_time);
        println!("  Proof generation time: {:?}", proof_generation_time);
        println!("  Proof verification time: {:?}", verification_time);
    }
}
