//! Simple compilation test to verify that the core functionality compiles

#[cfg(test)]
mod tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    
    use wire_lib::utils::field::field_to_bits;
    use wire_lib::utils::hash::compute_hash;
    
    #[test]
    fn test_basic_functionality() {
        // Test field operations
        let field_val = GoldilocksField::from_canonical_u64(123);
        let bits = field_to_bits(field_val);
        assert_eq!(bits.len(), 64);
        
        // Test hash operations
        let hash_input = vec![
            GoldilocksField::from_canonical_u64(1),
            GoldilocksField::from_canonical_u64(2),
        ];
        let hash_result = compute_hash(&hash_input);
        assert!(hash_result != GoldilocksField::ZERO);
        
        println!("Basic functionality test passed!");
    }
}
