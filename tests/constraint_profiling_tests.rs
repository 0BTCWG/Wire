#[cfg(test)]
mod constraint_profiling_tests {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::PoseidonGoldilocksConfig;
    
    use wire_lib::gadgets::ed25519::estimate_scalar_multiply_complexity;
    use wire_lib::gadgets::hash::count_hash_gates;
    use wire_lib::circuits::native_asset_create::NativeAssetCreateCircuit;
    use wire_lib::circuits::native_asset_mint::NativeAssetMintCircuit;
    use wire_lib::circuits::native_asset_burn::NativeAssetBurnCircuit;
    use wire_lib::circuits::wrapped_asset_mint::WrappedAssetMintCircuit;
    use wire_lib::circuits::wrapped_asset_burn::WrappedAssetBurnCircuit;
    use wire_lib::circuits::transfer::TransferCircuit;
    
    type F = GoldilocksField;
    const D: usize = 2;
    
    #[test]
    fn profile_scalar_multiply_complexity() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let gate_count = estimate_scalar_multiply_complexity(&mut builder);
        
        println!("Scalar multiplication gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_hash_gate_count() {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);
        
        let gate_count = count_hash_gates(&mut builder);
        
        println!("Hash operation gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_native_asset_create_circuit() {
        let circuit_data = NativeAssetCreateCircuit::create_circuit();
        let gate_count = circuit_data.common.gates.len();
        
        println!("NativeAssetCreateCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_native_asset_mint_circuit() {
        let circuit_data = NativeAssetMintCircuit::create_circuit();
        let gate_count = circuit_data.common.gates.len();
        
        println!("NativeAssetMintCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_native_asset_burn_circuit() {
        let circuit_data = NativeAssetBurnCircuit::create_circuit();
        let gate_count = circuit_data.common.gates.len();
        
        println!("NativeAssetBurnCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_wrapped_asset_mint_circuit() {
        let circuit_data = WrappedAssetMintCircuit::create_circuit();
        let gate_count = circuit_data.common.gates.len();
        
        println!("WrappedAssetMintCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_wrapped_asset_burn_circuit() {
        let circuit_data = WrappedAssetBurnCircuit::create_circuit();
        let gate_count = circuit_data.common.gates.len();
        
        println!("WrappedAssetBurnCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_transfer_circuit() {
        let circuit_data = TransferCircuit::create_circuit(); // Default configuration
        let gate_count = circuit_data.common.gates.len();
        
        println!("TransferCircuit gate count: {}", gate_count);
        // This is just a profiling test, so we don't need to assert anything
    }
    
    #[test]
    fn profile_all_circuits() {
        // This test runs all the profiling tests in one go
        profile_scalar_multiply_complexity();
        profile_hash_gate_count();
        profile_native_asset_create_circuit();
        profile_native_asset_mint_circuit();
        profile_native_asset_burn_circuit();
        profile_wrapped_asset_mint_circuit();
        profile_wrapped_asset_burn_circuit();
        profile_transfer_circuit();
    }
}
