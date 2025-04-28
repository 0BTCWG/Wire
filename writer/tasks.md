# 0BTC Wire Project Task List

## Completed Tasks

### Phase 0: Project Setup 
- Set up Rust development environment with nightly toolchain
- Configure Cargo.toml with necessary dependencies
- Create project structure with separate modules
- Set up WASM feature flag

### Phase 1: Core Types and Gadgets 
- Implement core data structures with Target versions
- Create hashing gadget (Poseidon-based)
- Implement signature verification gadget (simplified version)
- Build nullifier gadget for UTXO consumption
- Develop arithmetic and comparison gadgets
- Create fee payment gadget

### Phase 2-4: Circuit Structures 
- Implement basic structure for all circuits
- Update WrappedAssetMintCircuit for Plonky2 v0.2.x compatibility

## Next Steps

### 1. Update Remaining Circuits (Priority: High)
- Update WrappedAssetBurnCircuit for Plonky2 v0.2.x compatibility
- Update TransferCircuit for Plonky2 v0.2.x compatibility
- Update NativeAssetCreateCircuit for Plonky2 v0.2.x compatibility
- Update NativeAssetMintCircuit for Plonky2 v0.2.x compatibility
- Update NativeAssetBurnCircuit for Plonky2 v0.2.x compatibility

### 2. Enhance Signature Verification (Priority: High)
- Implement full EdDSA signature verification gadget
- Update all circuits to use the enhanced signature verification

### 3. Implement Testing (Priority: Medium)
- Write comprehensive unit tests for all gadgets
- Create integration tests for circuits
- Test edge cases (zero amounts, insufficient funds, invalid signatures)

### 4. Optimize Circuits (Priority: Medium)
- Profile constraint count for each circuit
- Optimize critical gadgets for efficiency
- Benchmark performance on different platforms

### 5. Complete CLI Implementation (Priority: Medium)
- Implement key generation functionality
- Implement circuit proving functionality
- Implement proof verification functionality
- Add configuration file support

### 6. Complete WASM Implementation (Priority: Low)
- Implement full WASM functionality
- Create browser demo application
- Optimize for browser environment

### 7. Improve Documentation (Priority: Low)
- Document circuit inputs, outputs, and constraints
- Create API documentation
- Write user guides for CLI and WASM usage
- Prepare release packages for executable and WASM

## Current Focus
We are currently focusing on updating the remaining circuit implementations to be compatible with Plonky2 v0.2.x. This is a critical step before we can proceed with enhancing the signature verification and implementing comprehensive testing.
