# 0BTC Wire Audit Test Vectors

## Introduction
This document outlines the test vectors that have been prepared for the external security audit of the 0BTC Wire project. These test vectors cover all critical operations and include both valid and invalid inputs, edge cases, and performance benchmarks.

## Test Vector Format
Each test vector is provided in JSON format with the following structure:

```json
{
  "id": "unique_identifier",
  "description": "Description of the test vector",
  "category": "Category of operation (e.g., 'signature', 'circuit', 'nullifier')",
  "type": "Type of test (e.g., 'valid', 'invalid', 'edge_case')",
  "inputs": {
    // Operation-specific inputs
  },
  "expected_outputs": {
    // Expected results
  },
  "notes": "Additional information or context"
}
```

## Cryptographic Operations

### EdDSA Signature Verification

#### Valid Signatures
- [ ] Standard valid signature
- [ ] Signature with maximum scalar value
- [ ] Signature with minimum scalar value
- [ ] Batch verification of multiple valid signatures

#### Invalid Signatures
- [ ] Invalid signature (wrong private key)
- [ ] Invalid signature (modified message)
- [ ] Invalid signature (modified R point)
- [ ] Invalid signature (modified S scalar)
- [ ] Signature with invalid curve point

#### Edge Cases
- [ ] Signature with point at infinity
- [ ] Signature with identity element
- [ ] Signature verification with extremely large message

### Poseidon Hash Function

#### Valid Hashes
- [ ] Hash of empty input
- [ ] Hash of single field element
- [ ] Hash of maximum field elements
- [ ] Hash with domain separation

#### Edge Cases
- [ ] Hash of maximum value field elements
- [ ] Hash of minimum value field elements
- [ ] Hash with repeated inputs

### Merkle Proof Verification

#### Valid Proofs
- [ ] Valid proof for leaf at index 0
- [ ] Valid proof for leaf at maximum index
- [ ] Valid proof for tree of minimum height
- [ ] Valid proof for tree of maximum height

#### Invalid Proofs
- [ ] Invalid proof (wrong path)
- [ ] Invalid proof (wrong root)
- [ ] Invalid proof (wrong leaf)
- [ ] Invalid proof (wrong height)

#### Edge Cases
- [ ] Proof for single-node tree
- [ ] Proof with maximum height

## Circuit Operations

### WrappedAssetMint Circuit

#### Valid Operations
- [ ] Standard mint operation
- [ ] Mint with minimum amount
- [ ] Mint with maximum amount
- [ ] Mint with different recipient addresses

#### Invalid Operations
- [ ] Invalid custodian signature
- [ ] Invalid attestation
- [ ] Invalid recipient address
- [ ] Invalid amount (out of range)

#### Edge Cases
- [ ] Mint with zero amount (should fail)
- [ ] Mint with maximum representable amount

### WrappedAssetBurn Circuit

#### Valid Operations
- [ ] Standard burn operation
- [ ] Burn with minimum amount
- [ ] Burn with maximum amount
- [ ] Burn with fee quote
- [ ] Burn without fee quote

#### Invalid Operations
- [ ] Invalid sender signature
- [ ] Invalid UTXO
- [ ] Invalid destination address
- [ ] Invalid fee quote signature

#### Edge Cases
- [ ] Burn with zero amount (should fail)
- [ ] Burn with maximum representable amount
- [ ] Burn with expired fee quote

### Transfer Circuit

#### Valid Operations
- [ ] Standard transfer operation
- [ ] Transfer with multiple inputs
- [ ] Transfer with multiple outputs
- [ ] Transfer with change output
- [ ] Transfer with fee payment

#### Invalid Operations
- [ ] Invalid sender signature
- [ ] Invalid input UTXO
- [ ] Invalid recipient address
- [ ] Invalid amount (exceeds inputs)
- [ ] Invalid fee payment

#### Edge Cases
- [ ] Transfer with maximum number of inputs
- [ ] Transfer with maximum number of outputs
- [ ] Transfer with zero change (exact amount)
- [ ] Transfer with maximum representable amount

### Recursive Proof Aggregation

#### Valid Operations
- [ ] Aggregate two proofs
- [ ] Aggregate maximum number of proofs
- [ ] Aggregate heterogeneous proof types
- [ ] Verify aggregated proof

#### Invalid Operations
- [ ] Aggregate with invalid proof
- [ ] Verify with modified aggregated proof
- [ ] Aggregate incompatible proof types

#### Edge Cases
- [ ] Aggregate single proof
- [ ] Aggregate maximum supported batch size

## Performance Benchmarks

### Proof Generation
- [ ] Measure proof generation time for each circuit type
- [ ] Measure proof generation memory usage for each circuit type
- [ ] Measure proof generation time with varying input sizes
- [ ] Measure proof generation time with varying constraint counts

### Proof Verification
- [ ] Measure verification time for each circuit type
- [ ] Measure verification time for aggregated proofs
- [ ] Measure verification time with varying public input sizes

### Recursive Aggregation
- [ ] Measure aggregation time for varying batch sizes
- [ ] Measure verification time for varying aggregation depths
- [ ] Measure memory usage for recursive aggregation

## Implementation-Specific Test Vectors

### Memory-Efficient Proof Generation
- [ ] Generate proof with memory constraints
- [ ] Generate proof with incremental witness generation
- [ ] Measure memory usage with and without optimizations

### Specialized Gadgets
- [ ] Range check with various range sizes
- [ ] Batch hashing with different batch sizes
- [ ] Vector operations with varying vector lengths

## Using the `generate_audit_test_vectors` Binary

The `generate_audit_test_vectors` binary is a tool for generating test vectors that can be used for auditing the 0BTC Wire project. It creates deterministic proofs for wrapped asset mint, wrapped asset burn, and transfer operations.

### Usage

```bash
cargo run --release --bin generate_audit_test_vectors -- --output-dir <OUTPUT_DIRECTORY>
```

Where `<OUTPUT_DIRECTORY>` is the directory where the test vectors will be saved.

### Implementation Details

The binary has been modernized to use the latest public APIs for all circuit operations:

1. **Wrapped Asset Mint Circuit**
   - Uses `WrappedAssetMintCircuit::generate_proof_static` with explicit byte conversion for all inputs
   - Handles fee quotes and custodian public keys properly
   - Uses only public, stable APIs for all cryptographic operations

2. **Wrapped Asset Burn Circuit**
   - Uses `WrappedAssetBurnCircuit::generate_proof_static` with explicit byte conversion
   - Properly formats BTC addresses and handles optional fee parameters
   - Ensures all witness assignments are explicit and auditable

3. **Transfer Circuit**
   - Uses `TransferCircuit::new()` followed by the instance method `generate_proof()`
   - Constructs all inputs with proper byte ordering and domain separation
   - Handles nullifier generation with proper randomness

4. **Utility Functions**
   - Added helper functions for consistent byte conversion (e.g., `u64_to_le_bytes`)
   - Ensures all integer literals are within valid u64 range
   - Properly handles errors with explicit error reporting

### Recent Improvements

- Fixed all witness assignment conflicts in test vector generation
- Ensured deterministic inputs for reproducible proof generation
- Updated to use the latest clap API for command-line argument parsing
- Added proper error handling for all proof generation steps
- Improved memory efficiency by avoiding unnecessary cloning
- Ensured all cryptographic operations use only public, stable APIs
- Fixed type safety issues with proper Target and BoolTarget handling

### Notes on Test Vector Generation

- All proofs are generated with deterministic inputs for reproducibility
- The binary handles errors gracefully and reports any proof generation failures
- Test vectors include both the inputs and the resulting proof (if successful)
- All cryptographic operations are explicit and auditable

## Instructions for Running Test Vectors

### Prerequisites
- Rust toolchain (nightly)
- Required dependencies (as specified in Cargo.toml)
- Minimum 8GB RAM for standard test vectors
- Minimum 16GB RAM for performance benchmarks

### Running the Test Vectors
1. Clone the repository
2. Install dependencies: `cargo build --release`
3. Run the test vector suite: `cargo run --release --bin test_vectors`
4. View results in the `results/` directory

### Interpreting Results
- Each test vector produces a JSON file with inputs, expected outputs, and actual outputs
- Timing information is included for performance benchmarks
- Memory usage is reported for relevant operations
- Any discrepancies between expected and actual outputs are flagged

## Conclusion
These test vectors provide comprehensive coverage of the 0BTC Wire codebase, focusing on cryptographic operations, circuit functionality, and performance characteristics. They are designed to assist auditors in verifying the correctness, security, and efficiency of the implementation.
