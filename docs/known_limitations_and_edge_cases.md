# 0BTC Wire Known Limitations and Edge Cases

## Introduction
This document outlines the known limitations, edge cases, and potential vulnerabilities in the 0BTC Wire project. These items are documented to provide transparency to auditors and users, and to ensure that these issues are properly understood and mitigated where possible.

## Cryptographic Limitations

### EdDSA Implementation
1. **Small Subgroup Attacks**: The current implementation does not explicitly check for small subgroup attacks. While Plonky2's underlying field should prevent these attacks, explicit validation would provide additional security.
   - **Mitigation**: Consider adding explicit validation of points to ensure they are in the main subgroup.

2. **Batch Verification Limitations**: The batch verification implementation uses a randomized approach that has a small probability of false positives (approximately 2^-128).
   - **Mitigation**: This is a standard trade-off for efficiency and the probability is cryptographically negligible.

3. **Side-Channel Attacks**: The implementation is not explicitly hardened against side-channel attacks such as timing attacks or power analysis.
   - **Mitigation**: In ZKP contexts, this is less relevant as computation happens offline, but should be considered for any online components.

### Poseidon Hash Function
1. **Parameter Selection**: The Poseidon hash parameters are chosen based on current security estimates. These may need to be updated as cryptanalysis advances.
   - **Mitigation**: Parameters are configurable and can be updated if needed.

2. **Domain Separation**: While domain separation is implemented, the approach uses simple prefixing which may not be optimal for all use cases.
   - **Mitigation**: The domain separation approach is documented and consistent throughout the codebase.

## Circuit Limitations

### General Circuit Limitations
1. **Circuit Size Limits**: Very large circuits (>2^20 constraints) may encounter memory issues during proof generation.
   - **Mitigation**: Memory-efficient proof generation is implemented but has performance trade-offs.

2. **Public Input Size**: There is a practical limit to the number of public inputs a circuit can have before verification becomes prohibitively expensive.
   - **Mitigation**: Design patterns encourage minimizing public inputs and using hash commitments where appropriate.

### Specific Circuit Limitations

#### WrappedAssetMint Circuit
1. **Custodian Trust Assumption**: The circuit relies on a trusted custodian to attest to BTC deposits.
   - **Mitigation**: This is an inherent design limitation, not a security vulnerability. Multi-signature custodian schemes could be implemented in the future.

2. **Replay Protection**: The deposit nonce provides replay protection but requires custodian to maintain state.
   - **Mitigation**: Documented in integration guide with best practices.

#### WrappedAssetBurn Circuit
1. **Fee Quote Expiry**: The fee quote expiry is checked within the circuit, but there's no mechanism to prevent submission of a valid proof after expiry.
   - **Mitigation**: External systems must enforce time-based constraints.

2. **BTC Address Validation**: The circuit does not validate that the destination BTC address is well-formed.
   - **Mitigation**: External validation is required and documented.

#### Transfer Circuit
1. **Asset Type Limitations**: The current implementation assumes homogeneous asset types within a transfer.
   - **Mitigation**: This is a design choice for simplicity. Multi-asset transfers would require a different circuit design.

2. **Maximum Input/Output Limits**: There are practical limits to the number of inputs and outputs in a transfer due to circuit size constraints.
   - **Mitigation**: Documented with recommended maximums.

### Recursive Proof Aggregation
1. **Verification Key Size**: The verification key size grows with the number of different circuit types being aggregated.
   - **Mitigation**: Recommended patterns for aggregation are documented.

2. **Depth Limitations**: There are practical limits to the depth of recursive aggregation before performance becomes prohibitive.
   - **Mitigation**: Benchmarks and recommendations are provided.

## Implementation Limitations

### Memory Usage
1. **Witness Generation**: Witness generation for large circuits can consume significant memory.
   - **Mitigation**: Incremental witness generation is implemented but has performance trade-offs.

2. **Parallel Proof Generation**: Parallel proof generation can lead to high memory usage when many proofs are generated simultaneously.
   - **Mitigation**: Configurable batch sizes and memory limits are provided.

### Performance
1. **Proof Generation Time**: Proof generation is computationally expensive, especially for complex circuits.
   - **Mitigation**: Performance characteristics are documented, and optimizations have been implemented where possible.

2. **Verification Time**: While verification is faster than generation, it can still be a bottleneck for high-throughput applications.
   - **Mitigation**: Recursive aggregation provides amortized verification cost improvements.

### Cross-Platform Support
1. **WebAssembly Limitations**: The WASM implementation has performance limitations compared to native code.
   - **Mitigation**: Performance characteristics are documented, and optimizations have been implemented where possible.

2. **Mobile Support**: The current implementation has not been optimized for mobile devices.
   - **Mitigation**: This is a known limitation that could be addressed in future versions.

## Security Considerations

### Nullifier Collision
1. **Theoretical Collision Risk**: While cryptographically unlikely, there is a theoretical risk of nullifier collisions.
   - **Mitigation**: The probability is negligible (approximately 2^-128), and the impact would be limited to specific UTXOs.

### Fee Mechanism
1. **Fee Sniping**: In certain scenarios, fee sniping attacks could be possible if transaction ordering is not properly enforced.
   - **Mitigation**: External systems must enforce appropriate transaction ordering, as documented.

### Privacy Considerations
1. **Transaction Graph Analysis**: The current design does not implement advanced privacy features like confidential transactions or zero-knowledge sets.
   - **Mitigation**: This is a design choice, not a vulnerability. Future versions could incorporate additional privacy features.

2. **Metadata Leakage**: Public inputs to circuits may leak metadata about transactions.
   - **Mitigation**: Design patterns to minimize metadata leakage are documented.

## Integration Risks

### External System Dependencies
1. **Custodian System Security**: The security of wrapped assets depends on the security of the custodian system.
   - **Mitigation**: Integration guide provides recommendations for custodian system security.

2. **Blockchain Integration**: Integration with specific blockchains may introduce additional security considerations.
   - **Mitigation**: Integration guide provides general recommendations, but specific blockchain integrations require additional review.

### Configuration Risks
1. **Insecure Defaults**: While secure defaults are provided, misconfiguration remains a risk.
   - **Mitigation**: Configuration options are documented with security implications.

2. **Parameter Selection**: Incorrect parameter selection (e.g., for circuit configuration) could impact security or performance.
   - **Mitigation**: Recommended parameters are provided and documented.

## Known Edge Cases

### Cryptographic Edge Cases
1. **Zero Values**: Special handling is required for zero values in certain cryptographic operations.
   - **Mitigation**: Zero value handling is explicitly implemented and tested.

2. **Maximum Field Values**: Operations with maximum field values require special consideration.
   - **Mitigation**: Tests include maximum field value cases.

### Circuit Edge Cases
1. **Empty Inputs**: Circuits may behave unexpectedly with empty input sets.
   - **Mitigation**: Input validation prevents empty inputs where appropriate.

2. **Maximum Capacity**: Circuits at maximum capacity (e.g., maximum inputs/outputs) may have different performance characteristics.
   - **Mitigation**: Tests include maximum capacity cases.

### Integration Edge Cases
1. **Concurrent Operations**: Concurrent operations on the same UTXO set may lead to race conditions.
   - **Mitigation**: Integration guide provides recommendations for concurrency control.

2. **Network Partitions**: Network partitions could lead to inconsistent state in distributed deployments.
   - **Mitigation**: Integration guide provides recommendations for handling network partitions.

## Conclusion
This document outlines the known limitations and edge cases in the 0BTC Wire project. While efforts have been made to mitigate these issues where possible, they represent inherent trade-offs or design choices that users and integrators should be aware of. This information is provided to assist auditors in understanding the security posture of the project and to help users make informed decisions about its use.
