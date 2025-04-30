# 0BTC Wire Audit Scope

## Introduction

This document defines the scope of the external security audit for the 0BTC Wire project. It outlines the components to be audited, the audit objectives, and the expected deliverables. This document serves as a reference for both the audit team and the project team to ensure a comprehensive and focused security review.

## Project Overview

0BTC Wire is a zero-knowledge proof system for Bitcoin wrapping and transfer operations. It enables secure, verifiable transactions with wrapped Bitcoin (wBTC) using zero-knowledge proofs based on the Plonky2 proving system. The project includes cryptographic gadgets, circuit implementations, CLI and WASM interfaces, and supporting utilities.

## Audit Objectives

The primary objectives of this audit are to:

1. Identify security vulnerabilities, weaknesses, and risks in the codebase
2. Verify the correctness of cryptographic implementations
3. Assess the robustness of the zero-knowledge proof system
4. Evaluate the security of the overall system architecture
5. Provide recommendations for security improvements

## In-Scope Components

The following components are in scope for the audit:

### Core Cryptographic Components

- **Ed25519 Implementation**: The implementation of Ed25519 signature verification in `src/gadgets/signature.rs`
- **Poseidon Hash Function**: The implementation of the Poseidon hash function in `src/gadgets/hash.rs`
- **Merkle Proof Verification**: The implementation of Merkle proof verification in `src/gadgets/merkle.rs`
- **Nullifier Calculation**: The implementation of nullifier calculation in `src/gadgets/nullifier.rs`

### Circuit Implementations

- **WrappedAssetMint Circuit**: The implementation in `src/circuits/wrapped_asset_mint.rs`
- **WrappedAssetBurn Circuit**: The implementation in `src/circuits/wrapped_asset_burn.rs`
- **Transfer Circuit**: The implementation in `src/circuits/transfer.rs`
- **NativeAssetCreate Circuit**: The implementation in `src/circuits/native_asset_create.rs`
- **NativeAssetMint Circuit**: The implementation in `src/circuits/native_asset_mint.rs`
- **NativeAssetBurn Circuit**: The implementation in `src/circuits/native_asset_burn.rs`

### Proof Generation and Verification

- **Proof Utilities**: The implementation in `src/core/proof.rs`
- **Recursive Proof Aggregation**: The implementation in `src/utils/recursive_prover.rs`

### User-Facing Interfaces

- **CLI Implementation**: The implementation in `src/cli/`
- **WASM Implementation**: The implementation in `src/wasm/`

### Advanced Features

- **Memory-Efficient Proof Generation**: The implementation in `src/utils/memory_efficient.rs`
- **Specialized Gadgets**: The implementation in `src/gadgets/specialized.rs`
- **Configuration System**: The implementation in `src/cli/config.rs`
- **Batch Processing**: The implementation in `src/cli/batch.rs`
- **Workflow System**: The implementation in `src/cli/workflow.rs`

## Out-of-Scope Components

The following components are out of scope for the audit:

- **External Dependencies**: Third-party libraries and dependencies, including Plonky2 itself
- **Demo Applications**: Example applications and demos in the `examples/` directory
- **Documentation**: Documentation files in the `docs/` directory
- **Tests**: Test files and test utilities
- **Build Scripts**: Build scripts and configuration files
- **CI/CD Pipeline**: Continuous integration and deployment configuration

## Audit Methodology

We expect the audit to include the following activities:

1. **Manual Code Review**: A comprehensive review of the in-scope components
2. **Automated Analysis**: Use of static analysis tools to identify potential vulnerabilities
3. **Cryptographic Analysis**: Review of cryptographic implementations for correctness and security
4. **Circuit Analysis**: Review of circuit implementations for correctness and security
5. **Test Vector Verification**: Verification of provided test vectors
6. **Edge Case Testing**: Testing of edge cases and boundary conditions

## Known Issues and Limitations

Please refer to the [Known Limitations and Edge Cases](known_limitations_and_edge_cases.md) document for a comprehensive list of known issues and limitations.

## Audit Deliverables

We expect the following deliverables from the audit:

1. **Audit Report**: A comprehensive report detailing the findings, including:
   - Executive summary
   - Methodology
   - Findings with severity ratings
   - Recommendations for remediation
   - Detailed technical descriptions of each finding

2. **Findings Database**: A structured database of findings, including:
   - Severity rating
   - Description
   - Location in the codebase
   - Potential impact
   - Recommended remediation

3. **Remediation Review**: A review of the remediation of findings, including:
   - Verification of fixes
   - Assessment of the effectiveness of the remediation
   - Recommendations for further improvements

## Severity Ratings

Findings should be classified according to the following severity ratings:

- **Critical**: Vulnerabilities that can lead to asset loss, compromise of the system, or other severe security issues
- **High**: Vulnerabilities that can have a significant impact on the security of the system but do not immediately lead to asset loss
- **Medium**: Vulnerabilities that have a moderate impact on the security of the system
- **Low**: Vulnerabilities that have a minor impact on the security of the system
- **Informational**: Issues that do not pose a security risk but may affect the quality, maintainability, or performance of the system

## Timeline and Logistics

- **Audit Duration**: 4 weeks
- **Start Date**: TBD
- **End Date**: TBD
- **Communication Channel**: [Specify communication channel]
- **Point of Contact**: [Specify point of contact]

## Additional Resources

The following resources are available to the audit team:

1. **Test Vectors**: A comprehensive set of test vectors for all in-scope components
2. **Documentation**: Detailed documentation of the system architecture, cryptographic protocols, and implementation details
3. **Development Team**: Access to the development team for questions and clarifications
4. **Source Code**: Access to the full source code repository

## Conclusion

This audit scope document outlines the components to be audited, the audit objectives, and the expected deliverables. It serves as a reference for both the audit team and the project team to ensure a comprehensive and focused security review. We look forward to working with the audit team to improve the security of the 0BTC Wire project.
