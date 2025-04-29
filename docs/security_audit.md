# 0BTC Wire Security Audit Guide

This document outlines the security audit process for the 0BTC Wire project, focusing on the cryptographic implementations, constraint enforcement, and potential attack vectors.

## Table of Contents

1. [Audit Objectives](#audit-objectives)
2. [Scope](#scope)
3. [Methodology](#methodology)
4. [Critical Components](#critical-components)
5. [Known Attack Vectors](#known-attack-vectors)
6. [Security Properties](#security-properties)
7. [Audit Checklist](#audit-checklist)
8. [Findings and Recommendations](#findings-and-recommendations)
9. [References](#references)

## Audit Objectives

The primary objectives of this security audit are to:

1. Ensure the correctness of all cryptographic implementations
2. Verify proper constraint enforcement in zero-knowledge circuits
3. Identify and mitigate potential attack vectors
4. Document security properties and assumptions
5. Provide recommendations for security improvements

## Scope

The audit covers the following components of the 0BTC Wire project:

1. **Cryptographic Implementations**
   - EdDSA signature verification
   - Poseidon hash function
   - Merkle proof verification
   - Nullifier generation

2. **Circuit Implementations**
   - WrappedAssetMint circuit
   - WrappedAssetBurn circuit
   - Transfer circuit
   - NativeAssetCreate circuit
   - NativeAssetMint circuit
   - NativeAssetBurn circuit

3. **Recursive Proof Aggregation**
   - Aggregation logic
   - Verification logic

4. **Input Validation**
   - CLI input validation
   - WASM input validation

## Methodology

The security audit will follow these steps:

1. **Code Review**
   - Manual review of cryptographic implementations
   - Analysis of constraint enforcement
   - Verification of input validation

2. **Testing**
   - Unit tests for cryptographic functions
   - Integration tests for circuits
   - Fuzz testing for input validation

3. **Attack Simulation**
   - Attempt to forge signatures
   - Try to create invalid proofs
   - Test double-spending scenarios

4. **Documentation Review**
   - Verify security assumptions
   - Check for documented limitations
   - Ensure proper error handling

## Critical Components

### EdDSA Signature Verification

The EdDSA signature verification is a critical component of the 0BTC Wire project, as it ensures that only authorized users can spend UTXOs. The implementation must correctly verify signatures according to the EdDSA specification.

Key security properties:
- Signature verification must be complete and sound
- No shortcuts or optimizations should compromise security
- The implementation should be resistant to side-channel attacks

### Poseidon Hash Function

The Poseidon hash function is used for various purposes, including UTXO commitment, nullifier generation, and Merkle tree construction. The implementation must provide the security properties expected of a cryptographic hash function.

Key security properties:
- Collision resistance
- Preimage resistance
- Second preimage resistance
- No optimizations should compromise these properties

### Merkle Proof Verification

Merkle proof verification is used to prove inclusion of UTXOs in the state tree. The implementation must correctly verify Merkle proofs according to the Merkle tree specification.

Key security properties:
- Proof verification must be complete and sound
- No shortcuts or optimizations should compromise security
- The implementation should handle edge cases correctly

### Nullifier Generation

Nullifier generation is used to prevent double-spending of UTXOs. The implementation must ensure that nullifiers are unique for each UTXO and cannot be forged.

Key security properties:
- Nullifiers must be unique for each UTXO
- Nullifiers must be deterministic
- Nullifiers must be unpredictable without knowledge of the private key

## Known Attack Vectors

### Double-Spending Attacks

Double-spending attacks involve spending the same UTXO multiple times. The 0BTC Wire project prevents this through nullifiers, which are published when a UTXO is spent. The nullifier generation and verification logic must be secure to prevent double-spending.

Mitigation:
- Ensure nullifiers are correctly generated and verified
- Verify that nullifiers are properly recorded and checked

### Signature Forgery Attacks

Signature forgery attacks involve creating valid signatures without knowledge of the private key. The EdDSA signature verification logic must be secure to prevent signature forgery.

Mitigation:
- Ensure signature verification is implemented correctly
- Verify that no shortcuts or optimizations compromise security

### Invalid Proof Attacks

Invalid proof attacks involve creating proofs that verify successfully but do not satisfy the circuit constraints. The proof verification logic must be secure to prevent invalid proof attacks.

Mitigation:
- Ensure all constraints are properly enforced
- Verify that the proof verification logic is complete and sound

### Front-Running Attacks

Front-running attacks involve observing pending transactions and submitting competing transactions with higher fees. While this is primarily a concern for the blockchain layer, the 0BTC Wire project should be designed to minimize the impact of front-running.

Mitigation:
- Consider implementing commit-reveal schemes for sensitive operations
- Document front-running risks and mitigation strategies

## Security Properties

The 0BTC Wire project should provide the following security properties:

1. **Confidentiality**: The contents of UTXOs should be confidential, with only the owner able to reveal the details.
2. **Integrity**: The state of the system should be protected from unauthorized modifications.
3. **Availability**: The system should be available for legitimate users to create and verify proofs.
4. **Authentication**: Only authorized users should be able to spend UTXOs.
5. **Non-repudiation**: Users should not be able to deny having spent UTXOs.
6. **Unlinkability**: It should be difficult to link different transactions to the same user.
7. **Forward secrecy**: Compromise of a private key should not reveal information about past transactions.

## Audit Checklist

### Cryptographic Implementations

- [ ] EdDSA signature verification follows the specification
- [ ] Poseidon hash function is implemented correctly
- [ ] Merkle proof verification is sound and complete
- [ ] Nullifier generation produces unique and unpredictable values
- [ ] No cryptographic shortcuts compromise security
- [ ] All cryptographic operations use constant-time implementations where applicable
- [ ] Random number generation is secure and properly seeded

### Circuit Implementations

- [ ] All circuits enforce the correct constraints
- [ ] No constraints are missing or redundant
- [ ] Public inputs are properly validated
- [ ] Private inputs are properly handled
- [ ] Circuit optimizations do not compromise security
- [ ] Edge cases are properly handled
- [ ] Error handling is comprehensive and secure

### Recursive Proof Aggregation

- [ ] Aggregation logic preserves the security of individual proofs
- [ ] Verification logic is sound and complete
- [ ] No security compromises in the aggregation process
- [ ] Edge cases are properly handled
- [ ] Error handling is comprehensive and secure

### Input Validation

- [ ] CLI input validation is comprehensive
- [ ] WASM input validation is comprehensive
- [ ] No input can cause unexpected behavior
- [ ] Error handling is comprehensive and secure
- [ ] Input size limits are enforced
- [ ] Input format is validated

## Findings and Recommendations

### Initial Findings (2025-04-30)

#### EdDSA Signature Verification

1. **Implementation Correctness**: 
   - The EdDSA signature verification implementation correctly follows the standard algorithm
   - All required steps are properly implemented: curve point validation, hash computation, and equation verification
   - Special cases (identity point, small scalar values) are handled correctly in scalar multiplication

2. **Security Considerations**:
   - The `is_on_curve` function returns a Target (0 or 1) rather than constraining the point to be on the curve
   - The batch verification uses a simplified approach for generating random weights, which could potentially be predictable
   - The implementation assumes that the inputs are properly validated before being passed to the verification function

3. **Recommendations**:
   - Modify `is_on_curve` to use `builder.assert_is_equal` to enforce the constraint rather than returning a Target
   - Improve the randomness source for batch verification weights to use a more secure method
   - Add explicit input validation for signature components

#### Poseidon Hash Function

1. **Implementation Correctness**:
   - The hash implementation correctly uses Plonky2's built-in Poseidon hash function
   - Optimized versions for different input sizes are provided to reduce constraint count
   - The UTXO hashing approach is hierarchical and efficient

2. **Security Considerations**:
   - Multiple hash implementations (original, optimized, specialized) could lead to inconsistencies
   - Empty input handling returns a constant value (0), which might not be ideal for security
   - The optimized implementations might have different security properties than the standard ones

3. **Recommendations**:
   - Standardize on a single hash implementation with optimizations under the hood
   - Use a more secure approach for empty input handling (e.g., hash a fixed non-zero value)
   - Document the security assumptions and properties of each hash implementation

#### Nullifier Generation

1. **Implementation Correctness**:
   - The nullifier calculation correctly combines salt and owner's secret key
   - The nullifier is properly registered as a public input
   - The implementation is simple and straightforward

2. **Security Considerations**:
   - The nullifier calculation uses the owner's secret key directly, which could potentially leak information
   - There is no domain separation between different hash usages
   - The nullifier is deterministic, which could potentially be used for tracking

3. **Recommendations**:
   - Consider using a derived key for nullifier generation rather than the owner's secret key directly
   - Add domain separation to the hash function (e.g., prefix with a context string)
   - Consider adding randomness to the nullifier generation process to improve privacy

#### Transfer Circuit

1. **Implementation Correctness**:
   - The circuit correctly verifies ownership of input UTXOs through signature verification
   - Conservation of value is properly enforced (input_sum >= output_sum)
   - Fee payment is properly enforced through the enforce_fee_payment gadget
   - Nullifiers are calculated and registered for all input UTXOs

2. **Security Considerations**:
   - The message signed by the sender includes recipient details, output amounts, asset ID, and a nonce, but does not include the fee amount or fee reservoir address
   - The nonce is a virtual target without explicit randomness requirements
   - The circuit assumes all input UTXOs have the same asset ID without explicit verification

3. **Recommendations**:
   - Include fee amount and fee reservoir address in the signed message
   - Add explicit randomness requirements for the nonce
   - Add explicit verification that all input UTXOs have the same asset ID

#### Wrapped Asset Mint Circuit

1. **Implementation Correctness**:
   - The circuit correctly verifies the custodian's signature on the attestation
   - The attestation includes recipient public key hash, amount, and deposit nonce
   - The output UTXO is created with the correct owner, asset ID, and amount

2. **Security Considerations**:
   - The deposit nonce is used to prevent replay attacks but there's no mechanism to track used nonces
   - There's no validation that the custodian's public key is authorized
   - The circuit doesn't enforce any limits on the mint amount

3. **Recommendations**:
   - Implement a mechanism to track and validate used nonces
   - Add a registry of authorized custodian public keys
   - Consider adding mint amount limits based on business requirements

#### Recursive Proof Aggregation

1. **Implementation Correctness**:
   - The recursive circuit setup correctly creates a circuit for proof aggregation
   - The base proof creation and proof extension logic are sound
   - The aggregation process handles batching appropriately

2. **Security Considerations**:
   - The condition for recursive verification is a virtual boolean target without explicit enforcement
   - The public inputs handling in the extension process is simplified and may not be appropriate for all circuit types
   - There's no validation that proofs being aggregated are of the same circuit type

3. **Recommendations**:
   - Add explicit enforcement of the condition for recursive verification
   - Implement more robust public input handling for different circuit types
   - Add validation to ensure proofs being aggregated are compatible

#### CLI Input Validation

1. **Implementation Correctness**:
   - The CLI uses clap for command-line argument parsing with appropriate types
   - Helper functions are provided for extracting and validating JSON values
   - Proof structure verification is implemented before processing

2. **Security Considerations**:
   - The `verify_proof_structure` function checks structure but not semantic validity
   - File paths are used without sanitization or validation
   - Error handling returns string messages without structured error types

3. **Recommendations**:
   - Enhance proof structure verification to include semantic validation
   - Add path sanitization and validation for file operations
   - Implement structured error types for better error handling

#### WASM Input Validation

1. **Implementation Correctness**:
   - The WASM interface properly initializes with error handling
   - Input parameters are validated before processing
   - Results are properly serialized for JavaScript consumption

2. **Security Considerations**:
   - The keypair generation uses OsRng which may have different security properties in a browser context
   - Some functions have incomplete input validation (e.g., `prove_native_asset_create`)
   - Error messages may leak sensitive information

3. **Recommendations**:
   - Review and enhance random number generation for browser contexts
   - Complete input validation for all WASM functions
   - Sanitize error messages to prevent information leakage

### Summary of Key Findings

1. **Signature Verification**:
   - The EdDSA signature verification implementation is generally correct but needs stronger constraint enforcement
   - Batch verification needs more secure randomness for weights
   - Signed messages should include all relevant parameters

2. **Hash Functions**:
   - Multiple hash implementations could lead to inconsistencies
   - Empty input handling needs improvement
   - Domain separation should be added for different hash usages

3. **Nullifier Generation**:
   - The nullifier calculation uses the owner's secret key directly, which could leak information
   - Domain separation should be added
   - Consider adding randomness for improved privacy

4. **Circuit Implementations**:
   - Conservation of value is properly enforced
   - Nonce handling needs improvement
   - Asset ID verification should be more explicit

5. **Recursive Proof Aggregation**:
   - The implementation is sound but needs more robust public input handling
   - Proof compatibility validation should be added
   - Condition enforcement should be more explicit

6. **Input Validation**:
   - CLI and WASM interfaces have basic validation but need enhancement
   - Path sanitization and structured error handling should be added
   - Random number generation in browser contexts needs review

### Next Steps

1. **Implement High-Priority Fixes**:
   - Add domain separation to hash functions
   - Enhance constraint enforcement in signature verification
   - Improve nonce handling and validation
   - Add explicit asset ID verification

2. **Enhance Input Validation**:
   - Implement comprehensive validation for all interfaces
   - Add path sanitization for file operations
   - Implement structured error handling

3. **Improve Security Documentation**:
   - Document security assumptions and properties
   - Create a security model for the system
   - Provide guidelines for secure usage

## References

1. [EdDSA Specification](https://datatracker.ietf.org/doc/html/rfc8032)
2. [Poseidon Hash Function Paper](https://eprint.iacr.org/2019/458.pdf)
3. [Plonky2 Documentation](https://github.com/mir-protocol/plonky2)
4. [Zero-Knowledge Proofs: An Illustrated Primer](https://blog.cryptographyengineering.com/2014/11/27/zero-knowledge-proofs-illustrated-primer/)
5. [Common Pitfalls in Zero-Knowledge Proof Implementations](https://eprint.iacr.org/2019/1128.pdf)
