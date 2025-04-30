# 0BTC Wire Security Model

## Overview

This document outlines the security model of the 0BTC Wire zero-knowledge proof system, including its security properties, assumptions, and error handling approach. It serves as a reference for developers, auditors, and integrators.

## Security Properties

### 1. Zero-Knowledge Proofs

The 0BTC Wire system uses Plonky2, a SNARK (Succinct Non-interactive Argument of Knowledge) system, to create zero-knowledge proofs with the following properties:

- **Completeness**: Honest provers can convince verifiers of valid statements.
- **Soundness**: Malicious provers cannot convince verifiers of invalid statements.
- **Zero-Knowledge**: Verifiers learn nothing about the witness beyond the validity of the statement.
- **Succinctness**: Proofs are small and verification is efficient.

### 2. Cryptographic Primitives

The system relies on several cryptographic primitives, each with specific security properties:

- **Poseidon Hash Function**: A SNARK-friendly cryptographic hash function with collision resistance and preimage resistance.
- **Ed25519 Signatures**: A secure digital signature scheme with existential unforgeability under chosen message attacks.
- **Merkle Trees**: Used for efficient membership proofs with collision resistance.
- **Nullifiers**: Prevent double-spending by creating unique, one-time identifiers for spent UTXOs.

### 3. Domain Separation

All hash functions in the system use domain separation to prevent cross-protocol attacks:

- Each hash function has a unique domain separator prepended to its input.
- Different contexts (signature, Merkle, nullifier, etc.) use different domain separators.
- Empty inputs are handled securely by using domain separators.

### 4. Input Validation

The system implements comprehensive input validation at all interfaces:

- **CLI Interface**: Validates file paths, circuit types, batch sizes, and proof structures.
- **WASM Interface**: Validates hex strings, keys, signatures, hashes, and circuit parameters.
- **Circuit Constraints**: Enforces validity of all inputs within the ZK circuits.

## Security Assumptions

The security of the 0BTC Wire system relies on the following assumptions:

1. **Cryptographic Assumptions**:
   - The security of the Goldilocks field (2^64 - 2^32 + 1) for finite field operations.
   - The hardness of the discrete logarithm problem in the Ed25519 curve.
   - The collision resistance of the Poseidon hash function.

2. **Implementation Assumptions**:
   - Correct implementation of the Plonky2 proving system.
   - Proper constraint generation in all circuits.
   - Secure random number generation for keys, salts, and nonces.

3. **Operational Assumptions**:
   - Secure key management by users.
   - Proper validation of proofs by verifiers.
   - Correct implementation of the recursive proof aggregation system.

## Error Handling Approach

The 0BTC Wire system implements a structured error handling approach to prevent security vulnerabilities:

### 1. Error Types

The system defines a hierarchy of error types in `src/errors.rs`:

- **WireError**: The top-level error type that wraps all other error types.
- **CryptoError**: Errors related to cryptographic operations.
- **CircuitError**: Errors related to circuit creation and constraint generation.
- **IOError**: Errors related to file operations and serialization.
- **ProofError**: Errors related to proof generation, verification, and aggregation.
- **ValidationError**: Errors related to input validation.

### 2. Error Sanitization

To prevent information leakage, the system sanitizes error messages before exposing them to external interfaces:

- Internal error messages may contain detailed information for debugging.
- External error messages are sanitized to remove potentially sensitive information.
- The `sanitize_error_message` function in `src/errors.rs` handles this sanitization.

### 3. Validation Chain

Input validation follows a chain of responsibility pattern:

1. **Interface Validation**: The CLI and WASM interfaces validate all inputs before processing.
2. **Parameter Validation**: Functions validate their parameters before performing operations.
3. **Constraint Validation**: ZK circuits enforce constraints on all inputs.

This multi-layered approach ensures that invalid inputs are rejected as early as possible.

## Security Boundaries

The 0BTC Wire system has the following security boundaries:

1. **Trusted Computing Base**:
   - The Plonky2 proving system.
   - The Rust compiler and standard library.
   - The operating system's random number generator.

2. **Untrusted Inputs**:
   - All user inputs (files, parameters, proofs).
   - Network communications.
   - External data sources.

3. **Trust Assumptions**:
   - Users must keep their private keys secure.
   - Verifiers must correctly implement the verification protocol.
   - The system assumes that the cryptographic primitives are secure.

## Security Best Practices

When integrating with the 0BTC Wire system, follow these best practices:

1. **Input Validation**:
   - Always validate all inputs before processing.
   - Use the provided validation functions in `src/cli/validation.rs` and `src/wasm/validation.rs`.
   - Never trust external inputs without validation.

2. **Error Handling**:
   - Use the structured error types in `src/errors.rs`.
   - Sanitize error messages before exposing them to users.
   - Log detailed error information for debugging, but only expose sanitized messages.

3. **Cryptographic Operations**:
   - Use the provided cryptographic primitives with their domain separators.
   - Never implement custom cryptographic operations without review.
   - Always use secure random number generation for keys, salts, and nonces.

4. **Circuit Development**:
   - Always enforce constraints on all inputs.
   - Use assertions for security-critical checks.
   - Test circuits with both valid and invalid inputs.

## Security Testing

The 0BTC Wire system includes comprehensive security testing:

1. **Unit Tests**:
   - Test all cryptographic primitives with known test vectors.
   - Test input validation with both valid and invalid inputs.
   - Test error handling with all error types.

2. **Integration Tests**:
   - Test the entire system with realistic use cases.
   - Test error handling across component boundaries.
   - Test performance under various conditions.

3. **Fuzz Testing**:
   - Test with randomly generated inputs to find edge cases.
   - Test with malformed inputs to ensure proper error handling.
   - Test with boundary values to ensure correct behavior.

## Conclusion

The 0BTC Wire system implements a comprehensive security model with multiple layers of protection. By following the best practices outlined in this document, developers can ensure that their integrations maintain the security properties of the system.

For more detailed information, refer to the following resources:

- [Security Audit](security_audit.md): Detailed findings and recommendations from the security audit.
- [Implementation Status](implementation_status.md): Current status of security improvements.
- [API Documentation](api_docs.md): Detailed documentation of the API, including security considerations.
