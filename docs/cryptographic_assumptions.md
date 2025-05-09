# 0BTC Wire Cryptographic Assumptions and Security Properties

## Introduction

This document outlines the cryptographic assumptions and security properties of the 0BTC Wire zero-knowledge proof system. It is intended to provide auditors with a clear understanding of the security foundations of the system and the properties that should be verified during the audit.

## Cryptographic Assumptions

### 1. Discrete Logarithm Assumption

The security of the Ed25519 signature scheme relies on the hardness of the discrete logarithm problem in the Edwards curve used by Ed25519 (Curve25519). Specifically, given a point P = xG, where G is the base point of the curve, it should be computationally infeasible to determine x.

**Implications for 0BTC Wire**: The security of signature verification in the system depends on this assumption. If this assumption were to be broken, an attacker could potentially forge signatures and create fraudulent proofs.

### 2. Collision Resistance of Poseidon Hash

The Poseidon hash function is assumed to be collision-resistant, meaning it should be computationally infeasible to find two different inputs that produce the same hash output.

**Implications for 0BTC Wire**: The system uses Poseidon for various purposes, including nullifier calculation, Merkle tree construction, and domain separation. If collision resistance were broken, an attacker might be able to create fraudulent proofs or double-spend UTXOs.

### 3. Pre-image Resistance of Poseidon Hash

The Poseidon hash function is assumed to be pre-image resistant, meaning given a hash output h, it should be computationally infeasible to find an input x such that hash(x) = h.

**Implications for 0BTC Wire**: Pre-image resistance is crucial for the security of nullifiers and Merkle tree commitments. If broken, an attacker might be able to reverse-engineer private inputs from public outputs.

### 4. Algebraic Knowledge Soundness of Plonky2

Plonky2, the underlying zero-knowledge proof system, relies on the algebraic knowledge soundness assumption, which states that a prover can only generate a valid proof if they know a valid witness for the statement being proven.

**Implications for 0BTC Wire**: This assumption is fundamental to the security of all proofs generated by the system. If broken, an attacker could potentially generate valid proofs for false statements.

### 5. Random Oracle Model

The Fiat-Shamir heuristic used to make the proof system non-interactive assumes the hash function behaves as a random oracle.

**Implications for 0BTC Wire**: This assumption is necessary for the security of the non-interactive proof system. If broken, the zero-knowledge and soundness properties might be compromised.

### 6. Computational Hardness of the Underlying Field

The security of the proof system relies on the computational hardness of certain problems in the underlying field (Goldilocks field with modulus 2^64 - 2^32 + 1).

**Implications for 0BTC Wire**: This assumption underpins the security of the entire proof system. If broken, the entire system's security would be compromised.

## Security Properties

### 1. Completeness

**Property**: If a statement is true and the prover knows a witness, then the prover can convince the verifier of this fact with overwhelming probability.

**Verification Approach**: Test that valid proofs for all circuit types are accepted by the verification algorithm.

### 2. Soundness

**Property**: If a statement is false, no malicious prover can convince the verifier that it is true, except with negligible probability.

**Verification Approach**: Test that invalid proofs (e.g., with incorrect signatures, invalid UTXOs, or conservation of value violations) are rejected by the verification algorithm.

### 3. Zero-Knowledge

**Property**: The proof reveals nothing about the witness beyond the validity of the statement being proven.

**Verification Approach**: Analyze the circuit implementations to ensure that private inputs are properly separated from public inputs, and that no information about private inputs is leaked through public inputs or the proof itself.

### 4. Conservation of Value

**Property**: In transfer operations, the sum of input values must equal the sum of output values (plus fees).

**Verification Approach**: Verify that the circuit enforces this constraint and that it cannot be bypassed.

### 5. Ownership Verification

**Property**: Only the owner of a UTXO (possessing the corresponding private key) can spend it.

**Verification Approach**: Verify that the circuit properly enforces signature verification and that signatures cannot be forged or reused.

### 6. Double-Spend Prevention

**Property**: A UTXO cannot be spent more than once.

**Verification Approach**: Verify that the nullifier calculation is correct and that nullifiers are properly registered and checked.

### 7. Domain Separation

**Property**: Different hash operations for different purposes use domain separation to prevent cross-protocol attacks.

**Verification Approach**: Verify that domain separation is consistently applied across all hash operations.

## Security Boundaries and Trust Model

### Security Boundaries

1. **Circuit Implementation**: The security boundary includes all circuit implementations and the gadgets they use.
2. **Proof Generation**: The security boundary includes the proof generation process, including witness generation and the Plonky2 prover.
3. **Proof Verification**: The security boundary includes the proof verification process, including the Plonky2 verifier.
4. **CLI and WASM Interfaces**: The security boundary includes the user-facing interfaces, including input validation and error handling.

### Trust Model

1. **Trusted Components**:
   - The cryptographic primitives (Ed25519, Poseidon)
   - The Plonky2 proving system
   - The underlying hardware and operating system

2. **Untrusted Components**:
   - User inputs
   - Network communications
   - External systems integrating with 0BTC Wire

3. **Trust Assumptions**:
   - Users must keep their private keys secure
   - Verifiers must correctly implement the verification protocol
   - The custodian system for wrapped assets must be secure

## Cryptographic Parameter Selection

### Ed25519 Parameters

The Ed25519 signature scheme uses the following parameters:
- Curve: Edwards25519 (a twisted Edwards curve)
- Base field: Prime field with modulus 2^255 - 19
- Cofactor: 8
- Hash function: SHA-512

These parameters were chosen for their security properties and efficiency.

### Poseidon Parameters

The Poseidon hash function uses the following parameters:
- Field: Goldilocks field with modulus 2^64 - 2^32 + 1
- Security level: 128 bits
- Sponge capacity: 2 field elements
- Sponge rate: Variable, depending on the application
- Number of rounds: Full rounds (8) and partial rounds (22)

These parameters were chosen to provide a balance between security and efficiency in the context of zero-knowledge proofs.

### Plonky2 Parameters

The Plonky2 proving system uses the following parameters:
- Field: Goldilocks field with modulus 2^64 - 2^32 + 1
- Extension degree: 2
- Number of challenges: 4
- FRI folding factor: 4
- FRI max degree bits: 20
- FRI max query rate: 8

These parameters were chosen to provide a balance between proof size, proving time, and verification time.

## Conclusion

This document has outlined the cryptographic assumptions and security properties of the 0BTC Wire zero-knowledge proof system. Understanding these assumptions and properties is crucial for auditors to effectively evaluate the security of the system. The audit should verify that these assumptions are valid and that the security properties are properly enforced by the implementation.
