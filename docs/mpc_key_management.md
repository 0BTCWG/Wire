# MPC Key Management for 0BTC Wire

## Introduction

This document details the key management practices for the Multi-Party Computation (MPC) custodian system used in 0BTC Wire. Secure key management is critical for the safety of the bridge between Bitcoin and the 0BTC Wire system.

## Key Types and Roles

The 0BTC Wire MPC system uses the following types of keys:

1. **MPC Key Shares**: Distributed fragments of the main signing key, where no single party possesses the complete key.
2. **TLS Certificates**: Used for secure communication between MPC operator nodes.
3. **Bitcoin Keys**: Used for managing Bitcoin deposits and withdrawals.

## Distributed Key Generation (DKG)

The MPC system uses a Distributed Key Generation (DKG) ceremony to create key shares without ever constructing the complete private key in any single location.

### DKG Ceremony Process

1. **Initialization**: Each operator initializes their node with a unique index and the addresses of all participating nodes.
2. **Commitment Phase**: Each operator generates random values and broadcasts commitments to these values.
3. **Share Distribution**: Each operator creates key shares for all other operators and distributes them securely.
4. **Verification**: Each operator verifies the shares they received from other operators.
5. **Key Share Computation**: Each operator computes their final key share.
6. **Public Key Computation**: All operators compute the same public key, which is used for verification.

### Security Properties

- **No Single Point of Failure**: The private key is never reconstructed in full at any point.
- **Threshold Security**: The system can tolerate up to `t-1` compromised operators in a `t-of-n` threshold scheme.
- **Verifiability**: All operators can verify that the DKG ceremony was conducted correctly.

## Key Share Storage

Key shares must be stored securely by each operator. Recommended practices include:

1. **Hardware Security Modules (HSMs)**: Store key shares in HSMs that support the Ed25519 algorithm.
2. **Encrypted Storage**: If HSMs are not available, encrypt key shares at rest using strong encryption.
3. **Backup Procedures**: Maintain secure, encrypted backups of key shares in separate physical locations.
4. **Access Controls**: Implement strict access controls for key share access, including multi-factor authentication.

## Key Rotation

Regular key rotation is recommended to maintain security:

1. **Scheduled Rotation**: Perform a complete DKG ceremony every 6-12 months.
2. **Emergency Rotation**: Perform an immediate key rotation if any operator suspects their key share may be compromised.
3. **Operator Change**: Perform a key rotation when adding or removing operators from the MPC system.

## Signing Ceremonies

When a signature is needed (for mint attestations, withdrawals, or fee consolidation), a signing ceremony is conducted:

1. **Initialization**: The initiating operator creates a signing request with the message to be signed.
2. **Approval**: Each participating operator reviews and approves the signing request.
3. **Share Generation**: Each participating operator generates a signature share using their key share.
4. **Share Collection**: The initiating operator collects signature shares from enough operators to meet the threshold.
5. **Signature Aggregation**: The signature shares are combined to create the complete signature.
6. **Verification**: All operators verify the final signature against the group's public key.

## Operator Security Requirements

Each MPC operator should adhere to the following security requirements:

1. **Dedicated Hardware**: Use dedicated, hardened servers for MPC operations.
2. **Network Security**: Implement strict firewall rules and network isolation.
3. **Physical Security**: Secure the physical location of MPC operator hardware.
4. **Regular Updates**: Keep all software up-to-date with security patches.
5. **Monitoring**: Implement continuous monitoring for suspicious activities.
6. **Incident Response**: Develop and practice incident response procedures.

## Threshold Parameters

The choice of threshold parameters is critical for security and availability:

1. **Recommended**: 3-of-5 threshold
   - Provides a good balance between security and availability
   - Can tolerate up to 2 compromised or unavailable operators

2. **Minimum**: 2-of-3 threshold
   - Suitable for smaller deployments
   - Can tolerate only 1 compromised or unavailable operator

3. **High Security**: 4-of-7 threshold
   - Higher security at the cost of reduced availability
   - Can tolerate up to 3 compromised or unavailable operators

## Operator Selection and Distribution

When selecting operators for the MPC system, consider the following:

1. **Organizational Diversity**: Select operators from different organizations to reduce collusion risk.
2. **Geographic Distribution**: Distribute operators across different geographic regions to reduce the risk of physical attacks or natural disasters affecting multiple operators.
3. **Jurisdictional Distribution**: Consider distributing operators across different legal jurisdictions to reduce the risk of legal compulsion.

## Emergency Procedures

Establish clear procedures for emergency situations:

1. **Key Compromise**: If an operator suspects their key share is compromised, they should immediately notify all other operators and initiate an emergency key rotation.
2. **Operator Unavailability**: If an operator becomes unavailable, ensure that the threshold can still be met with the remaining operators.
3. **Disaster Recovery**: Maintain secure backups of key shares and configuration to recover from catastrophic failures.

## Implementation with multi-party-eddsa

The 0BTC Wire MPC system uses the [multi-party-eddsa](https://github.com/ZenGo-X/multi-party-eddsa) library for threshold Ed25519 signatures. This library provides:

1. **Provable Security**: Based on provably secure distributed Schnorr signatures.
2. **Efficient DKG**: Uses a fast, trustless setup for distributed key generation.
3. **Threshold Signatures**: Supports t-of-n threshold signatures.

## Conclusion

Proper key management is essential for the security of the 0BTC Wire MPC system. By following the practices outlined in this document, operators can ensure that the bridge between Bitcoin and the 0BTC Wire system remains secure and reliable.
