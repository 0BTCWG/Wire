# MPC Key Management Procedures

This document outlines the secure key management procedures for the Multi-Party Computation (MPC) operators of the 0BTC Wire system.

## 1. Overview

The security of the 0BTC Wire system relies on the secure management of cryptographic keys by the MPC operators. These keys are used to:

- Sign attestations for minting wBTC
- Process BTC withdrawals for burn operations
- Consolidate fees collected in the fee reservoir

## 2. Threshold Signature Scheme

The 0BTC Wire system uses a t-of-n threshold signature scheme, where:

- **n**: Total number of MPC operators (recommended: 5-7)
- **t**: Minimum number of operators required to sign (recommended: n/2 + 1)

This ensures that no single operator (or small group of operators) can unilaterally control the funds.

## 3. Key Generation Ceremony

### 3.1 Preparation

1. Each operator prepares a secure, air-gapped computer with the following:
   - Fresh OS installation
   - MPC key generation software
   - Hardware security module (HSM) or hardware wallet
   - Offline backup media (paper, metal plates, etc.)

2. Operators agree on a time for a secure video conference

### 3.2 Ceremony Process

1. **Initial Setup**
   - Each operator generates a random seed on their HSM
   - The seed never leaves the HSM

2. **Distributed Key Generation (DKG)**
   - Operators follow the DKG protocol to generate their key shares
   - Each operator receives a verification vector and encrypted shares for other operators
   - The public key is derived and verified by all operators

3. **Backup**
   - Each operator backs up their key share using:
     - Primary backup: HSM or hardware wallet
     - Secondary backup: Encrypted backup on offline media
     - Tertiary backup: Secret sharing scheme (e.g., Shamir's Secret Sharing) distributed to trusted contacts

4. **Verification**
   - Operators verify the generated public key
   - Operators perform a test signature to ensure the threshold scheme works correctly

## 4. Operational Security

### 4.1 Key Storage

1. **Primary Storage**
   - Each operator's key share must be stored in a hardware security module (HSM) or hardware wallet
   - The HSM should never be connected to an internet-connected device except during signing operations
   - The HSM should require physical presence and PIN/password for operation

2. **Backup Storage**
   - Backups must be stored in physically secure locations (e.g., bank vaults)
   - Multiple backups should be stored in geographically distributed locations
   - Backups should be encrypted with a strong passphrase

### 4.2 Signing Procedure

1. **Request Validation**
   - Each operator independently validates the signing request
   - For minting: Verify the BTC deposit transaction
   - For burning: Verify the burn proof
   - For fee consolidation: Verify the fee UTXOs

2. **Secure Signing Environment**
   - Operators connect their HSM to an air-gapped computer
   - The signing request is transferred via QR code or USB drive
   - The operator reviews the transaction details on the HSM display
   - The operator approves the signature share generation

3. **Signature Aggregation**
   - Signature shares are collected from at least t operators
   - The shares are aggregated to form the complete signature
   - The signature is verified against the public key before submission

### 4.3 Key Rotation

1. **Regular Rotation**
   - Key shares should be rotated annually
   - The rotation follows the same ceremony process as the initial generation
   - Old keys remain valid until all funds are moved to addresses controlled by new keys

2. **Emergency Rotation**
   - If a key share is suspected to be compromised, an emergency rotation is initiated
   - All funds are immediately moved to a pre-established backup address
   - A new key generation ceremony is conducted

## 5. Physical Security

1. **Secure Facilities**
   - MPC operators should maintain physically secure facilities
   - Access control systems should be in place
   - Video surveillance should monitor access to HSMs

2. **Disaster Recovery**
   - Operators should have disaster recovery plans
   - Backup facilities should be available in case primary facilities are compromised

## 6. Operator Selection and Governance

1. **Operator Selection**
   - Operators should be selected based on:
     - Technical expertise
     - Security track record
     - Geographic distribution
     - Institutional backing

2. **Governance Model**
   - Clear governance rules for:
     - Adding/removing operators
     - Emergency procedures
     - Dispute resolution
     - Transparency and reporting

## 7. Audit and Compliance

1. **Regular Audits**
   - Independent security audits should be conducted annually
   - Penetration testing should be performed on operator infrastructure
   - Key management procedures should be reviewed by security experts

2. **Incident Response**
   - Clear procedures for responding to security incidents
   - Communication channels for emergency coordination
   - Public disclosure policy for security incidents

## 8. Implementation References

### 8.1 Recommended Hardware

- **HSMs**: YubiHSM 2, Ledger Nano X, Trezor Model T
- **Air-gapped computers**: Dedicated laptops with fresh OS installations
- **Backup media**: Cryptosteel, Billfodl, or similar metal backup devices

### 8.2 Software Libraries

- **Threshold signatures**: Threshold Signature Scheme (TSS) libraries like:
  - [multi-party-eddsa](https://github.com/ZenGo-X/multi-party-eddsa)
  - [threshold-crypto](https://github.com/poanetwork/threshold_crypto)
  - [frost-dalek](https://github.com/ZcashFoundation/frost-dalek)

- **Key management**: 
  - [shamir](https://github.com/hashicorp/vault/tree/main/shamir)
  - [rusty-secrets](https://github.com/SpinResearch/rusty-secrets)

### 8.3 Example Implementation

The `scripts/mpc/` directory contains reference implementations for:
- Key generation ceremony
- Signature generation
- Fee monitoring and consolidation

These scripts should be reviewed and adapted for production use with appropriate security measures.

## 9. Conclusion

Secure MPC key management is critical to the security of the 0BTC Wire system. These procedures should be followed rigorously and updated as security best practices evolve.
