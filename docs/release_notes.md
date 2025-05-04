# 0BTC Wire v0.1.0 Release Notes

## Overview

We are pleased to announce the release of 0BTC Wire v0.1.0, featuring a complete implementation of the Multi-Party Computation (MPC) custody system for secure bridging between Bitcoin and the 0BTC Wire system. This release represents a significant milestone in the development of 0BTC Wire, providing a secure, auditable, and decentralized bridge for wrapped Bitcoin.

## Release Date

May 1, 2025

## Major Features

### MPC Custody System

- **Threshold Signatures**: Implementation of threshold Ed25519 signatures using the ZenGo-X/multi-party-eddsa library
- **Distributed Key Generation**: Secure DKG ceremony with no single point of failure
- **Mint Attestation**: Secure attestation of Bitcoin deposits for minting wrapped Bitcoin
- **Burn Processing**: Secure processing of burn proofs for Bitcoin withdrawals
- **Fee Consolidation**: Efficient management of collected fees

### Security Enhancements

- **Encrypted Key Storage**: AES-256-GCM encryption for key shares with PBKDF2 key derivation
- **Key Rotation**: Secure mechanism for regular and emergency key rotation
- **Multi-Factor Authentication**: Password + TOTP authentication for MPC operators
- **Bitcoin Fork Detection**: Automatic detection of Bitcoin network forks with adjustable confirmation thresholds
- **Comprehensive Security Review**: Thorough security analysis with implemented recommendations

### Performance Improvements

- **Parallel Proof Generation**: Significantly improved proof generation performance using multi-threading
- **Batch Verification**: Optimized batch verification of proofs for improved throughput
- **Memory Optimization**: Reduced memory usage during proof generation and verification
- **Compilation Improvements**: Fixed various compilation issues and warnings for better stability

### Test Suite Improvements

- **Fixed Circuit Tests**: Resolved failing tests in swap, add/remove liquidity, and Lightning Network circuits
- **Improved Test Stability**: Modified tests to handle edge cases and avoid division by zero errors
- **Enhanced Test Coverage**: Ensured all critical circuit functionality is properly tested
- **Mock Proof Support**: Added support for mock proofs in tests for faster execution

### Operator Tooling

- **MPC Operator CLI**: Command-line interface for MPC operators
- **Ceremony Management**: Tools for managing DKG and signing ceremonies
- **Monitoring**: Metrics and logging for operational visibility
- **Backup and Recovery**: Tools for secure backup and recovery of key shares
- **Enhanced Batch Processing**: Improved batch processing with better error handling and parallel verification

### Documentation

- **MPC Architecture**: Detailed documentation of the MPC system architecture
- **Deployment Guide**: Comprehensive instructions for deploying MPC operator nodes
- **Security Guidelines**: Best practices for secure operation
- **Production Readiness**: Checklist for ensuring production readiness
- **Updated User Guide**: Comprehensive guide for using the Wire CLI with the latest features

## Detailed Changes

### Core Modules

- Added `src/mpc/` module with the following components:
  - `core.rs`: Core MPC functionality
  - `ceremonies.rs`: DKG and signing ceremony management
  - `attestation.rs`: Mint attestation workflow
  - `burn.rs`: Burn proof processing
  - `fee.rs`: Fee consolidation workflow
  - `secure_storage.rs`: Encrypted storage for key shares
  - `key_rotation.rs`: Key rotation mechanism
  - `auth.rs`: Multi-factor authentication
  - `bitcoin_security.rs`: Bitcoin fork detection and security

### Documentation

- Added `docs/mpc_architecture.md`: MPC system architecture
- Added `docs/mpc_library_selection.md`: Rationale for library selection
- Added `docs/mpc_interaction.md`: User interaction with MPC system
- Added `docs/mpc_key_management.md`: Key management guidelines
- Added `docs/mpc_security_review.md`: Security review and recommendations
- Added `docs/mpc_deployment.md`: Deployment instructions
- Added `docs/production_readiness.md`: Production readiness checklist
- Updated `README.md`, `docs/user_guide.md`, and other documentation

### Testing

- Added comprehensive test suite for MPC functionality
- Added integration tests for the full mint-transfer-burn lifecycle
- Added tests for fee consolidation workflow

### Build and CI/CD

- Updated GitHub workflows for cross-platform builds
- Improved artifact packaging for releases
- Added MPC-specific build targets

## Breaking Changes

- None. This is the initial release of the MPC custody system.

## Known Issues

- The MPC system currently requires manual intervention for certain error conditions
- Performance optimization for large-scale deployments is ongoing
- Integration with external HSMs is planned for a future release

## Upgrade Instructions

As this is the initial release of the MPC custody system, there are no upgrade instructions. For installation instructions, please refer to the [MPC Deployment Guide](/docs/mpc_deployment.md).

## Future Plans

- Performance optimization for MPC operations
- Integration with hardware security modules (HSMs)
- Enhanced monitoring and alerting
- Automated recovery for interrupted ceremonies
- Additional security hardening

## Contributors

We would like to thank all contributors who have made this release possible.

## License

0BTC Wire is licensed under the MIT License. See the LICENSE file for details.
