# 0BTC Wire v0.2.0 Release Notes

## Overview

We are pleased to announce the release of 0BTC Wire v0.2.0, featuring significant improvements and new features for the AMM state management and collateral locking mechanisms. This release represents a major milestone in the development of 0BTC Wire, providing enhanced security, usability, and performance.

## Release Date

May 1, 2025

## Major Features

### AMM State Management Documentation

- **Comprehensive Documentation**: Added detailed documentation explaining the UTXO-based AMM state management
- **User Interaction Documentation**: Documented challenges and solutions for user interaction with AMM pools
- **Best Practices**: Provided best practices for integration with off-chain indexers

### Collateral Locking Documentation

- **Collateral Locking Mechanism**: Added detailed documentation on the stablecoin collateral locking mechanism
- **Security Considerations**: Explained the security considerations for price attestations
- **Timelock Enforcement**: Documented the timelock enforcement and redemption process

### Code Quality Improvements

- **Clippy Warnings**: Fixed numerous clippy warnings throughout the codebase
- **Code Formatting**: Improved code formatting and consistency
- **Clarifying Comments**: Added clarifying comments to complex code sections
- **Unused Code**: Marked intentionally unused code with `#[allow(dead_code)]`

### Dependency Updates

- **sha2**: Updated `sha2` from 0.10.7 to 0.10.9
- **base32**: Updated `base32` from 0.4.0 to 0.5.1
- **env_logger**: Updated `env_logger` from 0.10.0 to 0.11.8

### Documentation Updates

- **README.md**: Updated README.md with information about AMM and stablecoin features
- **USER_GUIDE.md**: Enhanced USER_GUIDE.md with detailed instructions for AMM and stablecoin operations
- **INSTRUCTIONS.md**: Improved INSTRUCTIONS.md with quick start commands for all features

### Bug Fixes

- **test_fixed_div**: Fixed the `test_fixed_div` test in `gadgets/fixed_point.rs`
- **test_nullifier_uniqueness**: Fixed the `test_nullifier_uniqueness` test in `utils/tests/nullifier_tests.rs`
- **Mutable Borrow Issues**: Fixed multiple mutable borrow issues in several circuits
- **Type Mismatches**: Fixed type mismatches in circuit implementations

### Known Issues

- **Unused Result Types**: Some warnings about unused `Result` types remain to be addressed in future updates
- **Non-Snake Case Variable Names**: Non-snake case variable names in some circuit implementations

## Detailed Changes

### Core Modules

- Updated `src/amm/` module with the following components:
  - `state_management.rs`: UTXO-based AMM state management
  - `user_interaction.rs`: User interaction with AMM pools
  - `integration.rs`: Integration with off-chain indexers

- Updated `src/collateral/` module with the following components:
  - `locking_mechanism.rs`: Stablecoin collateral locking mechanism
  - `security_considerations.rs`: Security considerations for price attestations
  - `timelock_enforcement.rs`: Timelock enforcement and redemption process

### Documentation

- Added `docs/amm_state_management.md`: AMM state management documentation
- Added `docs/collateral_locking.md`: Collateral locking mechanism documentation
- Updated `README.md`, `docs/user_guide.md`, and other documentation

### Testing

- Added comprehensive test suite for AMM state management and collateral locking mechanisms
- Added integration tests for the full AMM and collateral locking lifecycle
- Added tests for fee consolidation workflow

### Build and CI/CD

- Updated GitHub workflows for cross-platform builds
- Improved artifact packaging for releases
- Added AMM-specific build targets

## Breaking Changes

- None. This release is backwards compatible with the previous version.

## Upgrade Instructions

To upgrade to 0BTC Wire v0.2.0, please refer to the [Upgrade Guide](/docs/upgrade_guide.md).

## Future Plans

- Performance optimization for AMM operations
- Integration with hardware security modules (HSMs)
- Enhanced monitoring and alerting
- Automated recovery for interrupted ceremonies
- Additional security hardening

## Contributors

We would like to thank all contributors who have made this release possible.

## License

0BTC Wire is licensed under the MIT License. See the LICENSE file for details.
