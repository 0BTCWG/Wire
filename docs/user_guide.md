# 0BTC Wire User Guide

## Introduction

Welcome to the 0BTC Wire User Guide. This document provides comprehensive instructions for using the 0BTC Wire zero-knowledge proof system for Bitcoin wrapping and transfer operations. 0BTC Wire enables secure, verifiable transactions with wrapped Bitcoin (wBTC) using zero-knowledge proofs.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Installation](#installation)
3. [Key Management](#key-management)
4. [Basic Operations](#basic-operations)
5. [Advanced Features](#advanced-features)
6. [Troubleshooting](#troubleshooting)
7. [Security Best Practices](#security-best-practices)

## Getting Started

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **CPU**: 4+ cores recommended for proof generation
- **RAM**: 8GB minimum, 16GB+ recommended for complex operations
- **Storage**: 1GB free space
- **Rust**: Latest nightly toolchain

### Quick Start

For those who want to get started immediately, here's a quick example:

```bash
# Clone and build 0BTC Wire
git clone https://github.com/0BTC/Wire.git
cd Wire
cargo build --release

# Generate a new key pair
./target/release/wire keygen --words 24 --output my_keypair.json

# Create a wrapped asset mint proof
./target/release/wire prove --circuit wrapped_asset_mint --input mint_params.json --output mint_proof.json

# Verify the proof
./target/release/wire verify --circuit wrapped_asset_mint --proof mint_proof.json
```

## Installation

For detailed installation instructions, please refer to the [Installation Guide](installation_guide.md).

### Building from Source

```bash
# Clone the repository
git clone https://github.com/0BTC/Wire.git

# Build the project
cd Wire
cargo build --release
```

## Key Management

0BTC Wire includes robust key management features based on industry standards.

### Generating Keys

```bash
# Generate a new keypair with a 24-word mnemonic
./target/release/wire keygen --words 24 --output my_keypair.json

# Generate a keypair with a custom derivation path
./target/release/wire keygen --words 24 --path "m/44'/0'/0'/0/0" --output my_keypair.json

# Recover a keypair from an existing mnemonic
./target/release/wire keygen --mnemonic "your mnemonic phrase here" --output recovered_keypair.json
```

### Key Security

- Store your mnemonic phrase securely, preferably offline
- Use hardware security modules for production environments
- Consider multi-signature setups for high-value operations

## Basic Operations

### Wrapped Asset Operations

#### Minting Wrapped Bitcoin

```bash
# Create a mint proof with custodian attestation
./target/release/wire prove --circuit wrapped_asset_mint \
  --input mint_params.json \
  --output mint_proof.json
```

The `mint_params.json` file should contain:

```json
{
  "btc_amount": 100000000,  // Amount in satoshis (1 BTC)
  "custodian_public_key": "0x...",
  "attestation_signature": "0x...",
  "recipient_public_key": "0x...",
  "salt": "0x..."  // Random value for UTXO commitment
}
```

#### Burning Wrapped Bitcoin

```bash
# Create a burn proof for withdrawal
./target/release/wire prove --circuit wrapped_asset_burn \
  --input burn_params.json \
  --output burn_proof.json
```

### Asset Transfers

```bash
# Create a transfer proof
./target/release/wire prove --circuit transfer \
  --input transfer_params.json \
  --output transfer_proof.json
```

### Native Asset Operations

```bash
# Create a new native asset
./target/release/wire prove --circuit native_asset_create \
  --input create_params.json \
  --output create_proof.json

# Mint native asset tokens
./target/release/wire prove --circuit native_asset_mint \
  --input mint_params.json \
  --output mint_proof.json

# Burn native asset tokens
./target/release/wire prove --circuit native_asset_burn \
  --input burn_params.json \
  --output burn_proof.json
```

## Advanced Features

### Parallel Proof Generation

For improved performance, you can use parallel proof generation:

```bash
./target/release/wire prove --circuit transfer \
  --input transfer_params.json \
  --output transfer_proof.json \
  --threads 8
```

### Generating Audit Test Vectors

To generate test vectors for auditing:

```bash
./target/release/generate_audit_test_vectors --output-dir ./test_vectors
```

## Troubleshooting

### Common Issues

#### Proof Generation Failures

If proof generation fails, check:
- Input parameter format and values
- System memory (at least 8GB recommended)
- Rust toolchain version (nightly required)

#### Verification Failures

If verification fails, check:
- Proof file integrity
- Circuit type matches the proof
- Public inputs match expected values

### Logging

Enable debug logging for more information:

```bash
RUST_LOG=debug ./target/release/wire prove --circuit transfer --input params.json --output proof.json
```

## Security Best Practices

### Key Management
- Use hardware wallets when possible
- Store mnemonics securely offline
- Use different keys for different environments

### Operational Security
- Validate all inputs before processing
- Run proof generation on isolated systems
- Keep software updated to the latest version
- Follow the principle of least privilege

### Audit and Compliance
- Regularly audit your implementation
- Keep records of all operations for compliance
- Use the audit test vectors to verify your implementation
