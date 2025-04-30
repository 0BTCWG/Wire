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
8. [API Reference](#api-reference)

## Getting Started

### System Requirements

- **Operating System**: Linux, macOS, or Windows
- **CPU**: 4+ cores recommended for proof generation
- **RAM**: 8GB minimum, 16GB+ recommended for complex operations
- **Storage**: 1GB free space
- **Rust**: Latest stable or nightly toolchain

### Quick Start

For those who want to get started immediately, here's a quick example:

```bash
# Install 0BTC Wire
cargo install wire_lib

# Generate a new key pair
wire-cli keys generate --output my_keys.json

# Create a wrapped asset mint proof
wire-cli proofs create-wrapped-mint --attestation attestation.json --keys my_keys.json --output mint_proof.json

# Verify the proof
wire-cli proofs verify --proof mint_proof.json --type wrapped-mint
```

## Installation

### From Binary Releases

Download the latest release for your platform from the [releases page](https://github.com/0btc/wire/releases).

#### Linux

```bash
curl -L https://github.com/0btc/wire/releases/latest/download/wire-linux-x86_64.tar.gz | tar xz
sudo mv wire-cli /usr/local/bin/
```

#### macOS

```bash
curl -L https://github.com/0btc/wire/releases/latest/download/wire-macos-x86_64.tar.gz | tar xz
sudo mv wire-cli /usr/local/bin/
```

#### Windows

1. Download the latest Windows release from the releases page
2. Extract the ZIP file
3. Add the extracted directory to your PATH

### From Source

```bash
# Clone the repository
git clone https://github.com/0btc/wire.git
cd wire

# Build the project
cargo build --release

# Install the CLI
cargo install --path .
```

### WebAssembly (WASM) Installation

For browser or Node.js applications:

```bash
npm install @0btc/wire-wasm
```

## Key Management

### Generating Keys

```bash
# Generate a new key pair
wire-cli keys generate --output my_keys.json

# Generate a key pair with a specific seed
wire-cli keys generate --seed "my secure seed phrase" --output my_keys.json
```

### Key Security

- Store private keys securely, preferably in an encrypted format
- Consider using hardware security modules (HSMs) for production deployments
- Implement key rotation policies for long-term security
- Back up keys securely with appropriate redundancy

## Basic Operations

### Wrapped Asset Mint

The wrapped asset mint operation creates a proof that a custodian has attested to a Bitcoin deposit.

```bash
# Create a wrapped asset mint proof
wire-cli proofs create-wrapped-mint \
  --attestation attestation.json \
  --custodian-pk custodian_pk.json \
  --recipient-pk-hash recipient_hash.json \
  --amount 1.5 \
  --output mint_proof.json
```

Example attestation.json:
```json
{
  "recipient_pk_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "amount": 150000000,
  "deposit_nonce": 42,
  "signature": {
    "r_x": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "r_y": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
    "s": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  }
}
```

### Wrapped Asset Burn

The wrapped asset burn operation creates a proof that a user wants to burn wrapped Bitcoin and receive native Bitcoin.

```bash
# Create a wrapped asset burn proof
wire-cli proofs create-wrapped-burn \
  --input-utxo utxo.json \
  --sender-keys sender_keys.json \
  --destination-btc-address "bc1q..." \
  --fee 0.0001 \
  --output burn_proof.json
```

Example utxo.json:
```json
{
  "owner_pubkey_hash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "asset_id": "0x0000000000000000000000000000000000000000000000000000000000000001",
  "amount": 150000000,
  "salt": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
}
```

### Transfer

The transfer operation creates a proof that a user wants to transfer wrapped Bitcoin to another user.

```bash
# Create a transfer proof
wire-cli proofs create-transfer \
  --input-utxos '[utxo1.json,utxo2.json]' \
  --sender-keys sender_keys.json \
  --recipients '[{"pk_hash":"0x1234...","amount":100000000},{"pk_hash":"0x5678...","amount":50000000}]' \
  --fee 0.0001 \
  --fee-reservoir "0x9876..." \
  --output transfer_proof.json
```

### Verifying Proofs

```bash
# Verify a proof
wire-cli proofs verify --proof proof.json --type wrapped-mint

# Verify a proof with additional context
wire-cli proofs verify --proof proof.json --type transfer --context context.json
```

### Batch Operations

```bash
# Create multiple proofs in batch mode
wire-cli batch create-proofs --config batch_config.json --output-dir ./proofs

# Verify multiple proofs in batch mode
wire-cli batch verify-proofs --proofs-dir ./proofs --output-file verification_results.json
```

Example batch_config.json:
```json
{
  "operations": [
    {
      "type": "wrapped-mint",
      "attestation": "attestation1.json",
      "output": "mint_proof1.json"
    },
    {
      "type": "wrapped-mint",
      "attestation": "attestation2.json",
      "output": "mint_proof2.json"
    }
  ],
  "parallel": true,
  "max_threads": 4
}
```

## Advanced Features

### Configuration System

0BTC Wire supports a comprehensive configuration system for customizing behavior:

```bash
# Generate a default configuration file
wire-cli config generate --output wire_config.json

# Use a custom configuration file
wire-cli --config wire_config.json proofs create-wrapped-mint ...
```

Example configuration file:
```json
{
  "global": {
    "log_level": "info",
    "output_format": "json",
    "default_proof_dir": "./proofs"
  },
  "circuits": {
    "wrapped_mint": {
      "optimization_level": "high"
    },
    "wrapped_burn": {
      "optimization_level": "medium"
    },
    "transfer": {
      "optimization_level": "high"
    }
  },
  "batch": {
    "default_parallel": true,
    "max_threads": 4,
    "memory_limit_gb": 8
  },
  "workflow": {
    "auto_verify": true,
    "save_intermediate_results": false
  }
}
```

### Recursive Proof Aggregation

Aggregate multiple proofs into a single proof for efficient verification:

```bash
# Aggregate multiple proofs
wire-cli proofs aggregate --input-dir ./proofs --output aggregated_proof.json

# Verify an aggregated proof
wire-cli proofs verify-aggregated --proof aggregated_proof.json
```

### Workflow System

Automate complex multi-step operations:

```bash
# Define a workflow
wire-cli workflow define --file workflow.json

# Execute a workflow
wire-cli workflow run --file workflow.json --input-dir ./inputs --output-dir ./outputs
```

Example workflow.json:
```json
{
  "name": "mint_and_transfer",
  "steps": [
    {
      "name": "mint",
      "type": "wrapped-mint",
      "inputs": {
        "attestation": "{{input_dir}}/attestation.json",
        "custodian_pk": "{{input_dir}}/custodian_pk.json"
      },
      "outputs": {
        "proof": "{{output_dir}}/mint_proof.json",
        "utxo": "{{output_dir}}/mint_utxo.json"
      }
    },
    {
      "name": "transfer",
      "type": "transfer",
      "depends_on": ["mint"],
      "inputs": {
        "input_utxos": ["{{steps.mint.outputs.utxo}}"],
        "sender_keys": "{{input_dir}}/sender_keys.json",
        "recipients": "{{input_dir}}/recipients.json"
      },
      "outputs": {
        "proof": "{{output_dir}}/transfer_proof.json",
        "utxos": "{{output_dir}}/transfer_utxos.json"
      }
    }
  ]
}
```

### Memory-Efficient Proof Generation

For large circuits or memory-constrained environments:

```bash
# Generate a proof with memory efficiency options
wire-cli proofs create-transfer --memory-efficient --incremental-witness --max-memory-gb 4 ...
```

## Troubleshooting

### Common Issues

#### Proof Generation Fails with Out of Memory Error

**Problem**: The proof generation process runs out of memory.

**Solution**:
- Use the `--memory-efficient` flag
- Reduce batch size or parallel operations
- Increase available system memory
- Use incremental witness generation with `--incremental-witness`

#### Verification Fails with Invalid Proof Error

**Problem**: Proof verification fails with an "invalid proof" error.

**Solution**:
- Ensure the proof was generated correctly
- Check that you're using the correct verification type
- Verify that the proof hasn't been tampered with
- Check for version compatibility issues

#### CLI Command Fails with Invalid Arguments

**Problem**: Command fails with "invalid arguments" or "missing required option" error.

**Solution**:
- Check the command syntax with `wire-cli help [command]`
- Ensure all required options are provided
- Verify file paths are correct and accessible
- Check JSON file formats for syntax errors

### Logging and Debugging

```bash
# Enable verbose logging
wire-cli --log-level debug proofs create-wrapped-mint ...

# Save logs to a file
wire-cli --log-file wire.log proofs create-wrapped-mint ...
```

### Getting Help

```bash
# Get general help
wire-cli help

# Get help for a specific command
wire-cli help proofs

# Get help for a specific subcommand
wire-cli help proofs create-wrapped-mint
```

## Security Best Practices

### Key Management
- Store private keys securely, preferably encrypted
- Use hardware security modules for production deployments
- Implement key rotation policies
- Never share private keys or store them in insecure locations

### Input Validation
- Validate all inputs before processing
- Use the provided validation utilities for all user inputs
- Be cautious with data from untrusted sources

### Proof Verification
- Always verify proofs before taking action based on them
- Implement defense in depth with multiple verification layers
- Consider using recursive aggregation for efficiency without sacrificing security

### Operational Security
- Keep the software updated to the latest version
- Follow the principle of least privilege for all operations
- Implement monitoring and alerting for suspicious activities
- Regularly audit system logs and operations

## API Reference

For detailed API documentation, please refer to the [API Reference](api_reference.md).

For integration examples, see the [Integration Guide](integration_guide.md).

For usage examples, see the [Usage Examples](usage_examples.md).

## License

0BTC Wire is licensed under [LICENSE]. See the LICENSE file for details.
