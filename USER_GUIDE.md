# 0BTC Wire User Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
   - [From Binary](#from-binary)
   - [From Source](#from-source)
3. [Key Management](#key-management)
   - [Generating Keys](#generating-keys)
   - [Recovering Keys](#recovering-keys)
   - [Key Security](#key-security)
4. [Basic Operations](#basic-operations)
   - [Proving Circuits](#proving-circuits)
   - [Verifying Proofs](#verifying-proofs)
   - [Aggregating Proofs](#aggregating-proofs)
5. [Asset Operations](#asset-operations)
   - [Minting Wrapped BTC](#minting-wrapped-btc)
   - [Burning Wrapped BTC](#burning-wrapped-btc)
   - [Transferring Assets](#transferring-assets)
   - [Creating Native Assets](#creating-native-assets)
6. [Advanced Features](#advanced-features)
   - [Configuration](#configuration)
   - [Batch Processing](#batch-processing)
   - [Workflows](#workflows)
7. [MPC Operator Guide](#mpc-operator-guide)
   - [Fee Monitoring](#fee-monitoring)
   - [Attestation Generation](#attestation-generation)
   - [Burn Processing](#burn-processing)
8. [Troubleshooting](#troubleshooting)
9. [FAQ](#faq)

## Introduction

0BTC Wire is a zero-knowledge UTXO system that enables secure, private transactions with wrapped Bitcoin and native assets. This guide provides comprehensive instructions for using the 0BTC Wire CLI tool.

## Installation

### From Binary

1. Download the latest release from the [releases page](https://github.com/0BTC/Wire/releases).

2. Extract the archive:
   ```bash
   tar -xzf wire-v0.1.0-linux-x86_64.tar.gz
   # or for macOS
   tar -xzf wire-v0.1.0-macos-x86_64.tar.gz
   ```

3. Move the binary to a location in your PATH:
   ```bash
   sudo mv wire /usr/local/bin/
   ```

4. Verify the installation:
   ```bash
   wire --version
   ```

### From Source

1. Clone the repository:
   ```bash
   git clone https://github.com/0BTC/Wire.git
   cd Wire
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

3. The binary will be available at `target/release/wire`.

4. Optionally, install the binary:
   ```bash
   cargo install --path .
   ```

## Key Management

### Generating Keys

The `wire keygen` command generates a new keypair using BIP-39 mnemonic phrases and HD wallet derivation.

```bash
# Generate a new keypair with default settings (12-word mnemonic)
wire keygen

# Generate a keypair with a 24-word mnemonic
wire keygen --words 24

# Generate a keypair with a custom derivation path
wire keygen --path "m/44'/0'/0'/0/0"

# Save the keypair to a file
wire keygen --output my_keys.json
```

The output includes:
- Mnemonic phrase
- Derivation path
- Private key (hex encoded)
- Public key (hex encoded)

### Recovering Keys

You can recover keys from an existing mnemonic phrase:

```bash
# Recover keys from a mnemonic phrase
wire keygen --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Recover keys with a custom derivation path
wire keygen --mnemonic "your mnemonic phrase here" --path "m/44'/0'/0'/0/0"
```

### Key Security

⚠️ **IMPORTANT SECURITY WARNINGS**:

- **NEVER share your mnemonic phrase or private key with anyone.**
- **ALWAYS back up your mnemonic phrase in a secure, offline location.**
- **CONSIDER using a hardware wallet or air-gapped computer for key generation.**
- **VERIFY all transaction details before signing.**
- **BE AWARE that anyone with access to your mnemonic can access your funds.**

## Basic Operations

### Proving Circuits

The `wire prove` command generates proofs for various circuit types:

```bash
# Generate a proof for a transfer circuit
wire prove --circuit transfer --input transfer_params.json --output transfer_proof.json

# Generate a proof with parallel processing
wire prove --circuit transfer --input transfer_params.json --output transfer_proof.json --parallel
```

### Verifying Proofs

The `wire verify` command verifies proofs:

```bash
# Verify a transfer proof
wire verify --circuit transfer --proof transfer_proof.json
```

### Aggregating Proofs

The `wire aggregate` command aggregates multiple proofs into a single proof:

```bash
# Aggregate proofs in a directory
wire aggregate --input-dir proofs/ --output aggregated_proof.json

# Aggregate with a custom batch size
wire aggregate --input-dir proofs/ --output aggregated_proof.json --batch-size 8 --verbose
```

## Asset Operations

### Minting Wrapped BTC

To mint wrapped BTC, you need an attestation from the MPC custodians:

```bash
# Generate a mint proof
wire prove --circuit wrapped_asset_mint --input mint_params.json --output mint_proof.json
```

The `mint_params.json` file should include:
- Attestation from MPC custodians
- Recipient public key
- Amount to mint

### Burning Wrapped BTC

To burn wrapped BTC and withdraw the underlying BTC:

```bash
# Generate a burn proof
wire prove --circuit wrapped_asset_burn --input burn_params.json --output burn_proof.json
```

The `burn_params.json` file should include:
- Input UTXO containing wBTC
- Destination BTC address
- Amount to burn
- Fee quote (optional)

### Transferring Assets

To transfer assets between addresses:

```bash
# Generate a transfer proof
wire prove --circuit transfer --input transfer_params.json --output transfer_proof.json
```

The `transfer_params.json` file should include:
- Input UTXOs
- Output recipients and amounts
- Fee information

### Creating Native Assets

To create a new native asset:

```bash
# Generate a native asset creation proof
wire prove --circuit native_asset_create --input asset_params.json --output asset_proof.json
```

The `asset_params.json` file should include:
- Creator public key
- Asset parameters (decimals, max supply, etc.)
- Fee information

## Advanced Features

### Configuration

The `wire advanced config` commands manage configuration:

```bash
# Initialize a default configuration
wire advanced config init --output wire_config.json

# Show the current configuration
wire advanced config show --config wire_config.json
```

### Batch Processing

The `wire advanced batch` commands process batches of proofs:

```bash
# Process a batch of proofs
wire advanced batch process --input-dir inputs/ --output-dir outputs/ --circuit transfer --config wire_config.json
```

### Workflows

The `wire advanced workflow` commands execute predefined workflows:

```bash
# Execute a workflow
wire advanced workflow execute --name mint_and_transfer --config wire_config.json
```

## MPC Operator Guide

### Fee Monitoring

MPC operators can monitor and consolidate fees using the provided scripts:

```bash
# Start the fee monitor
python scripts/mpc/fee_monitor.py --db fee_utxos.json --interval 300
```

### Attestation Generation

MPC operators can generate attestations for minting operations:

```bash
# Generate a new signing key
python scripts/mpc/attestation_generator.py --generate-key

# Start the attestation generator
python scripts/mpc/attestation_generator.py --db attestations.json --key signing_key.bin
```

### Burn Processing

MPC operators can process burn proofs and handle BTC withdrawals:

```bash
# Start the burn processor
python scripts/mpc/burn_processor.py --db burn_processor.json
```

## Troubleshooting

### Common Issues

1. **"Error: Invalid mnemonic phrase"**
   - Ensure the mnemonic phrase is correct and contains the expected number of words.
   - Check for typos or missing words.

2. **"Error: Failed to generate proof"**
   - Verify that the input parameters are correct.
   - Check that the circuit type is supported.
   - Ensure you have sufficient memory for proof generation.

3. **"Error: Proof verification failed"**
   - The proof may be invalid or corrupted.
   - Check that you're using the correct circuit type for verification.

### Logging

You can enable more detailed logging with the `RUST_LOG` environment variable:

```bash
# Enable debug logging
RUST_LOG=debug wire keygen

# Enable trace logging for specific modules
RUST_LOG=wire_lib::circuits=trace,wire_lib::utils=debug wire prove --circuit transfer --input params.json --output proof.json
```

## FAQ

**Q: How secure is the mnemonic phrase generation?**
A: We use the industry-standard BIP-39 library for mnemonic generation, which provides 128 to 256 bits of entropy depending on the word count.

**Q: Can I use the same mnemonic phrase for multiple wallets?**
A: Yes, you can derive multiple wallets from the same mnemonic by using different derivation paths.

**Q: How do I back up my keys?**
A: The most important thing to back up is your mnemonic phrase. Write it down on paper and store it in a secure location. You can always regenerate your keys from the mnemonic.

**Q: What if I lose my mnemonic phrase?**
A: If you lose your mnemonic phrase and don't have a backup of your private key, you will permanently lose access to your funds. There is no recovery mechanism.

**Q: How do I update the 0BTC Wire CLI?**
A: Download the latest release and replace your existing binary, or if you installed from source, pull the latest changes and rebuild.

---

For more information, visit the [0BTC Wire GitHub repository](https://github.com/0BTC/Wire) or join our [community Discord](https://discord.gg/0btc).
