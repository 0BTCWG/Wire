# 0BTC Wire Instructions

This document provides quick installation and usage instructions for the 0BTC Wire system.

## Installation

### Option 1: Install from Binary

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

### Option 2: Install from Source

1. Ensure you have Rust and Cargo installed:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. Clone the repository:
   ```bash
   git clone https://github.com/0BTC/Wire.git
   cd Wire
   ```

3. Build the project:
   ```bash
   cargo build --release
   ```

4. The binary will be available at `target/release/wire`.

5. Optionally, install the binary:
   ```bash
   cargo install --path .
   ```

## Quick Start

### Generate a Keypair

Generate a new keypair with a BIP-39 mnemonic phrase:

```bash
wire keygen --output my_keys.json
```

### Prove a Circuit

Generate a proof for a circuit:

```bash
wire prove --circuit transfer --input transfer_params.json --output transfer_proof.json
```

### Verify a Proof

Verify a proof:

```bash
wire verify --circuit transfer --proof transfer_proof.json
```

### Aggregate Proofs

Aggregate multiple proofs:

```bash
wire aggregate --input-dir proofs/ --output aggregated_proof.json
```

## Command Reference

Run `wire --help` to see all available commands:

```
0BTC Wire - Zero-Knowledge UTXO System

Usage: wire <COMMAND>

Commands:
  keygen            Generate a new keypair
  prove             Prove a circuit
  verify            Verify a proof
  aggregate         Aggregate multiple proofs into a single proof
  verify-aggregated Verify an aggregated proof
  advanced          Advanced CLI commands for configuration, batch processing, and workflows
  help              Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version
```

For detailed information about each command, use the `--help` flag:

```bash
wire keygen --help
wire prove --help
# etc.
```

## Documentation

For more detailed instructions, refer to the following documentation:

- [USER_GUIDE.md](USER_GUIDE.md): Comprehensive user guide
- [docs/mpc_interaction.md](docs/mpc_interaction.md): MPC custody and interaction flows
- [docs/mpc_key_management.md](docs/mpc_key_management.md): MPC key management procedures

## Support

If you encounter any issues, please:

1. Check the [Troubleshooting](USER_GUIDE.md#troubleshooting) section in the User Guide
2. File an issue on the [GitHub repository](https://github.com/0BTC/Wire/issues)
3. Join our [community Discord](https://discord.gg/0btc) for assistance
