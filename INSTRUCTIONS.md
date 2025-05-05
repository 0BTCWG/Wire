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

## Quick Start Commands

### Basic Operations

```bash
# Generate a new wallet
wire wallet generate

# View wallet information
wire wallet info

# Import an existing wallet from mnemonic
wire wallet import
```

### Asset Operations

```bash
# Mint wrapped BTC
wire prove --circuit wrapped_asset_mint --input mint_params.json --output mint_proof.json

# Transfer assets
wire prove --circuit transfer --input transfer_params.json --output transfer_proof.json

# Burn wrapped BTC
wire prove --circuit wrapped_asset_burn --input burn_params.json --output burn_proof.json

# Create a native asset
wire prove --circuit native_asset_create --input create_params.json --output create_proof.json
```

### AMM Operations

```bash
# Add liquidity to a pool
wire prove --circuit add_liquidity --input add_liquidity_params.json --output add_liquidity_proof.json

# Remove liquidity from a pool
wire prove --circuit remove_liquidity --input remove_liquidity_params.json --output remove_liquidity_proof.json

# Swap tokens using an AMM pool
wire prove --circuit swap --input swap_params.json --output swap_proof.json
```

### Stablecoin Operations

```bash
# Mint stablecoins
wire prove --circuit stablecoin_mint --input mint_params.json --output mint_proof.json

# Redeem stablecoins
wire prove --circuit stablecoin_redeem --input redeem_params.json --output redeem_proof.json
```

### Verification

```bash
# Verify a proof
wire verify --circuit transfer --proof transfer_proof.json
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

## Configuration

Create a configuration file:

```bash
wire config --create --output wire_config.json
```

## Advanced Features

For advanced features and detailed usage instructions, please refer to the [User Guide](USER_GUIDE.md).

## Troubleshooting

If you encounter any issues:

1. Ensure you're using the latest version of the software.
2. Check that your input files are correctly formatted.
3. For parallel processing issues, try reducing the number of threads or disabling parallelism.
4. For memory-related errors, try using smaller batch sizes.

## Notes for Developers

- The codebase has been updated to fix various compilation issues and warnings.
- All CLI commands now use the parallel prover for improved performance.
- Batch processing has been optimized for better error handling and reliability.
- For detailed information about recent fixes, see the [Compilation Fixes](docs/compilation_fixes.md) document.

## Documentation

For more detailed information, refer to the following documentation:

- [USER_GUIDE.md](./USER_GUIDE.md) - Comprehensive user guide
- [docs/amm_state_management.md](./docs/amm_state_management.md) - AMM state management details
- [docs/collateral_locking.md](./docs/collateral_locking.md) - Stablecoin collateral mechanism
- [docs/api_reference.md](./docs/api_reference.md) - API reference
- [docs/integration_guide.md](./docs/integration_guide.md) - Integration guide

## Getting Help

```bash
# Show help information
wire --help

# Show help for a specific command
wire wallet --help
wire prove --help
wire verify --help
```

## Support

If you encounter any issues, please:

1. Check the [Troubleshooting](USER_GUIDE.md#troubleshooting) section in the User Guide
2. File an issue on the [GitHub repository](https://github.com/0BTC/Wire/issues)
3. Join our [community Discord](https://discord.gg/0btc) for assistance

## License

This software is licensed under the [MIT License](LICENSE).
