# 0BTC Wire

A zero-knowledge UTXO system for Bitcoin-based assets using Plonky2. 0BTC Wire is a zero-knowledge proof system that enables:

1. **Wrapped Bitcoin (wBTC)** - Bridge Bitcoin to a UTXO-based ZK system
2. **Asset Transfers** - Transfer assets between users with privacy
3. **Native Assets** - Create, mint, and burn custom tokens

The system uses Plonky2, a PLONK-based ZK proving system with recursive verification capabilities, to create efficient zero-knowledge proofs for all operations.

## Features

- **Group I: Bridging Circuits**
  - `WrappedAssetMintCircuit`: Mint wBTC based on custodian attestation
  - `WrappedAssetBurnCircuit`: Burn wBTC and generate withdrawal requests

- **Group II: Transfer Circuit**
  - `TransferCircuit`: Transfer assets between users with privacy

- **Group III: Native Asset Circuits**
  - `NativeAssetCreateCircuit`: Create new native assets
  - `NativeAssetMintCircuit`: Mint additional tokens for existing assets
  - `NativeAssetBurnCircuit`: Burn native asset tokens

- **Security Features**
  - Domain-separated hash functions for all operations
  - Secure EdDSA signature verification
  - Nullifier generation to prevent double-spending
  - Fee enforcement with expiry timestamps
  - Comprehensive security review and testing

- **Key Management**
  - BIP-39 mnemonic phrase generation and recovery
  - SLIP-0010 HD wallet support for Ed25519 keys
  - Customizable derivation paths
  - Secure key storage recommendations

## Project Status

This project has completed all core functionality and is now in a release-ready state:

- All tests pass successfully
- All compiler warnings have been addressed
- All binaries build and run correctly
- Documentation has been updated and is comprehensive
- Audit test vectors have been generated and verified
- All cryptographic operations use public, stable APIs

## Getting Started

### Prerequisites

- Rust (nightly) with Cargo
- OpenSSL development libraries
- For WASM support: wasm-pack and Node.js
- Minimum 8GB RAM for standard operations
- Minimum 16GB RAM for test vector generation and benchmarks

### Installation

For detailed installation instructions, see [docs/installation_guide.md](docs/installation_guide.md).

```bash
# Clone the repository
git clone https://github.com/0BTC/Wire.git

# Build the project
cd Wire
cargo build --release

# Run tests
cargo test

# Generate audit test vectors
cargo run --release --bin generate_audit_test_vectors -- --output-dir ./test_vectors
```

## Documentation

Comprehensive documentation is available in the `docs` directory:

- [Installation Guide](docs/installation_guide.md) - Detailed installation instructions
- [API Reference](docs/api_reference.md) - Reference for all public APIs
- [Integration Guide](docs/integration_guide.md) - Guide for integrating with other systems
- [Security Model](docs/security_model.md) - Overview of the security model
- [Audit Test Vectors](docs/AUDIT_TEST_VECTORS.md) - Guide for generating and using audit test vectors

## Architecture

0BTC Wire is built with a modular architecture:

- **Core**: Basic types and utilities
- **Gadgets**: Zero-knowledge circuit components
- **Circuits**: Complete circuits for specific operations
- **Utils**: Helper functions and utilities
- **Binaries**: Command-line tools for various operations

All components are designed to be auditable, with explicit witness assignments and public APIs.

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Project Structure

```
Wire/
├── src/
│   ├── core/           # Core types and constants
│   ├── gadgets/        # Reusable ZK circuit components
│   ├── circuits/       # Main ZK circuits
│   ├── utils/          # Utility functions and modules
│   │   ├── wallet.rs   # BIP-39 and HD wallet implementation
│   │   ├── hash.rs     # Domain-separated hash functions
│   │   ├── signature.rs # EdDSA signature operations
│   │   └── nullifier.rs # Nullifier generation and verification
│   ├── cli/            # Command-line interface
│   ├── wasm/           # WebAssembly bindings
│   ├── lib.rs          # Library entry point
│   └── main.rs         # CLI entry point
├── docs/               # Documentation
│   ├── mpc_interaction.md  # MPC custody interaction flows
│   ├── mpc_key_management.md # MPC key management procedures
│   ├── security_review.md  # Comprehensive security review
│   └── audit_readiness_checklist.md # Audit preparation checklist
├── scripts/            # Utility scripts
│   └── mpc/            # MPC operator scripts
├── tests/              # Tests
│   ├── integration/    # End-to-end integration tests
│   └── audit/          # Security and fuzz tests
├── USER_GUIDE.md       # Comprehensive user guide
└── INSTRUCTIONS.md     # Quick start instructions
```

## Development

### Building Gadgets

The project uses a modular approach with reusable gadgets:

- **Hash Gadget**: Domain-separated ZK-friendly hash function (Poseidon)
- **Signature Verification**: Secure EdDSA signature verification
- **Nullifier Gadget**: Prevents double-spending of UTXOs
- **Fee Payment Gadget**: Handles transaction fees with expiry validation

### Testing

```bash
# Run unit tests
cargo test

# Run integration tests
cargo test --test integration

# Run security and fuzz tests
cargo test --test audit
```

## MPC Custody

The system includes reference implementations for MPC custody operations:

- Fee monitoring and consolidation
- Attestation generation for minting
- Burn proof processing for BTC withdrawals

See `docs/mpc_interaction.md` and `docs/mpc_key_management.md` for details.

## Security

0BTC Wire has undergone comprehensive security review and testing:

- Domain separation for all cryptographic operations
- Secure signature verification with proper curve validation
- Conservation of value enforcement in all circuits
- Double-spending prevention through nullifier registration
- Transaction replay prevention
- Extensive fuzz testing of all components

See `docs/security_review.md` for the full security analysis.
