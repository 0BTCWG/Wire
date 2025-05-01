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

## Getting Started

### Prerequisites

- Rust 1.65+ with Cargo
- For WASM support: wasm-pack

### Installation

For detailed installation instructions, see [INSTRUCTIONS.md](INSTRUCTIONS.md).

```bash
# Clone the repository
git clone https://github.com/0BTC/Wire.git
cd Wire

# Build the project
cargo build --release

# Build WebAssembly module (optional)
cargo install wasm-pack
wasm-pack build --target web
```

### Usage

For comprehensive usage instructions, see [USER_GUIDE.md](USER_GUIDE.md).

#### Command Line Interface

```bash
# Generate a new keypair with mnemonic
./target/release/wire keygen --words 24 --output my_keypair.json

# Recover from existing mnemonic
./target/release/wire keygen --mnemonic "your mnemonic phrase here" --output recovered_keypair.json

# Prove a circuit
./target/release/wire prove --circuit wrapped_asset_mint --input mint_params.json --output mint_proof.json --threads 8

# Verify a proof
./target/release/wire verify --circuit wrapped_asset_mint --proof mint_proof.json --verbose

# Aggregate multiple proofs
./target/release/wire aggregate --proofs proof1.json,proof2.json,proof3.json --output aggregated.json
```

#### WebAssembly API

```javascript
import * as wire from 'wire';

// Generate a keypair with mnemonic
const keypairWithMnemonic = wire.generate_keypair_with_mnemonic(24);
console.log(keypairWithMnemonic.mnemonic); // Save this securely!

// Create a proof
const proof = wire.prove_wrapped_asset_mint(attestationData, custodianPk);

// Verify a proof
const isValid = wire.verify_proof(proof, "WrappedAssetMint");
```

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

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
