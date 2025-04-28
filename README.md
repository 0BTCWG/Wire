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

## Getting Started

### Prerequisites

- Rust 1.65+ with Cargo
- For WASM support: wasm-pack

### Installation

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

#### Command Line Interface

```bash
# Generate a new keypair
./target/release/wire keygen --output my_keypair.json

# Prove a circuit
./target/release/wire prove --circuit wrapped_asset_mint --input mint_params.json --output mint_proof.json

# Verify a proof
./target/release/wire verify --circuit wrapped_asset_mint --proof mint_proof.json
```

#### WebAssembly API

```javascript
import * as wire from 'wire';

// Generate a keypair
const keypair = wire.generate_keypair();

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
│   ├── cli/            # Command-line interface
│   ├── wasm/           # WebAssembly bindings
│   ├── lib.rs          # Library entry point
│   └── main.rs         # CLI entry point
├── docs/               # Documentation
└── tests/              # Integration tests
```

## Development

### Building Gadgets

The project uses a modular approach with reusable gadgets:

- **Hash Gadget**: ZK-friendly hash function (Poseidon)
- **Signature Verification**: EdDSA signature verification
- **Nullifier Gadget**: Prevents double-spending of UTXOs
- **Fee Payment Gadget**: Handles transaction fees

### Testing

```bash
# Run unit tests
cargo test

# Run a specific test
cargo test test_wrapped_asset_mint
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
