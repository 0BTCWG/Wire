# 0BTC Wire Examples

This directory contains examples demonstrating how to use the 0BTC Wire library for various use cases. The examples are organized into the following categories:

## Directory Structure

- `basic/`: Simple examples demonstrating core functionality
- `advanced/`: Advanced examples showcasing optimization features
- `cli/`: Command-line interface examples and demos
- `wasm/`: WebAssembly integration examples for browser use

## Basic Examples

These examples demonstrate the core functionality of the 0BTC Wire library:

- `hash_example.rs`: Demonstrates how to use the hash gadgets
- `simple_transfer.rs`: Shows how to create and verify a transfer circuit proof

To run a basic example:

```bash
cargo run --example basic/hash_example
cargo run --example basic/simple_transfer
```

## Advanced Examples

These examples showcase advanced features and optimizations:

- `parallel_proof_example.rs`: Demonstrates parallel proof generation
- `recursive_proof_example.rs`: Shows how to use recursive proof aggregation

To run an advanced example:

```bash
cargo run --example advanced/parallel_proof_example -- --nocapture
cargo run --example advanced/recursive_proof_example -- --nocapture
```

## CLI Examples

These examples demonstrate how to use the CLI functionality:

- `cli_demo.rs`: A comprehensive CLI demo that showcases proof generation, verification, and aggregation

To run the CLI demo:

```bash
# Generate proofs
cargo run --example cli/cli_demo -- generate --count 4 --output ./proofs --parallel

# Verify proofs
cargo run --example cli/cli_demo -- verify --input ./proofs --parallel

# Verify proofs using recursive verification
cargo run --example cli/cli_demo -- verify --input ./proofs --recursive

# Aggregate proofs
cargo run --example cli/cli_demo -- aggregate --input ./proofs --output aggregated_proof.json --batch-size 4
```

## WASM Examples

These examples demonstrate how to use the 0BTC Wire WASM module in a browser environment:

- `index.html`: HTML interface for the WASM demo
- `wasm_demo.js`: JavaScript code for the WASM demo

To run the WASM demo:

1. Build the WASM module:
   ```bash
   wasm-pack build --target web
   ```

2. Start a local web server:
   ```bash
   python -m http.server
   ```

3. Open your browser and navigate to:
   ```
   http://localhost:8000/examples/wasm/
   ```

## Running Examples with Benchmarks

For examples that include benchmarks, use the `--nocapture` flag to see the benchmark results:

```bash
cargo test --test recursive_prover_benchmark -- --nocapture
```

## Example Inputs and Outputs

The `inputs/` and `proofs/` directories contain sample input data and generated proofs that can be used with the examples.

## Demo Script

The `demo.sh` script provides a comprehensive demonstration of the 0BTC Wire system, including key generation, proof generation, and verification.

To run the demo script:

```bash
./examples/demo.sh
```
