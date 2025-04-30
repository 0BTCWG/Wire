# 0BTC Wire Integration Guide

## Table of Contents

1. [Introduction](#introduction)
2. [Installation](#installation)
3. [CLI Integration](#cli-integration)
4. [WASM Integration](#wasm-integration)
5. [Rust Library Integration](#rust-library-integration)
6. [Security Considerations](#security-considerations)
7. [Performance Optimization](#performance-optimization)
8. [Troubleshooting](#troubleshooting)

## Introduction

This guide provides detailed instructions for integrating the 0BTC Wire zero-knowledge proof system into your applications. 0BTC Wire supports multiple integration methods:

- **CLI Integration**: For command-line applications and scripts
- **WASM Integration**: For web applications and browsers
- **Rust Library Integration**: For direct integration into Rust applications

## Installation

### Prerequisites

- Rust toolchain (nightly)
- Node.js and npm (for WASM integration)
- wasm-pack (for building WASM modules)

### Installing from Source

1. Clone the repository:

```bash
git clone https://github.com/0BTC/Wire.git
cd Wire
```

2. Build the project:

```bash
cargo build --release
```

3. Install the CLI globally (optional):

```bash
cargo install --path .
```

### Installing the WASM Package

1. Build the WASM package:

```bash
wasm-pack build --target web --out-dir pkg
```

2. Install the WASM package in your web project:

```bash
cd /path/to/your/web/project
npm install /path/to/Wire/pkg
```

## CLI Integration

The 0BTC Wire CLI provides a simple interface for generating and verifying zero-knowledge proofs.

### Key Generation

Generate a new key pair:

```bash
wire keygen --output keys.json
```

Example output:

```json
{
  "public_key": "0x1234567890abcdef...",
  "private_key": "0x9876543210fedcba..."
}
```

### Proof Generation

Generate a proof for a wrapped asset mint:

```bash
wire prove wrapped_mint --input mint_input.json --output mint_proof.json
```

Example input file (`mint_input.json`):

```json
{
  "asset_id": "0x1234567890abcdef...",
  "amount": 100,
  "owner_pk": "0xabcdef1234567890...",
  "salt": "0xfedcba9876543210..."
}
```

### Proof Verification

Verify a proof:

```bash
wire verify wrapped_mint --proof mint_proof.json
```

Example output:

```
Proof verification successful!
Verification time: 123.45ms
```

### Proof Aggregation

Aggregate multiple proofs:

```bash
wire aggregate --input proofs_dir --output aggregated_proof.json --batch-size 8
```

Example output:

```
Aggregated 16 proofs successfully!
Aggregation time: 1234.56ms
```

### Scripting Example

Here's an example of how to use the CLI in a bash script:

```bash
#!/bin/bash

# Generate a key pair
wire keygen --output keys.json

# Extract the public and private keys
PUBLIC_KEY=$(jq -r '.public_key' keys.json)
PRIVATE_KEY=$(jq -r '.private_key' keys.json)

# Create an input file for minting
cat > mint_input.json << EOF
{
  "asset_id": "0x1234567890abcdef...",
  "amount": 100,
  "owner_pk": "$PUBLIC_KEY",
  "salt": "0xfedcba9876543210..."
}
EOF

# Generate a proof
wire prove wrapped_mint --input mint_input.json --output mint_proof.json

# Verify the proof
wire verify wrapped_mint --proof mint_proof.json
```

## WASM Integration

The 0BTC Wire WASM module provides a JavaScript API for generating and verifying zero-knowledge proofs in web applications.

### Installation

```html
<script type="module">
  import * as wire from './pkg/wire.js';

  async function init() {
    await wire.default();
    // Now you can use the wire module
  }

  init();
</script>
```

### Key Generation

```javascript
function generateKeyPair() {
  const keypair = wire.generate_keypair();
  console.log("Public Key:", keypair.public_key);
  console.log("Private Key:", keypair.private_key);
  return keypair;
}
```

### Proof Generation

```javascript
function generateMintProof(assetId, amount, ownerPk, salt) {
  const input = {
    asset_id: assetId,
    amount: amount,
    owner_pk: ownerPk,
    salt: salt
  };

  const options = { verbose: true };

  try {
    const result = wire.generate_proof("wrapped_mint", input, options);
    console.log("Proof:", result.proof);
    console.log("Public Inputs:", result.public_inputs);
    return result;
  } catch (error) {
    console.error("Error generating proof:", error);
    throw error;
  }
}
```

### Proof Verification

```javascript
function verifyMintProof(proof, publicInputs) {
  try {
    const result = wire.verify_proof("wrapped_mint", proof, publicInputs);
    console.log("Proof valid:", result.valid);
    console.log("Verification time:", result.time_ms, "ms");
    return result.valid;
  } catch (error) {
    console.error("Error verifying proof:", error);
    throw error;
  }
}
```

### Proof Aggregation

```javascript
function aggregateProofs(proofs) {
  const options = {
    batch_size: 8,
    verbose: true
  };

  try {
    const result = wire.aggregate_proofs(proofs, options);
    console.log("Aggregated proof:", result.proof);
    console.log("Number of proofs:", result.num_proofs);
    return result;
  } catch (error) {
    console.error("Error aggregating proofs:", error);
    throw error;
  }
}
```

### Complete Web Application Example

Here's a complete example of a web application that uses the 0BTC Wire WASM module:

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>0BTC Wire Demo</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body>
  <div class="container mt-5">
    <h1>0BTC Wire Demo</h1>
    
    <div class="card mb-4">
      <div class="card-header">Key Generation</div>
      <div class="card-body">
        <button id="generateKeyBtn" class="btn btn-primary">Generate Key Pair</button>
        <div class="mt-3">
          <div class="mb-2">Public Key: <span id="publicKey"></span></div>
          <div>Private Key: <span id="privateKey"></span></div>
        </div>
      </div>
    </div>
    
    <div class="card mb-4">
      <div class="card-header">Proof Generation</div>
      <div class="card-body">
        <form id="proofForm">
          <div class="mb-3">
            <label for="assetId" class="form-label">Asset ID</label>
            <input type="text" class="form-control" id="assetId" required>
          </div>
          <div class="mb-3">
            <label for="amount" class="form-label">Amount</label>
            <input type="number" class="form-control" id="amount" required>
          </div>
          <div class="mb-3">
            <label for="salt" class="form-label">Salt</label>
            <input type="text" class="form-control" id="salt" required>
          </div>
          <button type="submit" class="btn btn-primary">Generate Proof</button>
        </form>
        <div class="mt-3">
          <div class="mb-2">Proof: <span id="proof"></span></div>
          <div>Public Inputs: <span id="publicInputs"></span></div>
        </div>
      </div>
    </div>
    
    <div class="card">
      <div class="card-header">Proof Verification</div>
      <div class="card-body">
        <button id="verifyBtn" class="btn btn-primary" disabled>Verify Proof</button>
        <div class="mt-3">
          <div>Verification Result: <span id="verificationResult"></span></div>
        </div>
      </div>
    </div>
    
    <div class="card mt-4">
      <div class="card-header">Console Output</div>
      <div class="card-body">
        <pre id="console" class="bg-dark text-light p-3" style="height: 200px; overflow-y: auto;"></pre>
      </div>
    </div>
  </div>

  <script type="module">
    import * as wire from './pkg/wire.js';

    let currentProof = null;
    let currentPublicInputs = null;
    let keypair = null;

    // Console logging
    const consoleElem = document.getElementById('console');
    const originalConsoleLog = console.log;
    console.log = function(...args) {
      originalConsoleLog.apply(console, args);
      consoleElem.innerHTML += args.join(' ') + '\n';
      consoleElem.scrollTop = consoleElem.scrollHeight;
    };

    // Initialize the WASM module
    async function init() {
      try {
        await wire.default();
        console.log("0BTC Wire WASM module initialized successfully");
      } catch (error) {
        console.error("Failed to initialize WASM module:", error);
      }
    }

    // Generate key pair
    document.getElementById('generateKeyBtn').addEventListener('click', () => {
      try {
        keypair = wire.generate_keypair();
        document.getElementById('publicKey').textContent = keypair.public_key;
        document.getElementById('privateKey').textContent = keypair.private_key;
        console.log("Key pair generated successfully");
      } catch (error) {
        console.error("Error generating key pair:", error);
      }
    });

    // Generate proof
    document.getElementById('proofForm').addEventListener('submit', (e) => {
      e.preventDefault();
      
      const assetId = document.getElementById('assetId').value;
      const amount = parseInt(document.getElementById('amount').value);
      const salt = document.getElementById('salt').value;
      
      if (!keypair) {
        console.error("Please generate a key pair first");
        return;
      }
      
      try {
        const input = {
          asset_id: assetId,
          amount: amount,
          owner_pk: keypair.public_key,
          salt: salt
        };
        
        console.log("Generating proof with input:", input);
        
        const result = wire.generate_proof("wrapped_mint", input, { verbose: true });
        currentProof = result.proof;
        currentPublicInputs = result.public_inputs;
        
        document.getElementById('proof').textContent = result.proof.substring(0, 20) + "...";
        document.getElementById('publicInputs').textContent = JSON.stringify(result.public_inputs);
        document.getElementById('verifyBtn').disabled = false;
        
        console.log("Proof generated successfully");
      } catch (error) {
        console.error("Error generating proof:", error);
      }
    });

    // Verify proof
    document.getElementById('verifyBtn').addEventListener('click', () => {
      if (!currentProof || !currentPublicInputs) {
        console.error("No proof to verify");
        return;
      }
      
      try {
        console.log("Verifying proof...");
        
        const result = wire.verify_proof("wrapped_mint", currentProof, currentPublicInputs);
        
        document.getElementById('verificationResult').textContent = 
          result.valid ? "Valid ✅" : "Invalid ❌";
        
        console.log("Proof verification result:", result.valid);
        console.log("Verification time:", result.time_ms, "ms");
      } catch (error) {
        console.error("Error verifying proof:", error);
        document.getElementById('verificationResult').textContent = "Error ❌";
      }
    });

    init();
  </script>
</body>
</html>
```

## Rust Library Integration

For direct integration into Rust applications, you can use the 0BTC Wire library.

### Adding the Dependency

Add the following to your `Cargo.toml`:

```toml
[dependencies]
wire = { git = "https://github.com/0BTC/Wire.git" }
```

### Key Generation

```rust
use wire::core::{PublicKey, PrivateKey};
use wire::utils::key_generation;

fn generate_keypair() -> (PublicKey, PrivateKey) {
    let (pk, sk) = key_generation::generate_keypair();
    println!("Public Key: {:?}", pk);
    println!("Private Key: {:?}", sk);
    (pk, sk)
}
```

### Proof Generation

```rust
use wire::circuits::WrappedAssetMintCircuit;
use wire::core::UTXO;

fn generate_mint_proof(
    asset_id: Vec<u8>,
    amount: u64,
    owner_pk: PublicKey,
    salt: Vec<u8>,
) -> Result<ProofWithPublicInputs<F, C, D>, WireError> {
    let circuit = WrappedAssetMintCircuit::new(asset_id, amount, owner_pk, salt);
    
    match circuit.prove() {
        Ok(proof) => {
            println!("Proof generated successfully");
            Ok(proof)
        },
        Err(err) => {
            eprintln!("Error generating proof: {:?}", err);
            Err(err)
        }
    }
}
```

### Proof Verification

```rust
use wire::circuits::WrappedAssetMintCircuit;

fn verify_mint_proof(
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<bool, WireError> {
    match WrappedAssetMintCircuit::verify(proof) {
        Ok(valid) => {
            println!("Proof verification result: {}", valid);
            Ok(valid)
        },
        Err(err) => {
            eprintln!("Error verifying proof: {:?}", err);
            Err(err)
        }
    }
}
```

### Proof Aggregation

```rust
use wire::utils::recursive_prover::{aggregate_proofs, RecursiveProverOptions};

fn aggregate_multiple_proofs(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
) -> Result<RecursiveProofResult<F, C, D>, WireError> {
    let options = RecursiveProverOptions {
        verbose: true,
        max_proofs_per_step: Some(8),
    };
    
    match aggregate_proofs(proofs, options) {
        Ok(result) => {
            println!("Aggregated {} proofs successfully", result.num_proofs);
            println!("Aggregation time: {:?}", result.generation_time);
            Ok(result)
        },
        Err(err) => {
            eprintln!("Error aggregating proofs: {:?}", err);
            Err(err)
        }
    }
}
```

### Complete Rust Application Example

Here's a complete example of a Rust application that uses the 0BTC Wire library:

```rust
use std::time::Instant;
use wire::circuits::WrappedAssetMintCircuit;
use wire::core::{PublicKey, PrivateKey, UTXO};
use wire::utils::key_generation;
use wire::utils::recursive_prover::{aggregate_proofs, RecursiveProverOptions};
use wire::errors::{WireError, WireResult};

fn main() -> WireResult<()> {
    // Generate a key pair
    let (pk, sk) = key_generation::generate_keypair();
    println!("Generated key pair:");
    println!("Public Key: {:?}", pk);
    println!("Private Key: {:?}", sk);
    
    // Create input data for minting
    let asset_id = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let amount = 100;
    let salt = vec![0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10];
    
    // Create the circuit
    let circuit = WrappedAssetMintCircuit::new(asset_id, amount, pk, salt);
    
    // Generate a proof
    println!("Generating proof...");
    let start = Instant::now();
    let proof = circuit.prove()?;
    let generation_time = start.elapsed();
    println!("Proof generated in {:?}", generation_time);
    
    // Verify the proof
    println!("Verifying proof...");
    let start = Instant::now();
    let valid = WrappedAssetMintCircuit::verify(&proof)?;
    let verification_time = start.elapsed();
    println!("Proof verification result: {}", valid);
    println!("Verification time: {:?}", verification_time);
    
    // Generate multiple proofs for aggregation
    println!("Generating multiple proofs for aggregation...");
    let mut proofs = Vec::new();
    for i in 0..4 {
        let salt = vec![i as u8; 8]; // Different salt for each proof
        let circuit = WrappedAssetMintCircuit::new(asset_id.clone(), amount, pk.clone(), salt);
        let proof = circuit.prove()?;
        proofs.push(proof);
    }
    
    // Aggregate the proofs
    println!("Aggregating proofs...");
    let options = RecursiveProverOptions {
        verbose: true,
        max_proofs_per_step: Some(2),
    };
    
    let start = Instant::now();
    let result = aggregate_proofs(proofs, options)?;
    let aggregation_time = start.elapsed();
    
    println!("Aggregated {} proofs in {:?}", result.num_proofs, aggregation_time);
    
    Ok(())
}
```

## Security Considerations

When integrating the 0BTC Wire system, consider the following security best practices:

### Input Validation

Always validate inputs before passing them to the Wire system:

```rust
// Validate asset ID
if asset_id.is_empty() || asset_id.len() > 32 {
    return Err(WireError::ValidationError(ValidationError::InputValidationError(
        "Asset ID must be between 1 and 32 bytes".to_string()
    )));
}

// Validate amount
if amount == 0 {
    return Err(WireError::ValidationError(ValidationError::InputValidationError(
        "Amount must be greater than zero".to_string()
    )));
}
```

### Error Handling

Use the structured error handling system to handle errors appropriately:

```rust
match circuit.prove() {
    Ok(proof) => {
        // Success case
    },
    Err(WireError::CryptoError(err)) => {
        // Handle cryptographic errors
        eprintln!("Cryptographic error: {}", err);
    },
    Err(WireError::ValidationError(err)) => {
        // Handle validation errors
        eprintln!("Validation error: {}", err);
    },
    Err(err) => {
        // Handle other errors
        eprintln!("Unexpected error: {}", err);
    }
}
```

### Key Management

Securely manage private keys:

- Never store private keys in plaintext
- Use a secure key management system
- Consider using hardware security modules (HSMs) for key storage

### Proof Verification

Always verify proofs before accepting them:

```rust
// Verify the proof
let valid = WrappedAssetMintCircuit::verify(&proof)?;
if !valid {
    return Err(WireError::ProofError(ProofError::InvalidProof(
        "Proof verification failed".to_string()
    )));
}
```

## Performance Optimization

### Batch Processing

For processing multiple proofs, use batch verification:

```rust
// Batch verify multiple proofs
let batch_valid = batch_verify_proofs(&proofs)?;
```

### Recursive Proof Aggregation

Use recursive proof aggregation to improve verification performance:

```rust
// Aggregate proofs
let options = RecursiveProverOptions {
    verbose: false,
    max_proofs_per_step: Some(8), // Optimal batch size
};

let result = aggregate_proofs(proofs, options)?;
```

### Parallel Processing

Enable parallel processing for proof generation:

```rust
// CLI
wire prove wrapped_mint --input mint_input.json --output mint_proof.json --parallel

// Rust
let circuit = WrappedAssetMintCircuit::new(asset_id, amount, pk, salt);
let proof = circuit.prove_parallel(num_threads)?;
```

## Troubleshooting

### Common Issues

#### WASM Module Loading Fails

```
Uncaught (in promise) TypeError: Failed to fetch
```

**Solution**: Ensure you're serving the WASM file from a web server, not a file:// URL.

#### Out of Memory Errors

```
thread 'main' has overflowed its stack
```

**Solution**: Increase the stack size:

```bash
RUST_MIN_STACK=8388608 cargo run --release
```

#### Proof Verification Fails

```
Error: ProofError(VerificationError("Proof verification failed"))
```

**Solutions**:
- Ensure the proof was generated with the correct circuit
- Check that the public inputs match the expected values
- Verify that the proof hasn't been tampered with

### Getting Help

If you encounter issues not covered in this guide:

1. Check the [GitHub Issues](https://github.com/0BTC/Wire/issues) for similar problems
2. Run with verbose logging enabled:
   ```bash
   RUST_LOG=debug wire prove wrapped_mint --input mint_input.json --verbose
   ```
3. Open a new issue with detailed information about your problem

## Conclusion

This integration guide provides the foundation for incorporating the 0BTC Wire zero-knowledge proof system into your applications. For more detailed information, refer to the [API Reference](api_reference.md) and [Security Model](security_model.md) documentation.
