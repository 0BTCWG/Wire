# 0BTC Wire Usage Examples

This document provides practical examples of how to use the 0BTC Wire system in various scenarios.

## Table of Contents

1. [Basic Operations](#basic-operations)
2. [Asset Transfer Workflows](#asset-transfer-workflows)
3. [Batch Processing](#batch-processing)
4. [Cross-Platform Examples](#cross-platform-examples)
5. [Integration Examples](#integration-examples)

## Basic Operations

### Key Generation

#### CLI Example

```bash
# Generate a new key pair
wire keygen --output keys.json

# View the generated keys
cat keys.json
```

#### Rust Example

```rust
use wire::utils::key_generation;

fn main() {
    // Generate a key pair
    let (public_key, private_key) = key_generation::generate_keypair();
    
    println!("Public Key: {:?}", public_key);
    println!("Private Key: {:?}", private_key);
}
```

#### WASM Example

```javascript
// Import the WASM module
import * as wire from 'wire';

// Initialize the module
await wire.default();

// Generate a key pair
const keypair = wire.generate_keypair();
console.log("Public Key:", keypair.public_key);
console.log("Private Key:", keypair.private_key);
```

### Wrapped Asset Minting

#### CLI Example

```bash
# Create an input file
cat > mint_input.json << EOF
{
  "asset_id": "0x1234567890abcdef1234567890abcdef",
  "amount": 1000,
  "owner_pk": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
  "salt": "0xfedcba0987654321"
}
EOF

# Generate a proof
wire prove wrapped_mint --input mint_input.json --output mint_proof.json

# Verify the proof
wire verify wrapped_mint --proof mint_proof.json
```

#### Rust Example

```rust
use wire::circuits::WrappedAssetMintCircuit;
use wire::core::{PublicKey, Point};
use wire::utils::field::F;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create input data
    let asset_id = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let amount = 1000;
    let owner_pk = PublicKey {
        point: Point {
            x: F::from_canonical_u64(0x1234567890abcdef),
            y: F::from_canonical_u64(0xfedcba0987654321),
        },
    };
    let salt = vec![0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21];
    
    // Create the circuit
    let circuit = WrappedAssetMintCircuit::new(asset_id, amount, owner_pk, salt);
    
    // Generate a proof
    let proof = circuit.prove()?;
    
    // Verify the proof
    let valid = WrappedAssetMintCircuit::verify(&proof)?;
    println!("Proof verification result: {}", valid);
    
    Ok(())
}
```

#### WASM Example

```javascript
// Input data
const input = {
  asset_id: "0x1234567890abcdef1234567890abcdef",
  amount: 1000,
  owner_pk: keypair.public_key,
  salt: "0xfedcba0987654321"
};

// Generate a proof
const result = wire.generate_proof("wrapped_mint", input, { verbose: true });

// Verify the proof
const verification = wire.verify_proof(
  "wrapped_mint",
  result.proof,
  result.public_inputs
);

console.log("Proof valid:", verification.valid);
console.log("Verification time:", verification.time_ms, "ms");
```

### Wrapped Asset Burning

#### CLI Example

```bash
# Create an input file
cat > burn_input.json << EOF
{
  "input_utxo": {
    "salt": "0xfedcba0987654321",
    "asset_id": "0x1234567890abcdef1234567890abcdef",
    "amount": 1000,
    "owner_pk": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  },
  "owner_sk": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba"
}
EOF

# Generate a proof
wire prove wrapped_burn --input burn_input.json --output burn_proof.json

# Verify the proof
wire verify wrapped_burn --proof burn_proof.json
```

#### Rust Example

```rust
use wire::circuits::WrappedAssetBurnCircuit;
use wire::core::{UTXO, PublicKey, Point};
use wire::utils::field::F;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create input data
    let input_utxo = UTXO {
        salt: vec![0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21],
        asset_id: vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
        amount: 1000,
        owner_pk: PublicKey {
            point: Point {
                x: F::from_canonical_u64(0x1234567890abcdef),
                y: F::from_canonical_u64(0xfedcba0987654321),
            },
        },
    };
    let owner_sk = vec![0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba];
    
    // Create the circuit
    let circuit = WrappedAssetBurnCircuit::new(input_utxo, owner_sk);
    
    // Generate a proof
    let proof = circuit.prove()?;
    
    // Verify the proof
    let valid = WrappedAssetBurnCircuit::verify(&proof)?;
    println!("Proof verification result: {}", valid);
    
    Ok(())
}
```

#### WASM Example

```javascript
// Input data
const input = {
  input_utxo: {
    salt: "0xfedcba0987654321",
    asset_id: "0x1234567890abcdef1234567890abcdef",
    amount: 1000,
    owner_pk: keypair.public_key
  },
  owner_sk: keypair.private_key
};

// Generate a proof
const result = wire.generate_proof("wrapped_burn", input, { verbose: true });

// Verify the proof
const verification = wire.verify_proof(
  "wrapped_burn",
  result.proof,
  result.public_inputs
);

console.log("Proof valid:", verification.valid);
```

## Asset Transfer Workflows

### Simple Transfer

#### CLI Example

```bash
# Create an input file
cat > transfer_input.json << EOF
{
  "input_utxo": {
    "salt": "0xfedcba0987654321",
    "asset_id": "0x1234567890abcdef1234567890abcdef",
    "amount": 1000,
    "owner_pk": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
  },
  "output_utxos": [
    {
      "salt": "0x1234567890abcdef",
      "asset_id": "0x1234567890abcdef1234567890abcdef",
      "amount": 900,
      "owner_pk": "0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
    },
    {
      "salt": "0x9876543210fedcba",
      "asset_id": "0x1234567890abcdef1234567890abcdef",
      "amount": 100,
      "owner_pk": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
    }
  ],
  "owner_sk": "0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba",
  "fee": 0
}
EOF

# Generate a proof
wire prove transfer --input transfer_input.json --output transfer_proof.json

# Verify the proof
wire verify transfer --proof transfer_proof.json
```

#### Rust Example

```rust
use wire::circuits::TransferCircuit;
use wire::core::{UTXO, PublicKey, Point};
use wire::utils::field::F;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create input data
    let input_utxo = UTXO {
        salt: vec![0xfe, 0xdc, 0xba, 0x09, 0x87, 0x65, 0x43, 0x21],
        asset_id: vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
        amount: 1000,
        owner_pk: PublicKey {
            point: Point {
                x: F::from_canonical_u64(0x1234567890abcdef),
                y: F::from_canonical_u64(0xfedcba0987654321),
            },
        },
    };
    
    let recipient_pk = PublicKey {
        point: Point {
            x: F::from_canonical_u64(0xabcdef1234567890),
            y: F::from_canonical_u64(0x1234567890abcdef),
        },
    };
    
    let output_utxos = vec![
        // Recipient UTXO
        UTXO {
            salt: vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            asset_id: vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            amount: 900,
            owner_pk: recipient_pk,
        },
        // Change UTXO
        UTXO {
            salt: vec![0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba],
            asset_id: vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef],
            amount: 100,
            owner_pk: input_utxo.owner_pk.clone(),
        },
    ];
    
    let owner_sk = vec![0x98, 0x76, 0x54, 0x32, 0x10, 0xfe, 0xdc, 0xba];
    let fee = 0;
    
    // Create the circuit
    let circuit = TransferCircuit::new(input_utxo, output_utxos, owner_sk, fee);
    
    // Generate a proof
    let proof = circuit.prove()?;
    
    // Verify the proof
    let valid = TransferCircuit::verify(&proof)?;
    println!("Proof verification result: {}", valid);
    
    Ok(())
}
```

#### WASM Example

```javascript
// Input data
const input = {
  input_utxo: {
    salt: "0xfedcba0987654321",
    asset_id: "0x1234567890abcdef1234567890abcdef",
    amount: 1000,
    owner_pk: sender_keypair.public_key
  },
  output_utxos: [
    {
      salt: "0x1234567890abcdef",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 900,
      owner_pk: recipient_keypair.public_key
    },
    {
      salt: "0x9876543210fedcba",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 100,
      owner_pk: sender_keypair.public_key
    }
  ],
  owner_sk: sender_keypair.private_key,
  fee: 0
};

// Generate a proof
const result = wire.generate_proof("transfer", input, { verbose: true });

// Verify the proof
const verification = wire.verify_proof(
  "transfer",
  result.proof,
  result.public_inputs
);

console.log("Proof valid:", verification.valid);
```

### Multi-Recipient Transfer

```javascript
// Input data for multi-recipient transfer
const input = {
  input_utxo: {
    salt: "0xfedcba0987654321",
    asset_id: "0x1234567890abcdef1234567890abcdef",
    amount: 1000,
    owner_pk: sender_keypair.public_key
  },
  output_utxos: [
    // Recipient 1
    {
      salt: "0x1234567890abcdef",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 400,
      owner_pk: recipient1_keypair.public_key
    },
    // Recipient 2
    {
      salt: "0x2345678901abcdef",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 300,
      owner_pk: recipient2_keypair.public_key
    },
    // Recipient 3
    {
      salt: "0x3456789012abcdef",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 200,
      owner_pk: recipient3_keypair.public_key
    },
    // Change
    {
      salt: "0x9876543210fedcba",
      asset_id: "0x1234567890abcdef1234567890abcdef",
      amount: 100,
      owner_pk: sender_keypair.public_key
    }
  ],
  owner_sk: sender_keypair.private_key,
  fee: 0
};

// Generate a proof
const result = wire.generate_proof("transfer", input, { verbose: true });
```

## Batch Processing

### Batch Proof Generation

```rust
use wire::circuits::WrappedAssetMintCircuit;
use wire::core::{PublicKey, Point};
use wire::utils::field::F;
use std::time::Instant;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Common data
    let asset_id = vec![0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef];
    let amount = 1000;
    let owner_pk = PublicKey {
        point: Point {
            x: F::from_canonical_u64(0x1234567890abcdef),
            y: F::from_canonical_u64(0xfedcba0987654321),
        },
    };
    
    // Generate multiple proofs
    let num_proofs = 10;
    let mut proofs = Vec::with_capacity(num_proofs);
    
    let start = Instant::now();
    
    for i in 0..num_proofs {
        // Use different salt for each proof
        let salt = vec![i as u8; 8];
        
        // Create the circuit
        let circuit = WrappedAssetMintCircuit::new(
            asset_id.clone(),
            amount,
            owner_pk.clone(),
            salt,
        );
        
        // Generate a proof
        let proof = circuit.prove()?;
        proofs.push(proof);
    }
    
    let elapsed = start.elapsed();
    println!("Generated {} proofs in {:?}", num_proofs, elapsed);
    println!("Average time per proof: {:?}", elapsed / num_proofs as u32);
    
    Ok(())
}
```

### Proof Aggregation

```rust
use wire::utils::recursive_prover::{aggregate_proofs, RecursiveProverOptions};

// Aggregate the proofs
let options = RecursiveProverOptions {
    verbose: true,
    max_proofs_per_step: Some(8),
};

let result = aggregate_proofs(proofs, options)?;
println!("Aggregated {} proofs", result.num_proofs);
println!("Aggregation time: {:?}", result.generation_time);

// Verify the aggregated proof
let valid = verify_aggregated_proof(&result.proof, &result.circuit_data)?;
println!("Aggregated proof verification: {}", valid);
```

### Batch Verification

```javascript
// Batch verify multiple proofs
const proofs = [
  { proof: proof1, public_inputs: publicInputs1 },
  { proof: proof2, public_inputs: publicInputs2 },
  { proof: proof3, public_inputs: publicInputs3 }
];

const aggregated = wire.aggregate_proofs(proofs, {
  batch_size: 8,
  verbose: true
});

const verification = wire.verify_aggregated_proof(
  aggregated.proof,
  "wrapped_mint"
);

console.log("Batch verification result:", verification.valid);
console.log("Verification time:", verification.time_ms, "ms");
```

## Cross-Platform Examples

### Node.js Script

```javascript
const fs = require('fs');
const wire = require('wire');

async function main() {
  // Initialize the WASM module
  await wire.default();
  
  // Generate a key pair
  const keypair = wire.generate_keypair();
  fs.writeFileSync('keys.json', JSON.stringify(keypair, null, 2));
  
  // Create input for wrapped asset mint
  const input = {
    asset_id: "0x1234567890abcdef1234567890abcdef",
    amount: 1000,
    owner_pk: keypair.public_key,
    salt: "0xfedcba0987654321"
  };
  
  // Generate a proof
  console.log("Generating proof...");
  const result = wire.generate_proof("wrapped_mint", input, { verbose: true });
  fs.writeFileSync('proof.json', JSON.stringify(result, null, 2));
  
  // Verify the proof
  console.log("Verifying proof...");
  const verification = wire.verify_proof(
    "wrapped_mint",
    result.proof,
    result.public_inputs
  );
  
  console.log("Proof valid:", verification.valid);
  console.log("Verification time:", verification.time_ms, "ms");
}

main().catch(console.error);
```

### Python Script with CLI

```python
import json
import subprocess
import tempfile
import os

def generate_keypair():
    """Generate a key pair using the Wire CLI."""
    result = subprocess.run(
        ["wire", "keygen", "--output", "keys.json"],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Key generation failed: {result.stderr}")
    
    with open("keys.json", "r") as f:
        return json.load(f)

def mint_wrapped_asset(asset_id, amount, owner_pk, salt):
    """Mint a wrapped asset using the Wire CLI."""
    # Create input file
    input_data = {
        "asset_id": asset_id,
        "amount": amount,
        "owner_pk": owner_pk,
        "salt": salt
    }
    
    with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".json") as f:
        input_file = f.name
        json.dump(input_data, f, indent=2)
    
    # Generate proof
    output_file = "mint_proof.json"
    result = subprocess.run(
        ["wire", "prove", "wrapped_mint", "--input", input_file, "--output", output_file],
        capture_output=True,
        text=True
    )
    
    # Clean up input file
    os.unlink(input_file)
    
    if result.returncode != 0:
        raise Exception(f"Proof generation failed: {result.stderr}")
    
    # Verify proof
    result = subprocess.run(
        ["wire", "verify", "wrapped_mint", "--proof", output_file],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        raise Exception(f"Proof verification failed: {result.stderr}")
    
    print("Proof verified successfully!")
    
    # Return the proof
    with open(output_file, "r") as f:
        return json.load(f)

def main():
    # Generate a key pair
    print("Generating key pair...")
    keypair = generate_keypair()
    print(f"Public Key: {keypair['public_key'][:10]}...")
    print(f"Private Key: {keypair['private_key'][:10]}...")
    
    # Mint a wrapped asset
    print("Minting wrapped asset...")
    proof = mint_wrapped_asset(
        asset_id="0x1234567890abcdef1234567890abcdef",
        amount=1000,
        owner_pk=keypair["public_key"],
        salt="0xfedcba0987654321"
    )
    
    print(f"Proof generated and verified successfully!")

if __name__ == "__main__":
    main()
```

## Integration Examples

### Blockchain Integration

```javascript
// Example of integrating with a blockchain smart contract
async function submitProofToBlockchain(proof, publicInputs) {
  // Connect to the blockchain
  const provider = new ethers.providers.Web3Provider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = provider.getSigner();
  
  // Contract address and ABI
  const contractAddress = "0x1234567890123456789012345678901234567890";
  const contractABI = [
    "function submitProof(bytes proof, bytes[] publicInputs) external returns (bool)"
  ];
  
  // Create contract instance
  const contract = new ethers.Contract(contractAddress, contractABI, signer);
  
  // Submit the proof
  const tx = await contract.submitProof(proof, publicInputs);
  await tx.wait();
  
  console.log("Proof submitted to blockchain successfully!");
  return tx.hash;
}

// Generate and submit a proof
async function mintAndSubmit() {
  // Generate a key pair
  const keypair = wire.generate_keypair();
  
  // Create input for wrapped asset mint
  const input = {
    asset_id: "0x1234567890abcdef1234567890abcdef",
    amount: 1000,
    owner_pk: keypair.public_key,
    salt: "0xfedcba0987654321"
  };
  
  // Generate a proof
  const result = wire.generate_proof("wrapped_mint", input, { verbose: true });
  
  // Verify the proof locally
  const verification = wire.verify_proof(
    "wrapped_mint",
    result.proof,
    result.public_inputs
  );
  
  if (verification.valid) {
    // Submit to blockchain
    const txHash = await submitProofToBlockchain(result.proof, result.public_inputs);
    console.log("Transaction hash:", txHash);
  } else {
    console.error("Proof verification failed!");
  }
}
```

### API Server Integration

```javascript
const express = require('express');
const bodyParser = require('body-parser');
const wire = require('wire');

// Initialize the WASM module
let wireInitialized = false;
async function initWire() {
  await wire.default();
  wireInitialized = true;
  console.log("Wire WASM module initialized");
}

// Create Express app
const app = express();
app.use(bodyParser.json());

// Initialize Wire
initWire();

// API endpoint for generating proofs
app.post('/api/prove', async (req, res) => {
  if (!wireInitialized) {
    return res.status(503).json({ error: "Wire module not initialized yet" });
  }
  
  try {
    const { circuit_type, input, options } = req.body;
    
    // Validate input
    if (!circuit_type || !input) {
      return res.status(400).json({ error: "Missing required parameters" });
    }
    
    // Generate proof
    const result = wire.generate_proof(circuit_type, input, options || {});
    
    // Return the proof
    res.json({
      success: true,
      proof: result.proof,
      public_inputs: result.public_inputs
    });
  } catch (error) {
    console.error("Error generating proof:", error);
    res.status(500).json({ error: error.message });
  }
});

// API endpoint for verifying proofs
app.post('/api/verify', async (req, res) => {
  if (!wireInitialized) {
    return res.status(503).json({ error: "Wire module not initialized yet" });
  }
  
  try {
    const { circuit_type, proof, public_inputs } = req.body;
    
    // Validate input
    if (!circuit_type || !proof || !public_inputs) {
      return res.status(400).json({ error: "Missing required parameters" });
    }
    
    // Verify proof
    const result = wire.verify_proof(circuit_type, proof, public_inputs);
    
    // Return the verification result
    res.json({
      success: true,
      valid: result.valid,
      time_ms: result.time_ms
    });
  } catch (error) {
    console.error("Error verifying proof:", error);
    res.status(500).json({ error: error.message });
  }
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
```

### Desktop Application Integration

```javascript
const { app, BrowserWindow, ipcMain } = require('electron');
const path = require('path');
const wire = require('wire');

// Initialize the WASM module
let wireInitialized = false;
async function initWire() {
  await wire.default();
  wireInitialized = true;
  console.log("Wire WASM module initialized");
}

// Create the main window
function createWindow() {
  const mainWindow = new BrowserWindow({
    width: 800,
    height: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });
  
  mainWindow.loadFile('index.html');
}

// Initialize the app
app.whenReady().then(() => {
  createWindow();
  initWire();
  
  app.on('activate', function () {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Handle IPC messages
ipcMain.handle('generate-keypair', async () => {
  if (!wireInitialized) {
    throw new Error("Wire module not initialized yet");
  }
  
  return wire.generate_keypair();
});

ipcMain.handle('generate-proof', async (event, args) => {
  if (!wireInitialized) {
    throw new Error("Wire module not initialized yet");
  }
  
  const { circuit_type, input, options } = args;
  return wire.generate_proof(circuit_type, input, options || {});
});

ipcMain.handle('verify-proof', async (event, args) => {
  if (!wireInitialized) {
    throw new Error("Wire module not initialized yet");
  }
  
  const { circuit_type, proof, public_inputs } = args;
  return wire.verify_proof(circuit_type, proof, public_inputs);
});

// Quit when all windows are closed
app.on('window-all-closed', function () {
  if (process.platform !== 'darwin') app.quit();
});
```

This document provides practical examples of how to use the 0BTC Wire system in various scenarios. For more detailed information, refer to the [API Reference](api_reference.md) and [Integration Guide](integration_guide.md).
