# 0BTC Wire API Reference

## Table of Contents

1. [Introduction](#introduction)
2. [Core Types](#core-types)
3. [Cryptographic Gadgets](#cryptographic-gadgets)
4. [Circuits](#circuits)
5. [CLI Interface](#cli-interface)
6. [WASM Interface](#wasm-interface)
7. [Utilities](#utilities)
8. [Error Handling](#error-handling)

## Introduction

0BTC Wire is a zero-knowledge proof system for private asset transfers. This API reference documents the main components of the system, their interfaces, and usage patterns.

## Core Types

### UTXO and UTXOTarget

```rust
pub struct UTXO {
    pub salt: Vec<u8>,
    pub asset_id: Vec<u8>,
    pub amount: u64,
    pub owner_pk: PublicKey,
}

pub struct UTXOTarget {
    pub salt: Vec<Target>,
    pub asset_id: Vec<Target>,
    pub amount: Target,
    pub owner_pk: PublicKeyTarget,
}
```

The `UTXO` struct represents an Unspent Transaction Output, containing:
- `salt`: A random value for uniqueness
- `asset_id`: Identifier for the asset type
- `amount`: Amount of the asset
- `owner_pk`: Public key of the owner

The `UTXOTarget` struct is the circuit representation of a UTXO, where each field is a circuit target.

### Point and PointTarget

```rust
pub struct Point {
    pub x: F,
    pub y: F,
}

pub struct PointTarget {
    pub x: Target,
    pub y: Target,
}
```

The `Point` struct represents a point on an elliptic curve, containing:
- `x`: The x-coordinate
- `y`: The y-coordinate

The `PointTarget` struct is the circuit representation of a point, where each coordinate is a circuit target.

### PublicKey and PublicKeyTarget

```rust
pub struct PublicKey {
    pub point: Point,
}

pub struct PublicKeyTarget {
    pub point: PointTarget,
}
```

The `PublicKey` struct represents a public key, containing:
- `point`: The point on the Ed25519 curve

The `PublicKeyTarget` struct is the circuit representation of a public key.

### Signature and SignatureTarget

```rust
pub struct Signature {
    pub r_point: Point,
    pub s_scalar: F,
}

pub struct SignatureTarget {
    pub r_point: PointTarget,
    pub s_scalar: Target,
}
```

The `Signature` struct represents an EdDSA signature, containing:
- `r_point`: The R point of the signature
- `s_scalar`: The S scalar of the signature

The `SignatureTarget` struct is the circuit representation of a signature.

## Cryptographic Gadgets

### Hash Gadget

```rust
pub fn hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
) -> WireResult<Target>
```

Computes a Poseidon hash of the inputs.

**Parameters:**
- `builder`: The circuit builder
- `inputs`: The inputs to hash

**Returns:**
- `WireResult<Target>`: The hash output or an error

```rust
pub fn hash_n<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[Target],
    domain: &str,
) -> WireResult<Target>
```

Computes a domain-separated Poseidon hash of the inputs.

**Parameters:**
- `builder`: The circuit builder
- `inputs`: The inputs to hash
- `domain`: The domain separator

**Returns:**
- `WireResult<Target>`: The hash output or an error

### Signature Verification Gadget

```rust
pub fn verify_message_signature<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    message: &[Target],
    signature: &SignatureTarget,
    public_key: &PublicKeyTarget,
) -> WireResult<Target>
```

Verifies an EdDSA signature on a message.

**Parameters:**
- `builder`: The circuit builder
- `message`: The message that was signed
- `signature`: The signature to verify
- `public_key`: The public key to verify against

**Returns:**
- `WireResult<Target>`: A target that is 1 if the signature is valid, 0 otherwise, or an error

```rust
pub fn batch_verify_signatures<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    messages: &[Vec<Target>],
    signatures: &[SignatureTarget],
    public_keys: &[PublicKeyTarget],
) -> WireResult<Target>
```

Batch verifies multiple EdDSA signatures.

**Parameters:**
- `builder`: The circuit builder
- `messages`: The messages that were signed
- `signatures`: The signatures to verify
- `public_keys`: The public keys to verify against

**Returns:**
- `WireResult<Target>`: A target that is 1 if all signatures are valid, 0 otherwise, or an error

### Merkle Proof Verification Gadget

```rust
pub fn verify_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
) -> WireResult<Target>
```

Verifies a Merkle proof.

**Parameters:**
- `builder`: The circuit builder
- `leaf`: The leaf value
- `index`: The index of the leaf
- `merkle_root`: The root of the Merkle tree
- `siblings`: The sibling nodes along the path from the leaf to the root

**Returns:**
- `WireResult<Target>`: A target that is 1 if the proof is valid, 0 otherwise, or an error

```rust
pub fn assert_merkle_proof<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: Target,
    index: Target,
    merkle_root: Target,
    siblings: &[Target],
) -> WireResult<()>
```

Verifies a Merkle proof with assertions.

**Parameters:**
- `builder`: The circuit builder
- `leaf`: The leaf value
- `index`: The index of the leaf
- `merkle_root`: The root of the Merkle tree
- `siblings`: The sibling nodes along the path from the leaf to the root

**Returns:**
- `WireResult<()>`: Success or an error

### Nullifier Gadget

```rust
pub fn calculate_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    asset_id: &[Target],
    amount: Target,
    owner_sk: Target,
) -> WireResult<Target>
```

Calculates a nullifier for a UTXO.

**Parameters:**
- `builder`: The circuit builder
- `salt`: The salt of the UTXO
- `asset_id`: The asset ID of the UTXO
- `amount`: The amount of the UTXO
- `owner_sk`: The owner's secret key

**Returns:**
- `WireResult<Target>`: The nullifier or an error

```rust
pub fn calculate_and_register_nullifier<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    salt: &[Target],
    asset_id: &[Target],
    amount: Target,
    owner_sk: Target,
) -> WireResult<Target>
```

Calculates a nullifier for a UTXO and registers it as a public input.

**Parameters:**
- `builder`: The circuit builder
- `salt`: The salt of the UTXO
- `asset_id`: The asset ID of the UTXO
- `amount`: The amount of the UTXO
- `owner_sk`: The owner's secret key

**Returns:**
- `WireResult<Target>`: The nullifier or an error

## Circuits

### WrappedAssetMintCircuit

```rust
pub struct WrappedAssetMintCircuit {
    pub asset_id: Vec<u8>,
    pub amount: u64,
    pub owner_pk: PublicKey,
    pub salt: Vec<u8>,
}
```

Circuit for minting wrapped assets.

**Methods:**
- `new(asset_id: Vec<u8>, amount: u64, owner_pk: PublicKey, salt: Vec<u8>) -> Self`: Creates a new circuit
- `build<F: RichField + Extendable<D>, const D: usize>(&self) -> CircuitData<F, C, D>`: Builds the circuit
- `prove<F: RichField + Extendable<D>, const D: usize>(&self) -> ProofWithPublicInputs<F, C, D>`: Generates a proof
- `verify<F: RichField + Extendable<D>, const D: usize>(proof: &ProofWithPublicInputs<F, C, D>) -> bool`: Verifies a proof

### WrappedAssetBurnCircuit

```rust
pub struct WrappedAssetBurnCircuit {
    pub input_utxo: UTXO,
    pub owner_sk: Vec<u8>,
}
```

Circuit for burning wrapped assets.

**Methods:**
- `new(input_utxo: UTXO, owner_sk: Vec<u8>) -> Self`: Creates a new circuit
- `build<F: RichField + Extendable<D>, const D: usize>(&self) -> CircuitData<F, C, D>`: Builds the circuit
- `prove<F: RichField + Extendable<D>, const D: usize>(&self) -> ProofWithPublicInputs<F, C, D>`: Generates a proof
- `verify<F: RichField + Extendable<D>, const D: usize>(proof: &ProofWithPublicInputs<F, C, D>) -> bool`: Verifies a proof

### TransferCircuit

```rust
pub struct TransferCircuit {
    pub input_utxo: UTXO,
    pub output_utxos: Vec<UTXO>,
    pub owner_sk: Vec<u8>,
    pub fee: u64,
}
```

Circuit for transferring assets.

**Methods:**
- `new(input_utxo: UTXO, output_utxos: Vec<UTXO>, owner_sk: Vec<u8>, fee: u64) -> Self`: Creates a new circuit
- `build<F: RichField + Extendable<D>, const D: usize>(&self) -> CircuitData<F, C, D>`: Builds the circuit
- `prove<F: RichField + Extendable<D>, const D: usize>(&self) -> ProofWithPublicInputs<F, C, D>`: Generates a proof
- `verify<F: RichField + Extendable<D>, const D: usize>(proof: &ProofWithPublicInputs<F, C, D>) -> bool`: Verifies a proof

## CLI Interface

### Key Generation

```
wire keygen [--output <path>]
```

Generates a new key pair.

**Options:**
- `--output <path>`: Path to save the key pair (default: `keys.json`)

### Proof Generation

```
wire prove <circuit_type> [--input <path>] [--output <path>]
```

Generates a proof for a circuit.

**Arguments:**
- `circuit_type`: Type of circuit (`wrapped_mint`, `wrapped_burn`, `transfer`, `native_create`, `native_mint`, `native_burn`)

**Options:**
- `--input <path>`: Path to the input file (default: `input.json`)
- `--output <path>`: Path to save the proof (default: `proof.json`)

### Proof Verification

```
wire verify <circuit_type> [--proof <path>]
```

Verifies a proof.

**Arguments:**
- `circuit_type`: Type of circuit (`wrapped_mint`, `wrapped_burn`, `transfer`, `native_create`, `native_mint`, `native_burn`)

**Options:**
- `--proof <path>`: Path to the proof file (default: `proof.json`)

### Proof Aggregation

```
wire aggregate [--input <dir>] [--output <path>] [--batch-size <size>] [--verbose]
```

Aggregates multiple proofs into a single proof.

**Options:**
- `--input <dir>`: Directory containing the proofs to aggregate (default: `proofs`)
- `--output <path>`: Path to save the aggregated proof (default: `aggregated_proof.json`)
- `--batch-size <size>`: Maximum number of proofs to aggregate in a single step (default: 8)
- `--verbose`: Print progress information

## WASM Interface

### Key Generation

```javascript
function generate_keypair(): { public_key: string, private_key: string }
```

Generates a new key pair.

**Returns:**
- An object containing the public key and private key as hex strings

### Proof Generation

```javascript
function generate_proof(
    circuit_type: string,
    input: object,
    options?: { verbose?: boolean }
): { proof: string, public_inputs: string[] }
```

Generates a proof for a circuit.

**Parameters:**
- `circuit_type`: Type of circuit (`wrapped_mint`, `wrapped_burn`, `transfer`, `native_create`, `native_mint`, `native_burn`)
- `input`: Input data for the circuit
- `options`: Optional settings
  - `verbose`: Print progress information

**Returns:**
- An object containing the proof and public inputs as hex strings

### Proof Verification

```javascript
function verify_proof(
    circuit_type: string,
    proof: string,
    public_inputs: string[]
): { valid: boolean, time_ms: number }
```

Verifies a proof.

**Parameters:**
- `circuit_type`: Type of circuit (`wrapped_mint`, `wrapped_burn`, `transfer`, `native_create`, `native_mint`, `native_burn`)
- `proof`: The proof as a hex string
- `public_inputs`: The public inputs as hex strings

**Returns:**
- An object containing the verification result and time taken

### Proof Aggregation

```javascript
function aggregate_proofs(
    proofs: { proof: string, public_inputs: string[] }[],
    options?: { batch_size?: number, verbose?: boolean }
): { proof: string, public_inputs: string[], num_proofs: number }
```

Aggregates multiple proofs into a single proof.

**Parameters:**
- `proofs`: Array of proofs to aggregate
- `options`: Optional settings
  - `batch_size`: Maximum number of proofs to aggregate in a single step
  - `verbose`: Print progress information

**Returns:**
- An object containing the aggregated proof, public inputs, and number of proofs aggregated

## Utilities

### Recursive Proof Aggregation

```rust
pub fn aggregate_proofs(
    proofs: Vec<ProofWithPublicInputs<F, C, D>>,
    options: RecursiveProverOptions,
) -> WireResult<RecursiveProofResult<F, C, D>>
```

Aggregates multiple proofs into a single recursive proof.

**Parameters:**
- `proofs`: The proofs to aggregate
- `options`: Options for the aggregation

**Returns:**
- `WireResult<RecursiveProofResult<F, C, D>>`: The aggregated proof result or an error

```rust
pub fn verify_aggregated_proof(
    aggregated_proof: &ProofWithPublicInputs<F, C, D>,
    circuit_data: &CircuitData<F, C, D>,
) -> WireResult<usize>
```

Verifies an aggregated proof.

**Parameters:**
- `aggregated_proof`: The aggregated proof to verify
- `circuit_data`: The circuit data

**Returns:**
- `WireResult<usize>`: The number of proofs aggregated or an error

## Error Handling

### WireError

```rust
pub enum WireError {
    CryptoError(CryptoError),
    CircuitError(CircuitError),
    IOError(IOError),
    ProofError(ProofError),
    ValidationError(ValidationError),
    GenericError(String),
}
```

The top-level error type for the 0BTC Wire system.

### CryptoError

```rust
pub enum CryptoError {
    HashError(String),
    SignatureError(String),
    KeyError(String),
    CurveError(String),
    NullifierError(String),
    MerkleError(String),
    NonceError(String),
}
```

Error type for cryptographic operations.

### CircuitError

```rust
pub enum CircuitError {
    ConstraintError(String),
    TargetError(String),
    WitnessError(String),
    BuilderError(String),
    LayoutError(String),
}
```

Error type for circuit operations.

### IOError

```rust
pub enum IOError {
    FileSystem(String),
    Serialization(String),
    Deserialization(String),
    NetworkError(String),
}
```

Error type for I/O operations.

### ProofError

```rust
pub enum ProofError {
    ProofGenerationError(String),
    VerificationError(String),
    InvalidProof(String),
    IncompatibleProofs(String),
    RecursionError(String),
    InvalidInput(String),
}
```

Error type for proof operations.

### ValidationError

```rust
pub enum ValidationError {
    InputValidationError(String),
    TypeError(String),
    RangeError(String),
    FormatError(String),
    MissingField(String),
}
```

Error type for validation operations.

### WireResult

```rust
pub type WireResult<T> = Result<T, WireError>;
```

Result type alias for Wire operations.
