# MPC Custody & Fee Management

This document defines the interaction flows between the 0BTC Wire system and the Multi-Party Computation (MPC) custody system that secures the wrapped Bitcoin assets.

## 1. MPC Interaction Flows

### 1.1 Minting Flow

The minting process allows users to deposit BTC and receive wBTC on the 0BTC Wire system. The MPC custodians must verify the BTC deposit and authorize the minting operation.

#### Process Flow

1. **BTC Deposit**
   - User initiates a deposit by sending BTC to a designated MPC-controlled Bitcoin address
   - The deposit transaction includes a memo/reference to link it to the user's 0BTC Wire address

2. **Deposit Verification**
   - MPC operators verify the Bitcoin transaction has sufficient confirmations (typically 6+)
   - MPC operators validate the amount and the destination reference

3. **Attestation Generation**
   ```
   SignedAttestationTarget {
       recipient_hash: [32 bytes], // Hash of recipient's public key
       amount: u64,                // Amount in satoshis
       nonce: u64,                 // Unique nonce to prevent replay attacks
       signature: SignatureTarget  // MPC custodian's signature
   }
   ```

4. **Attestation Distribution**
   - The signed attestation is securely provided to the user via an authenticated API endpoint
   - The API requires user authentication to ensure the attestation is delivered to the correct recipient
   - The attestation includes a nonce with a limited validity period (e.g., 24 hours)

5. **Mint Circuit Execution**
   - User invokes the `WrappedAssetMintCircuit` with the attestation
   - The circuit verifies the custodian's signature on the attestation
   - Upon successful verification, wBTC is minted to the recipient's address

### 1.2 Burning Flow

The burning process allows users to redeem their wBTC for BTC. The MPC custodians must verify the burn proof and process the BTC withdrawal.

#### Process Flow

1. **Burn Request**
   - User creates a burn request specifying:
     - Amount of wBTC to burn
     - Destination Bitcoin address
     - Optional fee quote (if using variable fees)

2. **Fee Quote (Optional)**
   - If using variable fees, the user requests a fee quote from the MPC operators
   - The fee quote includes:
     ```
     FeeQuote {
         fee_btc: u64,           // Fee amount in satoshis
         expiry: u64,            // Timestamp when the quote expires
         signature: Signature    // MPC custodian's signature on the quote
     }
     ```

3. **Burn Circuit Execution**
   - User invokes the `WrappedAssetBurnCircuit` with:
     - Input UTXO containing the wBTC to burn
     - Destination BTC address
     - Optional fee quote
   - The circuit verifies ownership and signatures
   - The circuit registers the nullifier, amount, and destination address as public inputs

4. **Proof Verification**
   - MPC operators monitor the L1/DA layer for burn proofs
   - When a valid burn proof is detected, operators verify:
     - The proof is valid
     - The nullifier hasn't been used before
     - The fee (if applicable) is correct

5. **BTC Withdrawal**
   - MPC operators initiate a Bitcoin transaction to the specified destination address
   - The withdrawal amount equals the burn amount minus the fee
   - The transaction is signed using the MPC threshold signature scheme
   - A reference to the burn proof is included in the transaction metadata

6. **Withdrawal Confirmation**
   - The withdrawal status is updated in the system
   - Users can track their withdrawal status via an API or UI

### 1.3 Fee Management

Fees collected from various operations are sent to a designated Fee Reservoir Address controlled by the MPC operators.

#### Fee Reservoir Address

The `FeeReservoirAddressHash` is defined as:
```
FeeReservoirAddressHash = Hash(MPC_FEE_COLLECTOR_PUBLIC_KEY)
```

Where `MPC_FEE_COLLECTOR_PUBLIC_KEY` is a public key derived from the MPC threshold scheme specifically for fee collection.

The actual value for the testnet environment is:
```
FeeReservoirAddressHash = 0x7a1e23f58c5b8c42c3e8d1c2f9d94c7e751b0c2e8a6df87a8a9d6b7f8c9d0e1f
```

For production, a different address will be used and securely generated through the MPC ceremony.

## 2. MPC Fee Sweeping Logic

### 2.1 Fee Monitoring

MPC operators run a monitoring service that:
- Scans the L1/DA layer for UTXOs created with the `FeeReservoirAddressHash` as the owner
- Maintains a database of fee UTXOs that have been detected but not yet consolidated
- Triggers the fee sweeping process when certain conditions are met (e.g., accumulated fees exceed a threshold, or a time period has elapsed)

### 2.2 Fee Consolidation

When fee sweeping is triggered:

1. **UTXO Selection**
   - The monitoring service selects fee UTXOs to be consolidated
   - It creates a list of input UTXOs and calculates the total amount

2. **Consolidation Transaction Creation**
   - MPC operators use their collective private key to:
     - Create input data for the `TransferCircuit`
     - Specify the main MPC operational address as the recipient
     - Set the amount to the total of all input UTXOs

3. **Proof Generation**
   - Generate a ZK proof for the consolidation transaction
   - The proof demonstrates that:
     - The MPC operators control the fee reservoir address
     - All input UTXOs are valid and owned by the fee reservoir address
     - The output UTXO correctly represents the sum of all inputs

4. **Transaction Submission**
   - Submit the proof and transaction data to the L1/DA layer
   - Register all input nullifiers to prevent double-spending

### 2.3 Security Considerations

- The MPC private key for the fee reservoir address must be managed with the highest security standards
- The key should be stored using a threshold signature scheme (e.g., t-of-n where t > n/2)
- Hardware security modules (HSMs) should be used by each MPC participant
- Regular security audits should be conducted on the fee sweeping infrastructure
- Monitoring and alerting systems should detect any unauthorized access attempts

## 3. Implementation

The implementation of these flows involves both on-chain (circuit) components and off-chain (MPC operator) components.

### 3.1 On-Chain Components

- `WrappedAssetMintCircuit`: Verifies custodian attestations for minting
- `WrappedAssetBurnCircuit`: Processes burn requests and registers nullifiers
- `TransferCircuit`: Used for fee consolidation

### 3.2 Off-Chain Components

- **MPC Custody Service**: Manages the MPC threshold signature scheme
- **Deposit Monitor**: Tracks BTC deposits and generates attestations
- **Burn Monitor**: Tracks burn proofs and processes withdrawals
- **Fee Monitor**: Tracks fee UTXOs and triggers consolidation
- **API Service**: Provides secure interfaces for users to interact with the MPC system

These components will be implemented as separate services that communicate securely with each other and with the blockchain.
