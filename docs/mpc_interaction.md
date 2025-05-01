# MPC Interaction Guide for 0BTC Wire

## Introduction

This document details the interaction between users and the Multi-Party Computation (MPC) custodian system for 0BTC Wire. The MPC custodian system is responsible for:

1. Attesting to Bitcoin deposits for minting wrapped Bitcoin (wBTC)
2. Processing burn proofs and initiating Bitcoin withdrawals
3. Consolidating fees collected in the fee reservoir

## Architecture Overview

The 0BTC Wire MPC system uses a threshold signature scheme to distribute trust among multiple operators. No single operator can generate signatures or access private keys alone.

```
                                 ┌─────────────────┐
                                 │                 │
                                 │  Bitcoin Node   │
                                 │                 │
                                 └────────┬────────┘
                                          │
                                          ▼
┌─────────────────┐             ┌─────────────────┐             ┌─────────────────┐
│                 │             │                 │             │                 │
│  MPC Operator   │◄───────────►│  MPC Operator   │◄───────────►│  MPC Operator   │
│  Node 1         │             │  Node 2         │             │  Node 3         │
│                 │             │                 │             │                 │
└────────┬────────┘             └────────┬────────┘             └────────┬────────┘
         │                               │                               │
         └───────────────────────────────┼───────────────────────────────┘
                                         │
                                         ▼
                                ┌─────────────────┐
                                │                 │
                                │  0BTC Wire      │
                                │  System         │
                                │                 │
                                └─────────────────┘
```

## User Mint Flow

### Step 1: Deposit Bitcoin

1. User requests a deposit address from the 0BTC Wire system
2. User sends Bitcoin to the provided deposit address
3. MPC operators monitor the Bitcoin blockchain for deposits

### Step 2: Obtain Mint Attestation

1. Once the deposit has sufficient confirmations (typically 6), MPC operators generate a threshold signature for a mint attestation
2. The attestation contains:
   - Bitcoin transaction ID and output index
   - Recipient's public key hash in the 0BTC Wire system
   - Amount in satoshis
   - Nonce to prevent replay attacks
   - Expiry timestamp
   - Threshold signature from the MPC operators

### Step 3: Mint Wrapped Bitcoin

1. User receives the attestation from the MPC operators
2. User creates a `WrappedAssetMintCircuit` proof using the attestation
3. User submits the proof to the 0BTC Wire system
4. The 0BTC Wire system verifies the proof and creates wrapped Bitcoin (wBTC) for the user

## User Burn Flow

### Step 1: Burn Wrapped Bitcoin

1. User creates a `WrappedAssetBurnCircuit` proof specifying:
   - Input UTXO containing wrapped Bitcoin
   - Destination Bitcoin address for withdrawal
   - Fee amount
2. User submits the proof to the 0BTC Wire system
3. The 0BTC Wire system verifies the proof and marks the wrapped Bitcoin as burned

### Step 2: Process Withdrawal

1. MPC operators monitor the 0BTC Wire system for burn proofs
2. MPC operators verify the burn proof
3. MPC operators create and sign a Bitcoin transaction to the user's specified address
4. MPC operators broadcast the transaction to the Bitcoin network
5. User receives native Bitcoin at their specified address

## Fee Consolidation Flow

1. MPC operators monitor the fee reservoir address in the 0BTC Wire system
2. When sufficient fees accumulate, MPC operators initiate a fee consolidation
3. MPC operators create and sign a `TransferCircuit` proof to consolidate fees
4. MPC operators submit the proof to the 0BTC Wire system
5. Fees are consolidated to a designated address

## MPC Operator Commands

MPC operators use the `mpc_operator` CLI tool to interact with the system:

```bash
# Initialize an MPC operator
mpc_operator init --parties 3 --threshold 2 --index 0 --addresses "localhost:50051,localhost:50052,localhost:50053" --output config.json

# Perform distributed key generation
mpc_operator dkg

# Generate a mint attestation
mpc_operator attest --txid <BITCOIN_TXID> --vout <OUTPUT_INDEX> --recipient <RECIPIENT_PUBKEY_HASH> --amount <AMOUNT_IN_SATOSHIS>

# Process a burn proof and initiate a withdrawal
mpc_operator withdraw --burn-txid <BURN_TXID> --address <BITCOIN_ADDRESS> --amount <AMOUNT_IN_SATOSHIS> --fee <FEE_IN_SATOSHIS>

# Consolidate fees
mpc_operator consolidate-fees --address <DESTINATION_ADDRESS>

# Monitor Bitcoin deposits
mpc_operator monitor-deposits --confirmations 6 --interval 300

# Process pending withdrawals
mpc_operator process-withdrawals --interval 300
```

## Security Considerations

1. **Threshold Parameters**: The recommended configuration is a 3-of-5 threshold, meaning 3 out of 5 operators must participate to generate valid signatures.

2. **Key Management**: MPC operators must secure their key shares. Loss of too many key shares could result in the inability to generate signatures.

3. **Ceremony Verification**: All operators should verify the inputs and outputs of signing ceremonies before participating.

4. **Deposit Confirmations**: Deposits should have sufficient confirmations (typically 6) before attestations are generated.

5. **Withdrawal Verification**: Burn proofs should be carefully verified before initiating withdrawals.

## Error Handling

1. **Deposit Errors**: If a deposit cannot be verified, the MPC operators will not generate an attestation.

2. **Withdrawal Errors**: If a burn proof is invalid or the withdrawal transaction fails, the MPC operators will report the error.

3. **Ceremony Errors**: If a DKG or signing ceremony fails, the MPC operators will abort the ceremony and retry.

## Conclusion

The MPC interaction system provides a secure, distributed way to manage the bridge between Bitcoin and the 0BTC Wire system. By using threshold signatures, no single operator can unilaterally control the bridge, ensuring security and decentralization.
