# Collateral Locking Mechanism in Wire Protocol

## Overview

This document explains the collateral locking mechanism used in the Wire protocol stablecoin system. The Wire protocol implements a fully collateralized stablecoin (zUSD) that is backed by wrapped Bitcoin (wBTC). This document details how collateral is locked, managed, and redeemed within the system.

## Core Components

### 1. Collateral UTXO Structure

The collateral locking mechanism is built around a specialized UTXO structure called `CollateralUTXOTarget`, which consists of:

- **Standard UTXO Fields**:
  - `owner_pubkey_hash`: Set to the MPC committee's public key hash
  - `asset_id`: Set to wBTC asset ID
  - `amount`: The amount of wBTC locked as collateral
  - `salt`: Random value for uniqueness

- **Collateral Metadata**:
  - `issuance_id`: Unique identifier for the stablecoin issuance
  - `lock_timestamp`: When the collateral was locked
  - `timelock_period`: Minimum period the collateral must remain locked
  - `lock_price`: BTC/USD price at the time of locking
  - `collateral_ratio`: Overcollateralization ratio (e.g., 150%)

### 2. Collateral Registry

The system maintains a `CollateralRegistry` that:
- Tracks all locked collateral UTXOs
- Allows finding collateral by issuance ID
- Enables verification of collateral status

## Collateral Locking Process

### 1. Stablecoin Minting

When a user mints zUSD stablecoins:

1. **Price Attestation**:
   - The MPC committee provides a signed BTC/USD price attestation
   - The attestation includes a timestamp to ensure freshness

2. **Collateral Calculation**:
   - Required collateral = (zUSD amount / BTC price) * overcollateralization ratio
   - Example: For 1000 zUSD with BTC at $50,000 and 150% collateral ratio:
     - Required collateral = (1000 / 50000) * 1.5 = 0.03 wBTC

3. **Collateral Verification**:
   - Verify the user has sufficient wBTC
   - Verify the collateralization ratio meets minimum requirements (≥ 150%)
   - Verify the price attestation is recent and signed by the MPC committee

4. **Collateral Locking**:
   - Create a collateral UTXO with the required wBTC amount
   - Set the owner to the MPC committee's public key hash
   - Store metadata including issuance ID, lock timestamp, and price
   - Lock the collateral with a minimum timelock period (24 hours)

5. **Stablecoin Issuance**:
   - Create a zUSD UTXO owned by the user
   - Link the zUSD issuance to the collateral via the issuance ID

### 2. Circuit Implementation

The `StablecoinMintCircuit` enforces these rules through zero-knowledge proofs:

```
StablecoinMintCircuit
├── Inputs:
│   ├── User's wBTC UTXO
│   ├── Price attestation (timestamp, BTC/USD price, MPC signature)
│   └── User's signature authorizing the mint
├── Outputs:
│   ├── Collateral UTXO (owned by MPC committee)
│   └── zUSD UTXO (owned by user)
└── Constraints:
    ├── Verify price attestation signature and recency
    ├── Calculate required collateral amount
    ├── Verify sufficient collateral
    ├── Verify minimum collateralization ratio (≥ 150%)
    ├── Create unique issuance ID
    └── Create properly structured output UTXOs
```

## Collateral Redemption Process

### 1. Stablecoin Redemption

When a user redeems zUSD for the underlying collateral:

1. **Redemption Request**:
   - User provides zUSD UTXOs to burn
   - User provides proof of ownership
   - User specifies the issuance ID of the collateral to unlock

2. **Collateral Verification**:
   - Verify the timelock period has elapsed
   - Verify the collateral is sufficient at current prices
   - Verify the issuance ID matches the redemption request

3. **Collateral Release**:
   - Create a wBTC UTXO owned by the user
   - Amount = (zUSD amount / current BTC price)
   - Burn the zUSD UTXOs

4. **Circuit Implementation**:
   - `StablecoinRedeemCircuit` enforces these rules through zero-knowledge proofs

### 2. Timelock Enforcement

Collateral is subject to a minimum timelock period (24 hours) to:
- Prevent flash loan attacks
- Allow time for price oracle updates
- Provide stability to the system

The `is_valid_for_redemption` function in `CollateralUTXOTarget` enforces:
- Current timestamp > lock timestamp + timelock period
- Collateral value at current price ≥ zUSD amount
- Issuance ID matches the redemption request

## Security Considerations

### 1. Price Oracle Security

- Price attestations are signed by the MPC committee
- Attestations have a limited validity period
- System rejects outdated price information
- Multiple price sources can be used for redundancy

### 2. Collateralization Safety

- Minimum collateralization ratio of 150%
- Additional safety margin against price volatility
- Verification at both mint and redemption time
- Circuit constraints prevent undercollateralized issuance

### 3. MPC Committee Control

- Collateral UTXOs are owned by the MPC committee
- Committee members must cooperate to release collateral
- Threshold signature scheme prevents single-party control
- Committee rotation possible without affecting locked collateral

## Implementation Details

### 1. Fixed-Point Arithmetic

The system uses fixed-point arithmetic for precise calculations:
- `FIXED_POINT_SCALING_FACTOR` = 1,000,000
- Values are scaled up for calculations and scaled down for storage
- Prevents rounding errors in collateral calculations

### 2. Nullifier Management

- Each collateral UTXO has a unique nullifier
- Prevents double-spending of collateral
- Enables tracking of collateral status

### 3. Circuit Optimizations

- Efficient range checks for price and amount validation
- Reuse of common components across circuits
- Batch processing for multiple redemptions

## Integration Guidelines

### 1. Client Applications

- Query the current state of collateral before minting or redeeming
- Implement retry logic for failed transactions
- Display collateralization ratio to users
- Show timelock period remaining before redemption is possible

### 2. Indexers and Explorers

- Track and index collateral UTXOs
- Provide APIs for querying collateral status
- Calculate system-wide collateralization metrics
- Alert on approaching under-collateralization

## Future Improvements

1. **Dynamic Collateralization Ratios**:
   - Adjust required collateral based on market volatility
   - Implement tiered collateralization requirements

2. **Multi-Asset Collateral**:
   - Support multiple collateral types beyond wBTC
   - Implement risk-weighted collateral calculations

3. **Liquidation Mechanisms**:
   - Automated liquidation of under-collateralized positions
   - Auction system for collateral liquidation

4. **Governance Parameters**:
   - Allow adjustment of timelock periods
   - Allow adjustment of minimum collateralization ratios

## Conclusion

The Wire protocol implements a robust collateral locking mechanism that ensures the stablecoin system remains fully backed at all times. The combination of UTXO-based state management, zero-knowledge proofs, and MPC committee oversight provides strong security guarantees while maintaining privacy and scalability.
