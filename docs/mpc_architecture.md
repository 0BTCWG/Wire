# MPC Operator Tooling Architecture

## Overview

The MPC Operator Tooling for 0BTC Wire is designed to enable secure, distributed management of cryptographic operations required for:

1. Generating mint attestations for wrapped Bitcoin (wBTC)
2. Processing burn operations and initiating BTC withdrawals
3. Consolidating fees collected in the fee reservoir

This document outlines the architecture, communication protocols, and security considerations for the MPC operator tooling.

## Architecture

The MPC operator tooling will be implemented as a standalone Rust application with the following components:

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

### Components

1. **MPC Core Library**
   - Wrapper around the selected MPC library (multi-party-eddsa)
   - Handles cryptographic operations
   - Manages key shares and threshold signatures

2. **Node Communication Module**
   - Secure communication between operator nodes
   - Protocol for distributed key generation (DKG)
   - Protocol for threshold signing ceremonies

3. **Bitcoin Interface**
   - Monitors Bitcoin blockchain for deposits
   - Verifies transaction confirmations
   - Creates and broadcasts withdrawal transactions

4. **0BTC Wire Interface**
   - Generates attestations for minting
   - Processes burn proofs for withdrawals
   - Monitors fee reservoir and initiates consolidation

5. **Operator CLI**
   - Command-line interface for operators
   - Secure configuration management
   - Ceremony initiation and participation

## Communication Protocol

The MPC nodes will communicate using a secure protocol with the following properties:

1. **Authentication**: All nodes must authenticate using TLS client certificates
2. **Encryption**: All communication is encrypted using TLS 1.3
3. **Message Format**: Protocol Buffers (protobuf) for structured data exchange
4. **Transport**: gRPC over HTTP/2 for efficient, bidirectional streaming

### Communication Flow

#### Distributed Key Generation (DKG)

```
1. Operator 1 initiates DKG ceremony
2. All operators exchange commitments
3. All operators exchange shares
4. All operators verify received shares
5. All operators compute their key share
6. Public key is published and verified by all operators
```

#### Threshold Signing

```
1. Operator detects need for signature (deposit/withdrawal/fee consolidation)
2. Initiating operator creates signing request with payload
3. Required threshold of operators approve the request
4. Participating operators exchange signature shares
5. Initiating operator aggregates shares into complete signature
6. Signature is verified by all operators before use
```

## Security Considerations

1. **Key Management**
   - Key shares never leave the operator's secure environment
   - Hardware security modules (HSMs) recommended for production
   - Regular key rotation procedures

2. **Node Security**
   - Dedicated, hardened servers for each operator
   - Network isolation and firewall rules
   - Regular security updates and monitoring

3. **Operational Security**
   - Multi-factor authentication for operators
   - Audit logging of all operations
   - Regular security drills and incident response procedures

4. **Threshold Parameters**
   - Recommended: 3-of-5 threshold for balance of security and availability
   - Minimum: 2-of-3 threshold for smaller deployments
   - Consider geographic and organizational distribution of operators

## Implementation Plan

1. **Phase 1: Core Library and CLI**
   - Implement MPC core library wrapper
   - Create basic CLI for local testing
   - Implement DKG and signing ceremonies

2. **Phase 2: Node Communication**
   - Implement secure communication protocol
   - Create node discovery and authentication
   - Test distributed operations

3. **Phase 3: Bitcoin and 0BTC Wire Integration**
   - Implement Bitcoin monitoring and transaction creation
   - Integrate with 0BTC Wire for attestations and burns
   - Implement fee consolidation logic

4. **Phase 4: Security Hardening and Testing**
   - Security review and penetration testing
   - Performance optimization
   - Documentation and operator training
