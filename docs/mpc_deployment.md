# MPC Deployment Guide for 0BTC Wire

## Introduction

This document provides comprehensive instructions for deploying the Multi-Party Computation (MPC) system for 0BTC Wire in a production environment. The MPC system is a critical component that manages the bridge between Bitcoin and the 0BTC Wire system, handling mint attestations, burn proofs, and fee consolidation.

## Prerequisites

### Hardware Requirements

Each MPC operator node should meet the following minimum requirements:

- **CPU**: 4+ cores, 2.5+ GHz
- **RAM**: 8+ GB
- **Storage**: 100+ GB SSD
- **Network**: 100+ Mbps, stable connection
- **Backup Power**: UPS recommended for critical nodes

### Software Requirements

- **Operating System**: Ubuntu 20.04 LTS or later (recommended)
- **Rust**: 1.70.0 or later
- **Bitcoin Node**: Bitcoin Core 24.0 or later
- **Database**: PostgreSQL 14.0 or later (optional, for production deployments)
- **Firewall**: UFW or similar
- **Monitoring**: Prometheus + Grafana (recommended)

### Security Requirements

- Hardware Security Module (HSM) for key share storage (recommended)
- TLS certificates for secure communication
- Dedicated server with physical security measures
- Network isolation and firewall rules
- Regular security updates and patches

## Deployment Architecture

For a production deployment, we recommend a distributed architecture with at least 3 MPC operator nodes (preferably 5 or more) in different geographic locations and under different administrative domains.

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

## Deployment Steps

### 1. Server Preparation

For each MPC operator node:

1. **Update the system**:
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **Install dependencies**:
   ```bash
   sudo apt install -y build-essential pkg-config libssl-dev curl git
   ```

3. **Install Rust**:
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

4. **Set up firewall**:
   ```bash
   sudo apt install -y ufw
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 50051/tcp  # MPC communication port
   sudo ufw enable
   ```

5. **Create a dedicated user**:
   ```bash
   sudo adduser mpc-operator
   sudo usermod -aG sudo mpc-operator
   ```

### 2. Bitcoin Node Setup

Each MPC operator should have access to at least one Bitcoin node:

1. **Install Bitcoin Core**:
   ```bash
   sudo apt install -y bitcoin-core
   ```

2. **Configure Bitcoin Core**:
   Create a `bitcoin.conf` file with:
   ```
   server=1
   rpcuser=bitcoinrpc
   rpcpassword=<secure-password>
   rpcallowip=127.0.0.1
   txindex=1
   ```

3. **Start Bitcoin Core**:
   ```bash
   bitcoind -daemon
   ```

4. **Wait for initial sync**:
   ```bash
   bitcoin-cli getblockchaininfo
   ```

### 3. 0BTC Wire MPC Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/0BTC/Wire.git
   cd Wire
   ```

2. **Build the MPC operator tool**:
   ```bash
   cargo build --release --bin mpc_operator
   ```

3. **Create configuration directories**:
   ```bash
   mkdir -p ~/.0btc-wire/mpc
   ```

### 4. MPC Operator Configuration

1. **Generate TLS certificates**:
   ```bash
   openssl req -x509 -newkey rsa:4096 -keyout ~/.0btc-wire/mpc/tls_key.pem -out ~/.0btc-wire/mpc/tls_cert.pem -days 365 -nodes
   ```

2. **Initialize the MPC operator**:
   ```bash
   ./target/release/mpc_operator init \
     --parties 3 \
     --threshold 2 \
     --index <your-index> \
     --addresses "node1.example.com:50051,node2.example.com:50051,node3.example.com:50051" \
     --output ~/.0btc-wire/mpc/config.json
   ```

3. **Create the first admin user**:
   ```bash
   ./target/release/mpc_operator user create \
     --username admin \
     --role admin
   ```
   Follow the prompts to set a password and configure TOTP.

### 5. Distributed Key Generation

All MPC operators must participate in the DKG ceremony:

1. **Initiate DKG on the first node**:
   ```bash
   ./target/release/mpc_operator dkg --ceremony-id initial-dkg
   ```

2. **Join DKG on other nodes**:
   ```bash
   ./target/release/mpc_operator dkg --ceremony-id initial-dkg
   ```

3. **Verify key generation**:
   ```bash
   ./target/release/mpc_operator key-info
   ```

### 6. Service Configuration

1. **Create a systemd service**:
   Create `/etc/systemd/system/mpc-operator.service`:
   ```
   [Unit]
   Description=0BTC Wire MPC Operator
   After=network.target

   [Service]
   User=mpc-operator
   Group=mpc-operator
   WorkingDirectory=/home/mpc-operator/Wire
   ExecStart=/home/mpc-operator/Wire/target/release/mpc_operator server
   Restart=on-failure
   RestartSec=5

   [Install]
   WantedBy=multi-user.target
   ```

2. **Enable and start the service**:
   ```bash
   sudo systemctl enable mpc-operator
   sudo systemctl start mpc-operator
   ```

3. **Check service status**:
   ```bash
   sudo systemctl status mpc-operator
   ```

## Monitoring and Maintenance

### Monitoring Setup

1. **Install Prometheus and Node Exporter**:
   ```bash
   sudo apt install -y prometheus prometheus-node-exporter
   ```

2. **Configure Prometheus**:
   Add the MPC operator metrics endpoint to `/etc/prometheus/prometheus.yml`.

3. **Install Grafana**:
   ```bash
   sudo apt install -y grafana
   sudo systemctl enable grafana-server
   sudo systemctl start grafana-server
   ```

4. **Configure Grafana**:
   - Add Prometheus as a data source
   - Import the MPC operator dashboard (provided separately)

### Backup Procedures

1. **Key Share Backup**:
   ```bash
   ./target/release/mpc_operator backup key-share --output ~/key-share-backup.enc
   ```
   Store the encrypted backup securely offline.

2. **Configuration Backup**:
   ```bash
   tar -czf ~/mpc-config-backup.tar.gz ~/.0btc-wire/mpc
   ```
   Store the configuration backup securely offline.

3. **Database Backup** (if using PostgreSQL):
   ```bash
   pg_dump -U mpc_user mpc_database > ~/mpc-db-backup.sql
   ```

### Regular Maintenance

1. **System Updates**:
   ```bash
   sudo apt update
   sudo apt upgrade -y
   ```

2. **MPC Software Updates**:
   ```bash
   cd Wire
   git pull
   cargo build --release --bin mpc_operator
   sudo systemctl restart mpc-operator
   ```

3. **Key Rotation** (every 6-12 months):
   ```bash
   ./target/release/mpc_operator key-rotation initiate --reason "Regular rotation"
   ```
   All operators must participate in the key rotation ceremony.

4. **Security Audit**:
   Conduct regular security audits of the MPC operator nodes.

## Troubleshooting

### Common Issues

1. **Communication Failures**:
   - Check network connectivity between nodes
   - Verify firewall rules
   - Check TLS certificate validity

2. **Ceremony Failures**:
   - Ensure all operators are online and responsive
   - Check logs for specific errors
   - Restart the ceremony if necessary

3. **Bitcoin Node Issues**:
   - Check Bitcoin node connectivity
   - Verify RPC credentials
   - Check for Bitcoin network forks

### Logs and Diagnostics

1. **View Service Logs**:
   ```bash
   sudo journalctl -u mpc-operator -f
   ```

2. **Check MPC Status**:
   ```bash
   ./target/release/mpc_operator status
   ```

3. **Diagnostic Tools**:
   ```bash
   ./target/release/mpc_operator diagnostics
   ```

## Disaster Recovery

### Node Failure

1. **Restore from Backup**:
   ```bash
   mkdir -p ~/.0btc-wire/mpc
   tar -xzf ~/mpc-config-backup.tar.gz -C ~/
   ./target/release/mpc_operator restore key-share --input ~/key-share-backup.enc
   ```

2. **Rejoin the MPC Network**:
   ```bash
   ./target/release/mpc_operator rejoin
   ```

### Key Compromise

1. **Notify All Operators**:
   Contact all other MPC operators immediately.

2. **Initiate Emergency Key Rotation**:
   ```bash
   ./target/release/mpc_operator key-rotation initiate --reason "Emergency rotation due to potential compromise" --emergency
   ```

3. **Investigate the Compromise**:
   Conduct a security investigation to determine the cause and extent of the compromise.

## Conclusion

This deployment guide provides the necessary steps to set up a secure and reliable MPC operator node for the 0BTC Wire system. Following these instructions will help ensure the security and integrity of the bridge between Bitcoin and the 0BTC Wire system.

For additional assistance, contact the 0BTC Wire development team or refer to the other documentation in the `docs/` directory.
