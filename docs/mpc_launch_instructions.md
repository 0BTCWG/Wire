# MPC Launch Instructions for 0BTC Wire Service

## Introduction

This document provides detailed instructions for MPC organizations to prepare for the launch of the 0BTC Wire service. These instructions are intended for the designated MPC operators who will be responsible for managing the secure bridge between Bitcoin and the 0BTC Wire system.

## Timeline

| Phase | Duration | Start Date | End Date |
|-------|----------|------------|----------|
| Preparation | 2 weeks | May 5, 2025 | May 19, 2025 |
| Coordination | 1 week | May 19, 2025 | May 26, 2025 |
| Key Generation | 1 day | May 27, 2025 | May 27, 2025 |
| Testing | 1 week | May 28, 2025 | June 3, 2025 |
| Launch | 1 day | June 4, 2025 | June 4, 2025 |

## Prerequisites

Each MPC organization must have:

1. **Dedicated Hardware**:
   - Server with minimum 4 cores, 8GB RAM, 100GB SSD
   - Hardware Security Module (HSM) for key share storage (strongly recommended)
   - Redundant power and network connectivity
   - Physical security measures for the server location

2. **Network Requirements**:
   - Static IP address
   - Ability to open specific ports for MPC communication (default: 50051)
   - Reliable, low-latency internet connection (minimum 10 Mbps, <100ms latency to other operators)
   - Firewall configured to allow only necessary connections

3. **Bitcoin Node**:
   - Fully synced Bitcoin Core node (v24.0 or later)
   - Minimum 500GB storage for blockchain data
   - RPC access configured securely

4. **Personnel**:
   - Primary operator (available 24/7 for critical operations)
   - Backup operator (trained and ready to step in if needed)
   - Security officer (responsible for key management procedures)

## Preparation Phase (2 weeks)

### 1. Infrastructure Setup

1. **Server Provisioning**:
   ```bash
   # Update system
   sudo apt update && sudo apt upgrade -y
   
   # Install dependencies
   sudo apt install -y build-essential pkg-config libssl-dev curl git
   
   # Set up firewall
   sudo apt install -y ufw
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 50051/tcp  # MPC communication port
   sudo ufw enable
   ```

2. **Bitcoin Node Setup**:
   ```bash
   # Install Bitcoin Core
   sudo apt install -y bitcoin-core
   
   # Configure Bitcoin Core
   mkdir -p ~/.bitcoin
   cat > ~/.bitcoin/bitcoin.conf << EOF
   server=1
   rpcuser=bitcoinrpc
   rpcpassword=$(openssl rand -hex 32)
   rpcallowip=127.0.0.1
   txindex=1
   EOF
   
   # Start Bitcoin Core and begin syncing
   bitcoind -daemon
   ```

3. **0BTC Wire Installation**:
   ```bash
   # Clone repository
   git clone https://github.com/0BTC/Wire.git
   cd Wire
   
   # Build the MPC operator tool
   cargo build --release --bin mpc_operator
   
   # Create configuration directories
   mkdir -p ~/.0btc-wire/mpc
   ```

4. **TLS Certificate Generation**:
   ```bash
   # Generate TLS certificates
   openssl req -x509 -newkey rsa:4096 -keyout ~/.0btc-wire/mpc/tls_key.pem \
     -out ~/.0btc-wire/mpc/tls_cert.pem -days 365 -nodes
   ```

### 2. Security Configuration

1. **HSM Setup** (if available):
   - Follow your HSM vendor's instructions for initialization
   - Configure the HSM for Ed25519 key operations
   - Test HSM connectivity with the server

2. **Backup Procedures**:
   - Prepare secure offline storage for key share backups
   - Document the backup and recovery procedures
   - Test the backup and recovery process

3. **Monitoring Setup**:
   ```bash
   # Install monitoring tools
   sudo apt install -y prometheus prometheus-node-exporter grafana
   
   # Configure Prometheus
   sudo tee /etc/prometheus/prometheus.yml > /dev/null << EOF
   global:
     scrape_interval: 15s
   
   scrape_configs:
     - job_name: 'mpc_operator'
       static_configs:
         - targets: ['localhost:9090']
   EOF
   
   # Start monitoring services
   sudo systemctl enable prometheus
   sudo systemctl start prometheus
   sudo systemctl enable grafana-server
   sudo systemctl start grafana-server
   ```

### 3. Communication Setup

1. **Secure Communication Channel**:
   - Establish a secure communication channel with other MPC operators
   - Exchange contact information (email, phone, secure messaging)
   - Verify identities of all operators

2. **Network Testing**:
   ```bash
   # Test connectivity to other MPC operators
   for ip in <operator1_ip> <operator2_ip> <operator3_ip>; do
     nc -zv $ip 50051
   done
   ```

## Coordination Phase (1 week)

### 1. Configuration Exchange

1. **Share Network Information**:
   - Share your node's public IP address and port with other operators
   - Verify connectivity between all nodes

2. **Create Configuration File**:
   ```bash
   # Create a draft configuration
   cat > ~/.0btc-wire/mpc/config.json << EOF
   {
     "parties": <number_of_operators>,
     "threshold": <required_threshold>,
     "party_addresses": [
       "<operator1_address>:50051",
       "<operator2_address>:50051",
       "<operator3_address>:50051"
     ],
     "my_index": <your_index>,
     "key_share_path": "~/.0btc-wire/mpc/key_share.enc",
     "tls_cert_path": "~/.0btc-wire/mpc/tls_cert.pem",
     "tls_key_path": "~/.0btc-wire/mpc/tls_key.pem",
     "user_db_path": "~/.0btc-wire/mpc/users.json",
     "security_db_path": "~/.0btc-wire/mpc/security.json",
     "bitcoin_nodes": [
       "http://localhost:8332"
     ],
     "normal_confirmations": 6,
     "fork_confirmations": 12
   }
   EOF
   ```

3. **Verify Bitcoin Nodes**:
   - Ensure all Bitcoin nodes are fully synced
   - Test RPC connectivity
   ```bash
   bitcoin-cli getblockchaininfo
   ```

### 2. Ceremony Planning

1. **Schedule Key Generation Ceremony**:
   - Agree on a specific date and time for the DKG ceremony
   - Ensure all operators can participate
   - Prepare a backup date in case of issues

2. **Ceremony Rehearsal**:
   - Conduct a rehearsal of the DKG ceremony
   - Document any issues and resolve them
   - Ensure all operators understand their roles

3. **Emergency Procedures**:
   - Document procedures for handling ceremony failures
   - Establish communication protocols for emergencies
   - Assign responsibilities for emergency response

## Key Generation Phase (1 day)

### 1. Preparation

1. **Verify System Readiness**:
   ```bash
   # Check system status
   df -h  # Verify disk space
   free -m  # Verify memory
   uptime  # Verify system load
   
   # Check Bitcoin node status
   bitcoin-cli getblockchaininfo
   
   # Verify MPC operator tool
   cd ~/Wire
   ./target/release/mpc_operator --version
   ```

2. **Initialize MPC Operator**:
   ```bash
   # Initialize the MPC operator with the final configuration
   ./target/release/mpc_operator init \
     --parties <number_of_operators> \
     --threshold <required_threshold> \
     --index <your_index> \
     --addresses "<operator1_address>:50051,<operator2_address>:50051,<operator3_address>:50051" \
     --output ~/.0btc-wire/mpc/config.json
   ```

3. **Create Admin User**:
   ```bash
   # Create the first admin user
   ./target/release/mpc_operator user create \
     --username admin \
     --role admin
   ```
   - Follow the prompts to set a strong password
   - Configure TOTP using an authenticator app
   - Store the backup codes securely

### 2. Distributed Key Generation

1. **Start DKG Ceremony**:
   - The designated ceremony coordinator initiates the DKG:
   ```bash
   # Initiate DKG (coordinator only)
   ./target/release/mpc_operator dkg --ceremony-id initial-dkg
   ```

   - Other operators join the ceremony:
   ```bash
   # Join DKG (other operators)
   ./target/release/mpc_operator dkg --ceremony-id initial-dkg
   ```

2. **Verify Key Generation**:
   ```bash
   # Verify key information
   ./target/release/mpc_operator key-info
   ```

3. **Backup Key Shares**:
   ```bash
   # Create an encrypted backup of the key share
   ./target/release/mpc_operator backup key-share --output ~/key-share-backup.enc
   ```
   - Store the backup securely according to your backup procedures
   - Verify that the backup can be restored if needed

### 3. Service Configuration

1. **Create Systemd Service**:
   ```bash
   # Create systemd service file
   sudo tee /etc/systemd/system/mpc-operator.service > /dev/null << EOF
   [Unit]
   Description=0BTC Wire MPC Operator
   After=network.target
   
   [Service]
   User=$USER
   Group=$USER
   WorkingDirectory=$HOME/Wire
   ExecStart=$HOME/Wire/target/release/mpc_operator server
   Restart=on-failure
   RestartSec=5
   
   [Install]
   WantedBy=multi-user.target
   EOF
   
   # Enable and start the service
   sudo systemctl enable mpc-operator
   sudo systemctl start mpc-operator
   
   # Check service status
   sudo systemctl status mpc-operator
   ```

## Testing Phase (1 week)

### 1. Basic Functionality Testing

1. **Test Communication**:
   ```bash
   # Test communication between nodes
   ./target/release/mpc_operator test-communication
   ```

2. **Test Signing**:
   ```bash
   # Create a test signing ceremony
   ./target/release/mpc_operator test-signing --message "test message"
   ```

3. **Verify Monitoring**:
   - Access Grafana dashboard at http://localhost:3000
   - Configure dashboards for MPC metrics
   - Test alerting functionality

### 2. End-to-End Testing

1. **Test Mint Attestation**:
   ```bash
   # Test mint attestation workflow
   ./target/release/mpc_operator test-attestation \
     --txid <test_txid> \
     --vout 0 \
     --recipient <test_recipient> \
     --amount 100000000
   ```

2. **Test Burn Processing**:
   ```bash
   # Test burn processing workflow
   ./target/release/mpc_operator test-burn \
     --txid <test_burn_txid> \
     --address <test_btc_address> \
     --amount 50000000 \
     --fee 1000
   ```

3. **Test Fee Consolidation**:
   ```bash
   # Test fee consolidation workflow
   ./target/release/mpc_operator test-consolidate-fees \
     --address <test_destination_address>
   ```

### 3. Disaster Recovery Testing

1. **Test Node Failure Recovery**:
   - Simulate a node failure by stopping the service
   - Verify that the system continues to function with the remaining nodes
   - Restore the node and verify it rejoins the network

2. **Test Backup Restoration**:
   ```bash
   # Test key share restoration
   ./target/release/mpc_operator restore key-share --input ~/key-share-backup.enc
   ```

3. **Test Emergency Procedures**:
   - Simulate various emergency scenarios
   - Verify that the documented procedures work as expected
   - Update procedures based on test results

## Launch Phase (1 day)

### 1. Final Verification

1. **System Check**:
   ```bash
   # Verify system status
   ./target/release/mpc_operator status
   
   # Check Bitcoin node status
   bitcoin-cli getblockchaininfo
   
   # Verify service status
   sudo systemctl status mpc-operator
   ```

2. **Security Verification**:
   ```bash
   # Run security checks
   ./target/release/mpc_operator security-check
   ```

3. **Coordination Check**:
   - Verify communication with all operators
   - Confirm readiness for launch
   - Address any last-minute concerns

### 2. Service Activation

1. **Enable Public Service**:
   ```bash
   # Enable public service
   ./target/release/mpc_operator enable-service
   ```

2. **Verify Service Status**:
   ```bash
   # Verify service is active
   ./target/release/mpc_operator service-status
   ```

3. **Monitor Initial Operations**:
   - Closely monitor the system during initial operations
   - Be prepared to respond to any issues
   - Maintain communication with all operators

## Post-Launch Procedures

### 1. Regular Maintenance

1. **System Updates**:
   ```bash
   # Regular system updates
   sudo apt update && sudo apt upgrade -y
   
   # Restart services if needed
   sudo systemctl restart mpc-operator
   ```

2. **Key Rotation**:
   - Schedule regular key rotations (every 6-12 months)
   ```bash
   # Initiate key rotation
   ./target/release/mpc_operator key-rotation initiate --reason "Regular rotation"
   ```

3. **Backup Verification**:
   - Regularly test backup and recovery procedures
   - Ensure all operators maintain secure backups

### 2. Monitoring and Reporting

1. **Regular Status Reports**:
   - Generate weekly status reports
   ```bash
   # Generate status report
   ./target/release/mpc_operator generate-report --period weekly
   ```

2. **Incident Response**:
   - Document any incidents or issues
   - Conduct post-incident reviews
   - Implement improvements based on lessons learned

3. **Performance Optimization**:
   - Monitor system performance
   - Identify and address bottlenecks
   - Implement optimizations as needed

## Contact Information

For coordination and support during the launch process, please contact:

- **Technical Coordinator**: [Name] - [Email] - [Phone]
- **Security Officer**: [Name] - [Email] - [Phone]
- **Emergency Contact**: [Name] - [Email] - [Phone]

## Appendix

### A. Configuration Templates

```json
{
  "parties": 3,
  "threshold": 2,
  "party_addresses": [
    "operator1.example.com:50051",
    "operator2.example.com:50051",
    "operator3.example.com:50051"
  ],
  "my_index": 0,
  "key_share_path": "~/.0btc-wire/mpc/key_share.enc",
  "tls_cert_path": "~/.0btc-wire/mpc/tls_cert.pem",
  "tls_key_path": "~/.0btc-wire/mpc/tls_key.pem",
  "user_db_path": "~/.0btc-wire/mpc/users.json",
  "security_db_path": "~/.0btc-wire/mpc/security.json",
  "bitcoin_nodes": [
    "http://localhost:8332"
  ],
  "normal_confirmations": 6,
  "fork_confirmations": 12
}
```

### B. Ceremony Checklist

- [ ] All operators are available and ready
- [ ] All systems are up-to-date and functioning
- [ ] Secure communication channel is established
- [ ] Backup procedures are in place
- [ ] Emergency procedures are documented
- [ ] Bitcoin nodes are fully synced
- [ ] Network connectivity is verified
- [ ] Monitoring is active
- [ ] Security measures are in place

### C. Emergency Contact Protocol

1. **Communication Channels**:
   - Primary: Secure messaging platform
   - Backup: Email
   - Emergency: Phone call

2. **Escalation Procedure**:
   - Level 1: Technical issue, contact Technical Coordinator
   - Level 2: Security concern, contact Security Officer
   - Level 3: Critical emergency, contact all operators

3. **Response Time Expectations**:
   - Acknowledgment: Within 15 minutes
   - Initial response: Within 1 hour
   - Resolution plan: Within 4 hours
