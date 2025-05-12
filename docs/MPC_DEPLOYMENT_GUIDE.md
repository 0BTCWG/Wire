# MPC Deployment Guide for 0BTC Wire

This guide provides detailed instructions for deploying and operating Multi-Party Computation (MPC) nodes for the 0BTC Wire system.

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Hardware Requirements](#hardware-requirements)
3. [Server Preparation](#server-preparation)
4. [Bitcoin Node Setup](#bitcoin-node-setup)
5. [MPC Installation](#mpc-installation)
6. [Operator Configuration](#operator-configuration)
7. [Distributed Key Generation (DKG) Ceremony](#distributed-key-generation-dkg-ceremony)
8. [Service Configuration](#service-configuration)
9. [Monitoring and Alerting](#monitoring-and-alerting)
10. [Backup Procedures](#backup-procedures)
11. [Maintenance](#maintenance)
12. [Troubleshooting](#troubleshooting)
13. [Disaster Recovery](#disaster-recovery)

## Prerequisites

Before beginning the deployment process, ensure you have:

- A secure communication channel established between all MPC operators
- Access to server infrastructure with appropriate security measures
- Domain names for each MPC node (recommended)
- SSL certificates for secure communication
- Administrative access to all servers
- Familiarity with Linux server administration
- Understanding of the 0BTC Wire system architecture

## Hardware Requirements

Each MPC node should meet or exceed the following specifications:

- **CPU**: 8+ cores (Intel Xeon or AMD EPYC recommended)
- **RAM**: 32GB minimum, 64GB recommended
- **Storage**: 1TB SSD (NVMe preferred)
- **Network**: 1Gbps connection with low latency
- **Backup Power**: UPS or equivalent
- **Hardware Security Module (HSM)**: Optional but recommended for production deployments

## Server Preparation

1. **Operating System Installation**:
   - Install Ubuntu Server 22.04 LTS or later
   - Apply all security updates: `sudo apt update && sudo apt upgrade -y`
   - Configure secure SSH access (key-based authentication only)
   - Disable root login and password authentication

2. **Security Hardening**:
   ```bash
   # Install security tools
   sudo apt install -y ufw fail2ban unattended-upgrades

   # Configure firewall
   sudo ufw default deny incoming
   sudo ufw default allow outgoing
   sudo ufw allow ssh
   sudo ufw allow 8333/tcp  # Bitcoin
   sudo ufw allow 8334/tcp  # MPC communication
   sudo ufw enable

   # Configure automatic security updates
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```

3. **System Configuration**:
   ```bash
   # Create dedicated user for MPC operations
   sudo adduser mpc-operator
   sudo usermod -aG sudo mpc-operator

   # Configure system limits
   echo "mpc-operator soft nofile 65535" | sudo tee -a /etc/security/limits.conf
   echo "mpc-operator hard nofile 65535" | sudo tee -a /etc/security/limits.conf
   ```

## Bitcoin Node Setup

Each MPC node requires access to a Bitcoin node for monitoring the blockchain:

1. **Install Bitcoin Core**:
   ```bash
   # Add Bitcoin repository
   sudo add-apt-repository ppa:bitcoin/bitcoin
   sudo apt update

   # Install Bitcoin Core
   sudo apt install -y bitcoind
   ```

2. **Configure Bitcoin Node**:
   ```bash
   # Create Bitcoin data directory
   sudo mkdir -p /data/bitcoin
   sudo chown -R mpc-operator:mpc-operator /data/bitcoin

   # Create configuration file
   cat > /data/bitcoin/bitcoin.conf << EOF
   server=1
   daemon=1
   txindex=1
   rpcuser=bitcoinrpc
   rpcpassword=$(openssl rand -hex 32)
   rpcallowip=127.0.0.1
   zmqpubhashblock=tcp://127.0.0.1:28332
   zmqpubrawtx=tcp://127.0.0.1:28333
   EOF
   ```

3. **Start Bitcoin Node**:
   ```bash
   sudo systemctl enable bitcoind
   sudo systemctl start bitcoind
   ```

4. **Wait for Initial Sync**:
   ```bash
   # Monitor sync progress
   bitcoin-cli getblockchaininfo
   ```

## MPC Installation

1. **Install Dependencies**:
   ```bash
   sudo apt install -y build-essential pkg-config libssl-dev libzmq3-dev
   
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source $HOME/.cargo/env
   ```

2. **Install 0BTC Wire**:
   ```bash
   # Clone repository
   git clone https://github.com/0BTC/Wire.git
   cd Wire

   # Build the project
   cargo build --release
   
   # Install the binary
   sudo cp target/release/wire /usr/local/bin/
   ```

3. **Install MPC Components**:
   ```bash
   # Install MPC dependencies
   cd /opt
   sudo git clone https://github.com/0BTC/Wire-MPC.git
   cd Wire-MPC
   sudo chown -R mpc-operator:mpc-operator .
   
   # Build MPC components
   cargo build --release
   
   # Install MPC binaries
   sudo cp target/release/wire-mpc* /usr/local/bin/
   ```

## Operator Configuration

1. **Create MPC Configuration Directory**:
   ```bash
   sudo mkdir -p /etc/wire-mpc
   sudo chown -R mpc-operator:mpc-operator /etc/wire-mpc
   ```

2. **Create Operator Configuration File**:
   ```bash
   cat > /etc/wire-mpc/config.json << EOF
   {
     "operator_id": "operator-1",
     "bitcoin_rpc": {
       "url": "http://127.0.0.1:8332",
       "user": "bitcoinrpc",
       "password": "YOUR_RPC_PASSWORD"
     },
     "mpc": {
       "threshold": 2,
       "total_parties": 3,
       "communication": {
         "listen_address": "0.0.0.0:8334",
         "peers": [
           "operator-2.example.com:8334",
           "operator-3.example.com:8334"
         ]
       }
     },
     "database": {
       "path": "/data/wire-mpc/db"
     },
     "security": {
       "key_storage": {
         "encrypted_storage_path": "/data/wire-mpc/keys",
         "encryption_method": "AES-256-GCM"
       },
       "mfa": {
         "enabled": true,
         "method": "TOTP"
       }
     },
     "fee_reservoir": {
       "address_hash": "YOUR_FEE_RESERVOIR_ADDRESS_HASH",
       "consolidation_threshold": 10,
       "min_fee_amount": 1000
     }
   }
   EOF
   ```

3. **Create Data Directories**:
   ```bash
   sudo mkdir -p /data/wire-mpc/{db,keys,logs}
   sudo chown -R mpc-operator:mpc-operator /data/wire-mpc
   sudo chmod 700 /data/wire-mpc/keys
   ```

## Distributed Key Generation (DKG) Ceremony

The DKG ceremony must be performed with all MPC operators present:

1. **Generate TOTP Secret for MFA**:
   ```bash
   wire-mpc-keygen generate-totp
   ```
   - Each operator should scan the QR code with their authenticator app
   - Verify that all operators can generate valid TOTP codes

2. **Initialize MPC Operator**:
   ```bash
   wire-mpc-keygen init --config /etc/wire-mpc/config.json
   ```
   - Create a strong encryption password when prompted
   - Store this password securely (consider using a hardware security module)

3. **Coordinate DKG Ceremony**:
   - Schedule a time when all operators can participate simultaneously
   - Establish a secure communication channel for coordination
   - Each operator should run:
   ```bash
   wire-mpc-keygen dkg --config /etc/wire-mpc/config.json
   ```
   - Follow the on-screen instructions to complete the ceremony
   - Verify that all operators have received their key shares

4. **Verify Key Shares**:
   ```bash
   wire-mpc-keygen verify --config /etc/wire-mpc/config.json
   ```
   - All operators should verify that their key shares are valid
   - Test a simple signature to ensure the distributed key is working

5. **Backup Key Shares**:
   - Each operator should securely back up their key shares
   - Use offline storage (e.g., encrypted USB drives stored in secure locations)
   - Consider using paper backups stored in safe deposit boxes

## Service Configuration

1. **Create Systemd Service Files**:

   **Bitcoin Service**:
   ```bash
   sudo tee /etc/systemd/system/bitcoind.service > /dev/null << EOF
   [Unit]
   Description=Bitcoin daemon
   After=network.target

   [Service]
   User=mpc-operator
   Group=mpc-operator
   Type=forking
   ExecStart=/usr/bin/bitcoind -daemon -conf=/data/bitcoin/bitcoin.conf -datadir=/data/bitcoin
   ExecStop=/usr/bin/bitcoin-cli -conf=/data/bitcoin/bitcoin.conf stop
   Restart=always
   RestartSec=30
   TimeoutStartSec=300
   TimeoutStopSec=300

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

   **MPC Mint Attestation Service**:
   ```bash
   sudo tee /etc/systemd/system/wire-mpc-attestation.service > /dev/null << EOF
   [Unit]
   Description=0BTC Wire MPC Attestation Service
   After=network.target bitcoind.service
   Requires=bitcoind.service

   [Service]
   User=mpc-operator
   Group=mpc-operator
   WorkingDirectory=/opt/Wire-MPC
   ExecStart=/usr/local/bin/wire-mpc-attestation --config /etc/wire-mpc/config.json
   Restart=always
   RestartSec=30
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

   **MPC Burn Processing Service**:
   ```bash
   sudo tee /etc/systemd/system/wire-mpc-burn.service > /dev/null << EOF
   [Unit]
   Description=0BTC Wire MPC Burn Processing Service
   After=network.target bitcoind.service
   Requires=bitcoind.service

   [Service]
   User=mpc-operator
   Group=mpc-operator
   WorkingDirectory=/opt/Wire-MPC
   ExecStart=/usr/local/bin/wire-mpc-burn --config /etc/wire-mpc/config.json
   Restart=always
   RestartSec=30
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

   **MPC Fee Monitor Service**:
   ```bash
   sudo tee /etc/systemd/system/wire-mpc-fee-monitor.service > /dev/null << EOF
   [Unit]
   Description=0BTC Wire MPC Fee Monitor Service
   After=network.target bitcoind.service
   Requires=bitcoind.service

   [Service]
   User=mpc-operator
   Group=mpc-operator
   WorkingDirectory=/opt/Wire-MPC
   ExecStart=/usr/local/bin/wire-mpc-fee-monitor --config /etc/wire-mpc/config.json
   Restart=always
   RestartSec=30
   StandardOutput=journal
   StandardError=journal

   [Install]
   WantedBy=multi-user.target
   EOF
   ```

2. **Enable and Start Services**:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable bitcoind.service
   sudo systemctl enable wire-mpc-attestation.service
   sudo systemctl enable wire-mpc-burn.service
   sudo systemctl enable wire-mpc-fee-monitor.service
   
   sudo systemctl start bitcoind.service
   sudo systemctl start wire-mpc-attestation.service
   sudo systemctl start wire-mpc-burn.service
   sudo systemctl start wire-mpc-fee-monitor.service
   ```

3. **Verify Services are Running**:
   ```bash
   sudo systemctl status bitcoind.service
   sudo systemctl status wire-mpc-attestation.service
   sudo systemctl status wire-mpc-burn.service
   sudo systemctl status wire-mpc-fee-monitor.service
   ```

## Monitoring and Alerting

1. **Install Monitoring Tools**:
   ```bash
   sudo apt install -y prometheus node-exporter prometheus-alertmanager grafana
   ```

2. **Configure Prometheus**:
   ```bash
   sudo tee /etc/prometheus/prometheus.yml > /dev/null << EOF
   global:
     scrape_interval: 15s
     evaluation_interval: 15s

   alerting:
     alertmanagers:
     - static_configs:
       - targets: ['localhost:9093']

   rule_files:
     - "/etc/prometheus/rules/*.yml"

   scrape_configs:
     - job_name: 'prometheus'
       static_configs:
       - targets: ['localhost:9090']

     - job_name: 'node'
       static_configs:
       - targets: ['localhost:9100']

     - job_name: 'wire-mpc'
       static_configs:
       - targets: ['localhost:9101']
   EOF
   ```

3. **Configure Alert Rules**:
   ```bash
   sudo mkdir -p /etc/prometheus/rules
   sudo tee /etc/prometheus/rules/wire-mpc.yml > /dev/null << EOF
   groups:
   - name: wire-mpc
     rules:
     - alert: MPCServiceDown
       expr: up{job="wire-mpc"} == 0
       for: 5m
       labels:
         severity: critical
       annotations:
         summary: "MPC service down"
         description: "MPC service has been down for more than 5 minutes."

     - alert: BitcoinNodeDown
       expr: up{job="node"} == 0
       for: 5m
       labels:
         severity: critical
       annotations:
         summary: "Bitcoin node down"
         description: "Bitcoin node has been down for more than 5 minutes."

     - alert: DiskSpaceRunningLow
       expr: node_filesystem_avail_bytes{mountpoint="/data"} / node_filesystem_size_bytes{mountpoint="/data"} * 100 < 10
       for: 5m
       labels:
         severity: warning
       annotations:
         summary: "Low disk space"
         description: "Server has less than 10% free disk space."
   EOF
   ```

4. **Configure Grafana Dashboard**:
   - Access Grafana at http://your-server-ip:3000
   - Default login: admin/admin
   - Add Prometheus as a data source
   - Import dashboards for Node Exporter and custom MPC metrics

5. **Set Up Email Alerts**:
   ```bash
   sudo tee /etc/alertmanager/alertmanager.yml > /dev/null << EOF
   global:
     smtp_smarthost: 'smtp.example.com:587'
     smtp_from: 'alertmanager@example.com'
     smtp_auth_username: 'alertmanager@example.com'
     smtp_auth_password: 'your-password'

   route:
     group_by: ['alertname', 'job']
     group_wait: 30s
     group_interval: 5m
     repeat_interval: 4h
     receiver: 'team-email'

   receivers:
   - name: 'team-email'
     email_configs:
     - to: 'team@example.com'
   EOF
   ```

6. **Restart Monitoring Services**:
   ```bash
   sudo systemctl restart prometheus
   sudo systemctl restart alertmanager
   sudo systemctl restart grafana-server
   ```

## Backup Procedures

1. **Database Backup**:
   ```bash
   # Create backup script
   cat > /home/mpc-operator/backup.sh << EOF
   #!/bin/bash
   TIMESTAMP=\$(date +%Y%m%d%H%M%S)
   BACKUP_DIR=/data/backups/\$TIMESTAMP
   
   # Create backup directory
   mkdir -p \$BACKUP_DIR
   
   # Stop services
   sudo systemctl stop wire-mpc-attestation.service
   sudo systemctl stop wire-mpc-burn.service
   sudo systemctl stop wire-mpc-fee-monitor.service
   
   # Backup database
   cp -r /data/wire-mpc/db \$BACKUP_DIR/
   
   # Backup configuration
   cp -r /etc/wire-mpc \$BACKUP_DIR/
   
   # Encrypt backup
   tar -czf \$BACKUP_DIR.tar.gz \$BACKUP_DIR
   openssl enc -aes-256-cbc -salt -in \$BACKUP_DIR.tar.gz -out \$BACKUP_DIR.tar.gz.enc
   rm \$BACKUP_DIR.tar.gz
   
   # Start services
   sudo systemctl start wire-mpc-attestation.service
   sudo systemctl start wire-mpc-burn.service
   sudo systemctl start wire-mpc-fee-monitor.service
   
   # Remove unencrypted backup
   rm -rf \$BACKUP_DIR
   
   # Keep only last 7 backups
   ls -t /data/backups/*.enc | tail -n +8 | xargs rm -f
   EOF
   
   # Make script executable
   chmod +x /home/mpc-operator/backup.sh
   
   # Create backup directory
   sudo mkdir -p /data/backups
   sudo chown -R mpc-operator:mpc-operator /data/backups
   
   # Set up daily cron job
   echo "0 2 * * * /home/mpc-operator/backup.sh" | crontab -
   ```

2. **Offsite Backup**:
   ```bash
   # Install rclone for cloud backups
   sudo apt install -y rclone
   
   # Configure rclone (follow interactive prompts)
   rclone config
   
   # Create offsite backup script
   cat > /home/mpc-operator/offsite-backup.sh << EOF
   #!/bin/bash
   # Sync local backups to cloud storage
   rclone sync /data/backups remote:wire-mpc-backups
   EOF
   
   # Make script executable
   chmod +x /home/mpc-operator/offsite-backup.sh
   
   # Set up daily cron job
   echo "0 3 * * * /home/mpc-operator/offsite-backup.sh" | crontab -
   ```

## Maintenance

1. **Regular System Updates**:
   ```bash
   # Create update script
   cat > /home/mpc-operator/update.sh << EOF
   #!/bin/bash
   # Update system packages
   sudo apt update && sudo apt upgrade -y
   
   # Update Wire MPC software
   cd /opt/Wire-MPC
   git pull
   cargo build --release
   sudo cp target/release/wire-mpc* /usr/local/bin/
   
   # Restart services
   sudo systemctl restart wire-mpc-attestation.service
   sudo systemctl restart wire-mpc-burn.service
   sudo systemctl restart wire-mpc-fee-monitor.service
   EOF
   
   # Make script executable
   chmod +x /home/mpc-operator/update.sh
   ```

2. **Key Rotation Procedure**:
   - Schedule key rotation at least once every 6 months
   - Coordinate with all MPC operators to perform a new DKG ceremony
   - Ensure all operators have backed up their new key shares
   - Verify the new distributed key is working correctly

3. **Log Rotation**:
   ```bash
   sudo tee /etc/logrotate.d/wire-mpc > /dev/null << EOF
   /data/wire-mpc/logs/*.log {
     daily
     missingok
     rotate 14
     compress
     delaycompress
     notifempty
     create 0640 mpc-operator mpc-operator
   }
   EOF
   ```

## Troubleshooting

1. **Service Failure**:
   ```bash
   # Check service status
   sudo systemctl status wire-mpc-attestation.service
   
   # View service logs
   sudo journalctl -u wire-mpc-attestation.service -n 100
   
   # Restart service
   sudo systemctl restart wire-mpc-attestation.service
   ```

2. **Bitcoin Node Issues**:
   ```bash
   # Check Bitcoin node status
   bitcoin-cli getblockchaininfo
   
   # Restart Bitcoin node
   sudo systemctl restart bitcoind
   
   # Check Bitcoin logs
   tail -n 100 /data/bitcoin/debug.log
   ```

3. **MPC Communication Issues**:
   ```bash
   # Check network connectivity
   ping operator-2.example.com
   
   # Test MPC port connectivity
   nc -zv operator-2.example.com 8334
   
   # Check firewall rules
   sudo ufw status
   ```

4. **Database Corruption**:
   ```bash
   # Stop services
   sudo systemctl stop wire-mpc-attestation.service
   sudo systemctl stop wire-mpc-burn.service
   sudo systemctl stop wire-mpc-fee-monitor.service
   
   # Restore from backup
   # Replace TIMESTAMP with the actual backup timestamp
   mkdir -p /tmp/restore
   openssl enc -d -aes-256-cbc -in /data/backups/TIMESTAMP.tar.gz.enc -out /tmp/restore.tar.gz
   tar -xzf /tmp/restore.tar.gz -C /tmp/restore
   
   # Replace corrupted database
   rm -rf /data/wire-mpc/db
   cp -r /tmp/restore/TIMESTAMP/db /data/wire-mpc/
   
   # Clean up
   rm -rf /tmp/restore
   
   # Start services
   sudo systemctl start wire-mpc-attestation.service
   sudo systemctl start wire-mpc-burn.service
   sudo systemctl start wire-mpc-fee-monitor.service
   ```

## Disaster Recovery

1. **Complete Server Failure**:
   - Provision a new server following the Server Preparation steps
   - Install Bitcoin Core and MPC components
   - Restore configuration and database from backups
   - Restore key shares from secure backup
   - Verify all services are functioning correctly

2. **Key Share Compromise**:
   - Immediately notify all other MPC operators
   - Temporarily suspend all MPC operations
   - Conduct a security investigation to determine the extent of the compromise
   - Perform a new DKG ceremony with all operators
   - Update all affected configurations and services
   - Resume operations with the new key shares

3. **Bitcoin Fork Handling**:
   - Monitor Bitcoin network for potential forks
   - If a fork is detected, pause all MPC operations
   - Wait for confirmation that the fork has been resolved
   - Adjust confirmation thresholds if necessary
   - Resume operations only when the Bitcoin network is stable

4. **Emergency Contact Procedure**:
   - Maintain an up-to-date emergency contact list for all MPC operators
   - Establish a secure communication channel for emergency coordination
   - Define escalation procedures for different types of emergencies
   - Conduct regular emergency drills to ensure all operators are familiar with the procedures

---

This guide provides a comprehensive framework for deploying and operating MPC nodes for the 0BTC Wire system. Each organization should adapt these procedures to their specific security requirements and operational environment.
