#!/bin/bash
# Demo script for the 0BTC Wire CLI

# Set up colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}0BTC Wire CLI Demo${NC}"
echo "This script demonstrates the basic functionality of the 0BTC Wire CLI."
echo

# Step 1: Generate a keypair
echo -e "${GREEN}Step 1: Generating a keypair${NC}"
cargo run -- key-gen --output examples/keypair.json
echo

# Step 2: Prove a wrapped asset mint circuit
echo -e "${GREEN}Step 2: Proving a wrapped asset mint circuit${NC}"
cargo run -- prove --circuit wrapped_asset_mint --input examples/inputs/wrapped_asset_mint.json --output examples/proofs/wrapped_asset_mint_proof.json
echo

# Step 3: Verify the proof
echo -e "${GREEN}Step 3: Verifying the proof${NC}"
cargo run -- verify --circuit wrapped_asset_mint --proof examples/proofs/wrapped_asset_mint_proof.json
echo

# Step 4: Prove a transfer circuit
echo -e "${GREEN}Step 4: Proving a transfer circuit${NC}"
cargo run -- prove --circuit transfer --input examples/inputs/transfer.json --output examples/proofs/transfer_proof.json
echo

# Step 5: Verify the transfer proof
echo -e "${GREEN}Step 5: Verifying the transfer proof${NC}"
cargo run -- verify --circuit transfer --proof examples/proofs/transfer_proof.json
echo

echo -e "${BLUE}Demo completed successfully!${NC}"
