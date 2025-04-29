#!/bin/bash
# 0BTC Wire Demo Script
# This script demonstrates the core functionality of the 0BTC Wire system

# Set up colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Create directories for outputs
mkdir -p examples/cli/outputs/proofs

echo -e "${BLUE}0BTC Wire Demo${NC}"
echo -e "${BLUE}==============${NC}"
echo

# Step 1: Generate a keypair
echo -e "${GREEN}Step 1: Generating a keypair${NC}"
cargo run -- key-gen --output examples/cli/outputs/keypair.json
echo

# Step 2: Generate multiple proofs
echo -e "${GREEN}Step 2: Generating multiple proofs${NC}"
cargo run --example cli/cli_demo -- generate --count 4 --output examples/cli/outputs/proofs --parallel
echo

# Step 3: Verify proofs individually
echo -e "${GREEN}Step 3: Verifying proofs individually${NC}"
cargo run --example cli/cli_demo -- verify --input examples/cli/outputs/proofs --parallel
echo

# Step 4: Aggregate proofs
echo -e "${GREEN}Step 4: Aggregating proofs${NC}"
cargo run --example cli/cli_demo -- aggregate --input examples/cli/outputs/proofs --output examples/cli/outputs/aggregated_proof.json --batch-size 4
echo

# Step 5: Verify aggregated proof
echo -e "${GREEN}Step 5: Verifying aggregated proof${NC}"
cargo run --example cli/cli_demo -- verify --input examples/cli/outputs --recursive
echo

# Step 6: Run basic hash example
echo -e "${GREEN}Step 6: Running basic hash example${NC}"
cargo run --example basic/hash_example
echo

# Step 7: Run basic transfer example
echo -e "${GREEN}Step 7: Running basic transfer example${NC}"
cargo run --example basic/simple_transfer
echo

echo -e "${BLUE}Demo completed successfully!${NC}"
echo -e "${BLUE}To run the WASM demo, follow these steps:${NC}"
echo -e "1. Build the WASM module: ${GREEN}wasm-pack build --target web${NC}"
echo -e "2. Start a local web server: ${GREEN}python -m http.server${NC}"
echo -e "3. Open your browser and navigate to: ${GREEN}http://localhost:8000/examples/wasm/${NC}"
