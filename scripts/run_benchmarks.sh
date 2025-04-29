#!/bin/bash
# Script to run comprehensive benchmarks for the 0BTC Wire project
# This script runs the benchmarks and generates performance reports

set -e

# Print header
echo "=================================================="
echo "0BTC Wire Performance Benchmarking Suite"
echo "=================================================="
echo

# Create output directory
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
OUTPUT_DIR="benchmark_results_${TIMESTAMP}"
mkdir -p "${OUTPUT_DIR}"
echo "Creating output directory: ${OUTPUT_DIR}"

# Function to run a specific benchmark
run_benchmark() {
    local name=$1
    local description=$2
    local command=$3
    
    echo
    echo "Running benchmark: ${name}"
    echo "${description}"
    echo "------------------------------------------------"
    
    # Run the benchmark and capture output
    ${command} | tee "${OUTPUT_DIR}/${name}.log"
    
    echo "Benchmark complete. Results saved to ${OUTPUT_DIR}/${name}.log"
    echo
}

# Run integration benchmarks
run_benchmark "integration" "Integration benchmarks for all components" \
    "cargo test --test integration::benchmarks -- --nocapture"

# Run standalone benchmark
run_benchmark "standalone" "Standalone benchmark for core operations" \
    "cd benchmark && cargo run --release"

# Copy CSV results to output directory
find . -name "benchmark_results_*.csv" -newer "${OUTPUT_DIR}" -exec cp {} "${OUTPUT_DIR}/" \;

# Generate summary report
echo "Generating summary report..."
cat > "${OUTPUT_DIR}/summary.md" << EOF
# 0BTC Wire Benchmark Summary

Date: $(date)

## Overview

This report contains the results of performance benchmarks for the 0BTC Wire project.

## Benchmark Results

The following benchmarks were run:

1. Integration Benchmarks
   - Hash Function Benchmarks
   - Signature Verification Benchmarks
   - Parallel Processing Benchmarks
   - Recursive Proof Aggregation Benchmarks
   - Circuit Benchmarks

2. Standalone Benchmark
   - Simple Addition Circuit
   - Hash Operations
   - Transfer Circuit
   - Recursive Proof Aggregation (estimated)

## Files

- \`integration.log\`: Full output from the integration benchmarks
- \`standalone.log\`: Full output from the standalone benchmark
- \`benchmark_results_*.csv\`: CSV files containing detailed benchmark results

## Performance Analysis

### Integration vs. Standalone Results

Compare the integration and standalone benchmark results to identify any discrepancies or performance issues.

### Key Metrics

- **Gate Count**: Measure of circuit complexity
- **Proof Generation Time**: Time to generate proofs
- **Proof Verification Time**: Time to verify proofs
- **Throughput**: Proofs per second

## Next Steps

1. Analyze the benchmark results to identify performance bottlenecks
2. Implement optimizations for the identified bottlenecks
3. Re-run benchmarks to measure the impact of optimizations
4. Update the performance optimization documentation

## How to Run Benchmarks

\`\`\`bash
./scripts/run_benchmarks.sh
\`\`\`
EOF

echo "Summary report generated: ${OUTPUT_DIR}/summary.md"

# Extract key metrics from the standalone benchmark
echo "Extracting key metrics from standalone benchmark..."
grep -A 15 "Benchmark Summary" "${OUTPUT_DIR}/standalone.log" > "${OUTPUT_DIR}/standalone_summary.txt"

# Create a symlink to the latest results
ln -sf "${OUTPUT_DIR}" benchmark_results_latest

echo
echo "=================================================="
echo "Benchmarking complete!"
echo "Results saved to: ${OUTPUT_DIR}"
echo "A symlink to the latest results was created: benchmark_results_latest"
echo "=================================================="
