# 0BTC Wire Performance Benchmark Suite

This standalone benchmark suite measures the performance of key operations in the 0BTC Wire zero-knowledge proof system.

## Overview

The benchmark suite tests the following operations:

1. **Simple Addition Circuit** - A basic circuit that adds two numbers
2. **Hash Operations** - Measures the performance of Poseidon hash operations in a circuit
3. **Transfer Circuit** - A simplified version of the core transfer circuit
4. **Recursive Proof Aggregation** - Estimated performance for recursive proof verification

## Running the Benchmarks

```bash
# From the benchmark directory
cargo run --release

# From the main project directory
cd benchmark && cargo run --release
```

## Benchmark Results

The benchmark outputs performance metrics including:

- Gate count (circuit complexity)
- Circuit build time
- Proof generation time
- Proof verification time
- Throughput (proofs per second)

## Integration with Main Project

This standalone benchmark provides a simplified way to measure core performance without dependencies on the main codebase. For more comprehensive benchmarks, see the integration tests in the main project.

## Performance Optimization

For strategies on optimizing ZK circuit performance, refer to the [Performance Optimization Guide](../docs/performance_optimization.md).
