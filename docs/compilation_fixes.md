# Wire Library Compilation Fixes

This document outlines the changes made to fix compilation issues in the Wire library.

## Summary of Issues Fixed

### 1. Missing Dependencies

- Added the missing `base32` crate dependency to `Cargo.toml`

### 2. Ownership/Borrowing Issues

Fixed ownership issues in the following MPC modules where `db_path` was moved into a struct field but then borrowed later:

- `src/mpc/attestation.rs`: Fixed by cloning `db_path` before storing it in the `AttestationManager` struct
- `src/mpc/burn.rs`: Fixed by cloning `db_path` before storing it in the `BurnManager` struct
- `src/mpc/fee.rs`: Fixed by cloning `db_path` before storing it in the `FeeManager` struct
- `src/mpc/key_rotation.rs`: Fixed by cloning `db_path` before storing it in the `KeyRotationManager` struct
- `src/mpc/bitcoin_security.rs`: Fixed by cloning `db_path` before storing it in the `BitcoinSecurityManager` struct

## Additional Recommendations

### 1. Unstable Features

If there are any unstable features being used in the library (e.g., `#![feature(specialization)]`), consider one of the following approaches:

- Use the nightly Rust compiler for development
- Refactor the code to avoid using unstable features
- Add a feature flag to conditionally include the unstable features

### 2. Type Mismatches and Other Errors

For any remaining type mismatches or other Rust-specific errors:

- Review error messages carefully to identify the specific issues
- Consider using more explicit type annotations where needed
- Ensure that all trait implementations are complete

### 3. Testing Strategy

After making these fixes:

- Run `cargo check` to verify that the code compiles without errors
- Run `cargo test` to ensure that all tests pass
- Consider adding more unit tests to verify the fixed functionality

### 4. Version Tagging

Once the library is stable:

- Create version tags (e.g., `v0.1.0`) to allow for more reliable dependency specification
- Consider using semantic versioning to indicate breaking changes

## Implementation Details

### Fixed Ownership Issues

The primary issue was that `db_path` was being moved into struct fields but then borrowed later in the code. This was fixed by cloning the `db_path` string before storing it in the structs:

```rust
// Before
let manager = Self {
    mpc_core,
    db_path,  // db_path moved here
    // ...
};

// After
let manager = Self {
    mpc_core,
    db_path: db_path.clone(),  // db_path cloned, original still available
    // ...
};
```

This allows the original `db_path` to still be available for use in subsequent code, such as checking if the file exists:

```rust
if Path::new(&db_path).exists() {
    // ...
}
```

### Added Dependencies

Added the missing `base32` dependency to `Cargo.toml`:

```toml
base32 = "0.4.0"
```

## Next Steps

1. Verify that these fixes resolve the compilation issues
2. Address any remaining errors that may be uncovered during compilation
3. Run the test suite to ensure functionality is preserved
4. Consider a code review to identify any other potential issues
