//! Audit-specific test suite for the 0BTC Wire project
//!
//! This module is the entry point for the audit test suite.
//! Run with: cargo test --test audit_tests --features audit-tests

#[cfg(feature = "audit-tests")]
mod audit;

#[cfg(feature = "audit-tests")]
#[test]
fn audit_test_suite_entry_point() {
    println!("Running audit test suite...");
    // This test is just a placeholder to ensure the test suite is properly registered
    assert!(true);
}
