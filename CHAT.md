# 0BTC Wire - Developer Task List for Production Readiness

This task list outlines key areas for review, hardening, and implementation based on the current codebase structure and potential weaknesses identified. Addressing these items will improve the system's robustness and prepare it for external auditing.

**I. Circuit Logic & Constraints:**

*   **[✓] Review Value Conservation:**
    *   **Task:** Meticulously review constraints in `TransferCircuit`, AMM circuits (`SwapCircuit`, `AddLiquidityCircuit`, `RemoveLiquidityCircuit`), and Stablecoin circuits (`StablecoinMintCircuit`, `StablecoinRedeemCircuit`) to ensure the sum of output values (+ fees) strictly equals the sum of input values.
    *   **Action:** Add explicit assertions (`builder.assert_equal`) for value balance checks.
*   **[✓] Verify Ownership Checks:**
    *   **Task:** Ensure signature verification (`verify_message_signature` usage) is correctly implemented in all circuits that spend UTXOs (`TransferCircuit`, `WrappedAssetBurnCircuit`, `NativeAssetBurnCircuit`, `LNBurnCircuit`, `StablecoinMintCircuit`, `StablecoinRedeemCircuit`, AMM circuits).
    *   **Action:** Confirm the correct message is being signed and verified against the appropriate public key. Double-check domain separation usage in signature hashing.
*   **[✓] Harden Nullifier Logic:**
    *   **Task:** Review nullifier calculation (`compute_utxo_nullifier_target`, `calculate_and_register_nullifier`) in all spending circuits.
    *   **Action:** Ensure nullifiers are unique per spent UTXO and are correctly registered as public inputs to prevent double-spends. Verify domain separation.
*   **[✓] Validate State Transitions (AMM & Stablecoin):**
    *   **Task:** Review state transition logic in AMM (`SwapCircuit`, `AddLiquidityCircuit`, `RemoveLiquidityCircuit`) and Stablecoin (`StablecoinMintCircuit`, `StablecoinRedeemCircuit`) circuits.
    *   **Action:** Audit state update logic (reserves, LP shares, collateral, minted supply) and add explicit assertions. Confirm formulas (CPMM, bonding curve, collateral ratio) are correctly translated into constraints.
*   **[✓] Verify Asset ID Handling:**
    *   **Task:** Ensure all circuits correctly handle and enforce `asset_id`.
    *   **Action:** Verify `TransferCircuit` prevents asset type changes. Check mint/burn circuits use the correct asset IDs (wBTC, zUSD, native). Add explicit equality checks for `asset_id` where necessary.
*   **[✓] Implement/Verify Virtual CPMM Circuits:**
    *   **Task:** If Virtual CPMM is intended for this phase, implement `BuyTokenCircuit`, `SellTokenCircuit`, and `TransitionCircuit`. If integrated differently, document and review that implementation.
    *   **Action:** Write circuits enforcing bonding curve math and transition logic. Add corresponding tests.
*   **[✓] Define Collateral Locking Mechanism:**
    *   **Task:** Clearly define and document how wBTC collateral is "locked" in `StablecoinMintCircuit` (e.g., specific UTXO type, transfer to MPC pool).
    *   **Action:** Ensure the chosen mechanism is correctly and securely implemented in the circuit constraints and corresponding redemption logic (`StablecoinRedeemCircuit`).

**II. Arithmetic & Gadgets:**

*   **[✓] Implement Robust Arithmetic:**
    *   **Task:** Review all complex arithmetic in circuits (especially AMM and Stablecoin). Replace any placeholder logic (e.g., for division, square roots) with robust, verified gadget implementations.
    *   **Action:** Implement or integrate secure fixed-point or scaled-integer arithmetic gadgets. Add thorough unit tests for these gadgets covering edge cases. Check `src/gadgets/arithmetic.rs`.
*   **[✓] Review Gadget Usage:**
    *   **Task:** Ensure all cryptographic gadgets (`src/gadgets/`) are used correctly according to their specifications (e.g., correct inputs, domain separation for hashes).
    *   **Action:** Audit calls to hash, signature, merkle, and nullifier gadgets within all circuits.

**III. MPC System:**

*   **[ ] Secure Key Share Storage:**
    *   **Task:** Review `src/mpc/secure_storage.rs`. Ensure key shares are encrypted at rest using strong, standard algorithms (e.g., AES-GCM) and proper key derivation (e.g., PBKDF2).
    *   **Action:** Harden implementation if necessary. Document backup and recovery procedures clearly for operators.
*   **[ ] Verify Ceremony Robustness:**
    *   **Task:** Review DKG and signing ceremony logic in `src/mpc/ceremonies.rs`.
    *   **Action:** Add checks for participant timeouts, invalid messages, and potential adversarial behavior. Implement recovery mechanisms for failed ceremonies.
*   **[ ] Add MPC Audit Logging:**
    *   **Task:** Implement comprehensive, secure logging for all critical MPC actions (ceremony participation, key generation, signing, attestation generation, withdrawals).
    *   **Action:** Add logging points in `src/mpc/` modules. Ensure logs don't contain sensitive data.
*   **[ ] Review Communication Security:**
    *   **Task:** Verify the TLS implementation for node communication (`src/mpc/communication.rs`).
    *   **Action:** Ensure certificate validation is strict. Implement replay protection (e.g., nonces, timestamps) and potentially rate limiting on the MPC API endpoints.
*   **[ ] Harden Attestation/Withdrawal Logic:**
    *   **Task:** Review MPC logic for LN bridge (`src/mpc/lightning.rs`), Stablecoin oracle/redemption (`src/mpc/stablecoin.rs`), and BTC bridging (`src/mpc/attestation.rs`, `src/mpc/burn.rs`).
    *   **Action:** Ensure external data (LN payments, prices, BTC blocks) is validated. Implement robust nonce/ID checks for attestations to prevent replays. Verify signature generation logic. Add thorough error handling.

**IV. Testing & Verification:**

*   **[✓] Enhance Circuit Test Coverage:**
    *   **Task:** Write specific tests for edge cases (zero amounts, max values, empty inputs/outputs) in all circuits.
    *   **Action:** Expand test files in `tests/` (e.g., `transfer_circuit_tests.rs`, etc.) and `tests/audit/edge_cases.rs`.
*   **[✓] Add Negative Tests:**
    *   **Task:** Create tests that *expect* proof generation or verification to fail due to violated constraints (e.g., invalid signature, insufficient funds, conservation violation).
    *   **Action:** Add tests asserting specific `WireError` types are returned.
*   **[✓] Verify Fuzz Test Coverage:**
    *   **Task:** Review fuzz tests (`tests/audit/fuzz.rs`, `enhanced_fuzz.rs`) and ensure they cover critical components and potential attack vectors identified in security reviews.
    *   **Action:** Expand fuzz targets if necessary.
*   **[✓] Update Audit Test Vectors:**
    *   **Task:** Ensure `generate_audit_test_vectors.rs` produces deterministic vectors covering all major valid and invalid scenarios based on the final circuit implementations.
    *   **Action:** Update generation logic and `docs/audit_test_vectors.md`.

**V. Code Quality & Robustness:**

*   **[✓] Eliminate Panics:**
    *   **Task:** Search the codebase for `.unwrap()` and `.expect()` calls.
    *   **Action:** Replace panics with proper error handling using the `WireResult` and error types defined in `src/errors.rs`.
*   **[✓] Review Error Handling & Sanitization:**
    *   **Task:** Ensure errors are propagated correctly and that `sanitize_error_message` effectively prevents leaking sensitive internal state.
    *   **Action:** Audit error paths and external-facing error messages.
*   **[✓] Improve Input Validation:**
    *   **Task:** Review validation logic in `src/cli/validation.rs` and `src/wasm/validation.rs`.
    *   **Action:** Ensure all user inputs (CLI args, WASM params, API inputs) are strictly validated. Add missing checks, tighten existing ones (e.g., length limits, format checks).
*   **[ ] Code Cleanup:**
    *   **Task:** Remove dead code, add clarifying comments, ensure consistent formatting (`cargo fmt`), and address clippy warnings (`cargo clippy`).
    *   **Action:** Run linters, formatters, and manually review code for clarity and maintainability.
*   **[ ] Update Dependencies:**
    *   **Task:** Check for updates to dependencies, especially cryptographic libraries (Plonky2, ed25519-dalek) and apply security patches.
    *   **Action:** Run `cargo update`, test thoroughly after updates.

**VI. Documentation:**

*   **[ ] Document AMM State Management:**
    *   **Task:** Update relevant documentation (`docs/`) to explain the `PoolStateUTXO` mechanism and the challenges/solutions for user interaction (e.g., needing off-chain indexers).
*   **[ ] Document Collateral Locking:**
    *   **Task:** Clearly document the chosen mechanism for locking stablecoin collateral in `docs/` and ensure it aligns with the circuit implementation.
*   **[ ] Final Documentation Review:**
    *   **Task:** Ensure all guides (`USER_GUIDE.md`, `installation_guide.md`, etc.) and technical docs (`mpc_*.md`, `api_reference.md`) are accurate and reflect the final implementation.

---

Completing these internal tasks will significantly strengthen the codebase and streamline the external audit process. Prioritize tasks related to circuit constraints and MPC security.