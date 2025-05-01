Okay, here is the developer task list formatted as a checklist:

---

## 0BTC Wire - Developer To-Do List (MPC Integration Phase)

**MPC Implementation & Integration (External Library Strategy)**

*   [x] **Task 1: Select MPC Library**
    *   [x] Research Threshold Ed25519 signature libraries (Rust, audited, open-source).
    *   [x] Determine if Threshold ECDSA is needed for BTC withdrawals (or if multisig suffices). Select library if needed.
    *   [x] Document the chosen library/libraries and the rationale.
*   [x] **Task 2: Design MPC Operator Tooling**
    *   [x] Define architecture (separate service? CLI commands?).
    *   [x] Specify secure communication protocols between operator nodes.
    *   [x] Document interaction points with BTC chain monitoring and the 0BTC Wire system.
    *   [x] Create architecture diagram and design document.
*   [x] **Task 3: Implement MPC Operator Tooling Core**
    *   [x] Build the Rust application/CLI extension based on the design.
    *   [x] Integrate the selected MPC library (from Task 1).
    *   [x] Implement Distributed Key Generation (DKG) ceremony logic.
    *   [x] Implement Threshold Signing ceremony logic (Ed25519 required, ECDSA optional).
*   [x] **Task 4: Implement Mint Attestation Workflow**
    *   [x] Integrate logic to receive verified BTC deposit info.
    *   [x] Implement the process to initiate and complete the threshold Ed25519 signing ceremony for mint attestations using the MPC tooling.
    *   [x] Implement a secure way to provide the signed attestation to the user/system.
*   [x] **Task 5: Implement Burn Processing Workflow**
    *   [x] Integrate logic to receive verified `WrappedAssetBurnCircuit` proofs.
    *   [x] Implement extraction of withdrawal details from burn proofs.
    *   [x] Implement the process to create and sign BTC withdrawal transactions using the MPC tooling (Threshold ECDSA or triggering external multisig).
*   [x] **Task 6: Implement Fee Consolidation Workflow**
    *   [x] Implement monitoring of the `fee_reservoir_address`.
    *   [x] Implement the generation of a `TransferCircuit` proof for consolidating fee UTXOs.
    *   [x] Integrate with MPC tooling to get the required threshold signature for the fee consolidation transfer.
    *   [x] Ensure the simulation logic in `scripts/mpc/fee_monitor.py` is replaced/represented by this actual implementation.

**CLI Enhancements**

*   [x] **Task 7 (Optional): Create MPC Operator CLI Commands**
    *   [x] Add an `mpc` subcommand to the `wire` CLI.
    *   [x] Implement commands like `generate-attestation`, `process-burn`, `consolidate-fees`.
    *   [x] Ensure commands integrate securely with the MPC tooling and have proper authorization.

**Documentation**

*   [x] **Task 8: Create MPC Documentation**
    *   [x] Write `docs/mpc_interaction.md` detailing user mint/burn flows with MPC interaction.
    *   [x] Write `docs/mpc_key_management.md` detailing key management using the chosen MPC library/tooling.
*   [x] **Task 9: Update Existing Documentation**
    *   [x] Update `README.md`, `USER_GUIDE.md`, `INSTRUCTIONS.md` to restrict MPC ops, clarify Python script status (simulations), update keygen instructions, and link to new MPC docs.
    *   [x] Update or create `scripts/mpc/README.md` to label Python scripts as non-production simulations.

**Codebase Cleanup**

*   [x] **Task 10: Resolve Disabled Utility Modules**
    *   [x] Investigate commented-out re-exports (`recursive_prover`, `memory_efficient`, `benchmarking`) in `src/utils/mod.rs`.
    *   [x] Re-enable or remove code/comments as appropriate.
    *   [x] Update `docs/implementation_status.md`.

**Testing & Security**

*   [x] **Task 11: Implement MPC Integration Tests**
    *   [x] Add tests covering the full mint-transfer-burn lifecycle, including interactions (or simulated interactions) with the MPC tooling.
    *   [x] Test fee consolidation workflow.
*   [x] **Task 12: Security Review**
    *   [x] Review the security design and implementation of the MPC operator tooling and communication channels.

---

## Next Steps

1. **Performance Optimization**
   - Profile the MPC operations to identify bottlenecks
   - Optimize ceremony flows for better performance
   - Implement caching and other optimizations where appropriate

2. **Deployment Preparation**
   - Create deployment documentation for MPC operators
   - Prepare test environments for operator training
   - Create backup and recovery procedures

3. **Production Readiness**
   - Conduct a final review of all components
   - Prepare release notes and documentation
   - Create a deployment plan for production