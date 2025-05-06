## Wire Developer TODO List - Feature Expansion

This list outlines the development tasks required to implement the newly specified features into the Wire core library (Rust circuits, gadgets, core types, WASM bindings) and potentially associated components like the CLI.

**I. AMM Enhancements:**

*   **[✓] Implement LP Fees:**
    *   **Task:** Modify `SwapCircuit` logic to calculate and allocate swap fees (e.g., 0.3%) to liquidity providers.
    *   **Action:** Adjust reserve update calculations to implicitly reflect fee accrual to LPs (e.g., increase `k` slightly or adjust output amounts). Ensure fee calculations are integrated correctly within the fixed-point arithmetic. Add tests specifically for fee calculation accuracy.
*   **[✓] Implement Protocol Fees (Optional but Specified):**
    *   **Task:** Add logic to `SwapCircuit` to divert a fraction of the LP fee to a designated protocol address (`fee_reservoir_address_hash`).
    *   **Action:** Introduce a configurable protocol fee percentage parameter (potentially a circuit constant or public input). Modify swap calculations to subtract the protocol fee *before* calculating the LP share or output amounts. Ensure this fee is correctly directed (e.g., implicitly added to a protocol-controlled balance or explicitly sent via a small fee UTXO - the former is simpler in UTXO models). Update tests.
*   **[✓] Update AMM Tests:**
    *   **Task:** Enhance existing AMM circuit tests (`add_liquidity`, `remove_liquidity`, `swap`) to verify correct fee calculations (LP and protocol fees).
    *   **Action:** Add test cases with various swap sizes and fee scenarios. Assert correct reserve updates and output amounts considering fees.

**II. Stablecoin V2 (Protocol Fees & "zero" Collateral):**

*   **(Prerequisite) Define "zero" Token:**
    *   **[✓] Task:** Define "zero" as a Native Asset within the Wire system.
    *   **[✓] Action:** Ensure `NativeAssetCreateCircuit` can be used (or is already used) to establish the "zero" token with its 1B initial supply. Determine how its Asset ID is represented.
*   **[✓] Design & Implement Price Oracles (MPC Task Primarily, but affects Circuit):**
    *   **Task:** Design the mechanism for MPCs ("Party") to fetch, agree upon, and attest to **both** `wBTC/USD` and `zero/USD` (or `zero/wBTC`) prices reliably.
    *   **Action:** Specify the format for a *new* Price Attestation structure that includes *both* prices and potentially the price source/timestamp for each. This new attestation format will be input to the V2 stablecoin circuits.
*   **[✓] Refactor `StablecoinMintCircuit` (`StablecoinMintV2Circuit`):**
    *   **Task:** Modify the mint circuit to handle mixed collateral (70% wBTC, 30% "zero") and protocol fees.
    *   **Action:**
        *   Update **Inputs:** Accept *both* wBTC UTXOs and "zero" UTXOs, the new dual-price attestation, user signature.
        *   Update **Logic:**
            *   Verify ownership of *both* wBTC and "zero" input UTXOs.
            *   Verify the dual-price attestation signature and recency.
            *   Calculate the USD value of the proposed `zUSD` mint amount.
            *   Calculate the required USD value of wBTC collateral (70% of `zUSD` value / 1.5 CR = ~46.67% of `zUSD` value).
            *   Calculate the required USD value of "zero" collateral (30% of `zUSD` value / 1.5 CR = ~20% of `zUSD` value).
            *   Convert required USD values to required wBTC and "zero" token amounts using the attested prices.
            *   Calculate protocol fee (e.g., 0.1% of the `zUSD` value, taken proportionally from wBTC and "zero" collateral).
            *   Verify user provided *at least* the required amounts of wBTC and "zero" (required + fee).
            *   Consume input UTXOs (wBTC and "zero").
            *   Create locked collateral UTXOs (or update MPC pool state) for *both* wBTC and "zero".
            *   Create fee UTXOs (wBTC and "zero") sent to the protocol reservoir.
            *   Create output `zUSD` UTXO for the user.
            *   Create change UTXOs for *both* wBTC and "zero" if applicable.
        *   Update **Outputs:** `zUSD` UTXO, change UTXOs (wBTC/"zero"), fee UTXOs (wBTC/"zero"), collateral locking state update.
*   **[✓] Refactor `StablecoinRedeemCircuit` (`StablecoinRedeemV2Circuit`):**
    *   **Task:** Modify the redeem circuit to return mixed collateral and handle protocol fees.
    *   **Action:**
        *   Update **Inputs:** Accept `zUSD` UTXO, dual-price attestation, potentially MPC "OK-to-Redeem" attestation (more complex now with mixed collateral), user signature.
        *   Update **Logic:**
            *   Verify ownership of input `zUSD` UTXO.
            *   Verify attestation signatures and recency.
            *   Calculate the total USD value being redeemed.
            *   Calculate the target wBTC amount to return (70% of redeemed USD value / current wBTC/USD price).
            *   Calculate the target "zero" amount to return (30% of redeemed USD value / current zero/USD price).
            *   Calculate protocol fee (e.g., 0.1% of redeemed USD value, potentially paid in `zUSD` or deducted from returned collateral).
            *   Verify sufficient *total collateral value* exists for this redemption (likely requires the MPC "OK-to-Redeem" check referencing the specific locked collateral for this mint).
            *   Consume input `zUSD` UTXO.
            *   Authorize release of corresponding wBTC and "zero" collateral.
            *   Create output wBTC UTXO for the user (target wBTC amount - proportional fee, if applicable).
            *   Create output "zero" UTXO for the user (target "zero" amount - proportional fee, if applicable).
            *   (If fee paid in zUSD, ensure input zUSD covers redeemed amount + fee).
        *   Update **Outputs:** wBTC UTXO, "zero" UTXO.
*   **[✓] Implement Liquidation Mechanism (Major Task - May be Out of Scope):**
    *   **Task:** Design and implement how undercollateralized positions (due to price drops, especially in "zero") are handled.
    *   **Action:** Requires new circuits (`LiquidateCircuit`), interaction with MPCs to trigger liquidations based on price feeds, and potentially an auction mechanism. This is complex. *Confirm if this is in scope.*
*   **[✓] Update Stablecoin Tests:**
    *   **Task:** Write extensive tests for `StablecoinMintV2Circuit` and `StablecoinRedeemV2Circuit`.
    *   **Action:** Test various collateral ratios, price scenarios (wBTC up, "zero" down, etc.), fee calculations, edge cases (zero amounts, dust amounts), and failure conditions (insufficient collateral, bad signatures, stale prices).

**III. ICO Mechanism:**

*   **[✓] Design ICO Parameter Representation:**
    *   **Task:** Define how ICO parameters are stored (e.g., dedicated "ICO Parameter UTXO", published off-chain and referenced by hash).
    *   **Action:** Update core types if necessary.
*   **[✓] Implement `ICOConfigCircuit` (Optional):**
    *   **Task:** Create a circuit for creators to commit ICO parameters on-chain.
    *   **Action:** Define inputs (params, signature) and outputs (parameter commitment/UTXO).
*   **[✓] Implement `ICOContributeCircuit`:**
    *   **Task:** Create the circuit for users to contribute payment assets.
    *   **Action:** Define inputs (payment UTXO, ICO identifier/params, amount, signature), logic (verify payment, create locked escrow UTXO), and outputs (escrow UTXO, change UTXO).
*   **[✓] Define `ICOSettlementAttestation` Format (MPC Task):**
    *   **Task:** Specify the data structure MPCs will sign to attest to ICO success/failure.
    *   **Action:** Define fields (ICO ID, outcome, total raised, timestamp, signature).
*   **[✓] Implement `ICOSuccessSettleCircuit`:**
    *   **Task:** Create the circuit to distribute tokens and funds upon successful ICO completion.
    *   **Action:** Define inputs (attestation, *many* escrow UTXOs, creator token UTXO, signature). Implement logic for attestation verification, consuming inputs, pro-rata calculation, fee calculation (1%), creating *many* output UTXOs (native tokens to contributors, funds to creator, fees to reservoir). **Address scalability concerns regarding the number of inputs/outputs.**
*   **[✓] Implement `ICOFailureRefundCircuit`:**
    *   **Task:** Create the circuit for users to claim refunds upon failed ICO.
    *   **Action:** Define inputs (attestation, user's escrow UTXO, signature). Implement logic for attestation verification, consuming escrow UTXO, creating refund UTXO.
*   **[✓] Add ICO Tests:**
    *   **Task:** Test all new ICO circuits.
    *   **Action:** Test contribution, successful settlement (distribution, fees), failed settlement (refunds), edge cases (min/max raise, deadline).

**IV. Airdrop Mechanism:**

*   **[✓] Implement `AirdropLockCircuit` (Optional):**
    *   **Task:** Create a circuit for creators to lock the total airdrop supply and commit to the Merkle root.
    *   **Action:** Define inputs (creator token UTXO, Merkle root, signature), logic (consume input, create locked escrow UTXO with Merkle root metadata), outputs (escrow UTXO).
*   **[✓] Implement `AirdropClaimCircuit`:**
    *   **Task:** Create the circuit for users to claim their airdropped tokens.
    *   **Action:** Define inputs (Merkle proof components: siblings, index/path), user-specific data (amount, salt), signature/fee payment. Define public inputs (Merkle Root, Claim Nullifier). Implement logic for leaf hash reconstruction, Merkle proof verification, signature/fee check, creating output native token UTXO, registering claim nullifier.
*   **[✓] Define Airdrop Nullifier Scheme:**
    *   **Task:** Design how to prevent double-claims per user per airdrop.
    *   **Action:** Define nullifier input (e.g., hash(airdrop_id || user_address)).
*   **[✓] Add Airdrop Tests:**
    *   **Task:** Test the `AirdropClaimCircuit`.
    *   **Action:** Test valid claims, invalid claims (bad proof, wrong amount), double-claim attempts.

**V. WASM Bindings & CLI Updates:**

*   **[✓] Expose New Circuits via WASM:**
    *   **Task:** Add `#[wasm_bindgen]` wrappers for all new circuits (`Stablecoin V2`, `ICO`, `Airdrop`).
    *   **Action:** Create functions like `generate_ico_contribute_proof`, `verify_airdrop_claim_proof`, etc., ensuring data types are compatible between Rust and JS.
*   **[✓] Update CLI:**
    *   **Task:** Add new subcommands to the `wire` CLI tool for interacting with the new features.
    *   **Action:** Add commands like `wire amm configure-fees`, `wire stablecoin mint-v2`, `wire ico contribute`, `wire airdrop claim`, etc. Update argument parsing and command execution logic.

**VI. General Tasks:**

*   **[✓] Update Core Types:** Define new structs/targets if needed (e.g., `ZeroTokenUTXO`, `ICOParameterUTXO`, `EscrowUTXO`, `AirdropLeafData`).
*   **[✓] Update Error Handling:** Add new error variants to `WireError` and sub-enums as needed.
*   **[✓] Update Documentation:** Document all new circuits, fee mechanisms, stablecoin V2 design, ICO flow, and airdrop process. Update user guides and API references.
*   **[✓] Refactor/Optimize:** Review existing code for potential refactoring opportunities arising from the new features. Optimize new circuits for constraint count.

This list is extensive, particularly the Stablecoin V2 and ICO features, which require significant design and implementation effort, including coordination with the teams building the off-chain components (Party/Minter, Explorer).