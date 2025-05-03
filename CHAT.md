Okay, here are the developer instructions for implementing the three requested features within the 0BTC Wire ecosystem, keeping in mind the ZK-UTXO model, the existence of MPC operators, and the constraints discussed (especially avoiding global state *within circuits* and not relying on external chains for direct value backing, while allowing wBTC internally).

---

## Developer Instructions: Extending 0BTC Wire

This document outlines the requirements and design considerations for implementing three new major features into the 0BTC Wire system:

1.  **Lightning Network Bridge:** Enable minting and redeeming wBTC using Lightning Network payments.
2.  **Automated Market Makers (AMMs):** Implement CPMM and Virtual CPMM (Pump.fun-style) for internal token swaps.
3.  **wBTC-Collateralized Stablecoin:** Create a USD-pegged stablecoin (`zUSD`) collateralized by wBTC using MPC Price Attestations.

Developers should be familiar with the existing 0BTC Wire architecture, Plonky2 circuits, the UTXO model, and the role of the MPC operators.

---

### Feature 1: Lightning Network Bridge for wBTC

**Goal:** Allow users to bridge BTC into and out of 0BTC Wire as wBTC using the Lightning Network for faster and potentially cheaper operations compared to on-chain transactions.

**Architecture Overview:**

*   MPC operators run Lightning Network node(s) connected to the broader LN.
*   Users interact with the MPC LN node(s) to deposit (pay LN invoice) or withdraw (provide LN invoice).
*   MPCs attest to LN payment receipts for minting and execute LN payments upon verifying wBTC burns.
*   New ZK circuits verify MPC attestations (for mint) and user ownership (for burn).

**Required Components:**

1.  **MPC Lightning Node Infrastructure:** Operators need to run and manage liquidity for one or more shared Lightning nodes.
2.  **MPC Logic:**
    *   **Invoice Generation:** Generate LN invoices for users requesting wBTC withdrawal (burn).
    *   **Payment Monitoring:** Monitor incoming LN payments corresponding to mint requests.
    *   **Mint Attestation:** Upon confirming an LN payment for a mint deposit, the MPC quorum signs a `(payment_hash, amount, recipient_pkh, timestamp)` attestation.
    *   **Burn Proof Verification:** Monitor 0BTC Wire for `LNBurnCircuit` proofs.
    *   **Invoice Payment:** Upon verifying a valid `LNBurnCircuit` proof, the MPC quorum authorizes payment of the user-provided LN invoice using the MPC-controlled LN node.
3.  **New ZK Circuits:**
    *   `LNMintCircuit`: Mints wBTC within 0BTC Wire.
    *   `LNBurnCircuit`: Burns wBTC within 0BTC Wire.
4.  **Off-Chain Communication:** Mechanism for users to request withdrawal invoices from MPCs and receive mint attestations after payment.

**Circuit Design:**

*   **`LNMintCircuit`:**
    *   **Public Inputs:** MPC Mint Attestation `(payment_hash, amount, recipient_pkh, timestamp, mpc_signature)`, MPC Public Key.
    *   **Private Inputs:** Salt/blinding factor for the new UTXO.
    *   **Logic:**
        1.  Verify the `mpc_signature` on the attestation using the MPC Public Key.
        2.  Verify the `timestamp` is recent (requires current time as public input or relaxation of this check).
        3.  Create a new wBTC UTXO (`asset_id = WBTC_ASSET_ID`) with the specified `amount` owned by `recipient_pkh`.
    *   **Outputs:** New wBTC UTXO commitment.

*   **`LNBurnCircuit`:**
    *   **Public Inputs:** Input wBTC UTXO nullifier, LN Invoice details (payment hash, amount, expiry), destination LN node info (potentially).
    *   **Private Inputs:** Input wBTC UTXO details (amount, asset ID, owner, salt), User's Secret Key corresponding to the input UTXO.
    *   **Logic:**
        1.  Verify ownership of the input wBTC UTXO using the user's signature (created against the burn details + invoice).
        2.  Verify the input UTXO amount is sufficient for the invoice amount (+ potential routing fees, handled off-chain by MPC).
        3.  Calculate and register the nullifier for the input wBTC UTXO.
        4.  (Crucially, the *actual payment* happens off-chain by the MPC after verifying this proof).

**User Interaction Flow:**

*   **Minting:**
    1.  User requests deposit info from MPCs (maybe gets a specific LN node URI or temporary invoice).
    2.  User pays LN invoice to MPC node.
    3.  MPC detects payment, quorum generates signed Mint Attestation.
    4.  User receives attestation, uses it as input to `LNMintCircuit` to generate a proof.
    5.  User submits proof to 0BTC Wire; verifier confirms, new wBTC UTXO is added.
*   **Burning:**
    1.  User generates an LN invoice on their own LN node/wallet.
    2.  User creates inputs for `LNBurnCircuit` including their wBTC UTXO, the invoice details, and signs it.
    3.  User generates the `LNBurnCircuit` proof.
    4.  User submits the *proof and the LN invoice* to the MPC operators (via API/off-chain).
    5.  MPCs verify the proof. If valid, they pay the user's LN invoice from the MPC LN node.

**Key Considerations:**

*   **LN Liquidity:** MPCs must actively manage LN channel liquidity.
*   **Proof of Payment:** The MPC mint attestation serves as the verifiable proof of LN deposit.
*   **Withdrawal Execution:** Burning wBTC via ZK proof *authorizes* the MPCs to pay the user's LN invoice; the payment itself is an off-chain LN action triggered by the proof. Trust is required that MPCs will pay upon seeing a valid proof.
*   **Fees:** LN routing fees need to be handled (likely deducted by MPCs during withdrawal payment).

---

### Feature 2: CPMM and Virtual CPMM AMMs

**Goal:** Enable decentralized swaps between assets (wBTC and native assets) directly within the 0BTC Wire system using Constant Product Market Maker (CPMM) and Pump.fun-style Virtual CPMM bonding curves.

**Architecture Overview:**

*   Liquidity pools are represented by unique "Pool State UTXOs".
*   Liquidity Provider (LP) shares are represented by separate "LP Share UTXOs".
*   Specific ZK circuits (`Swap`, `AddLiquidity`, `RemoveLiquidity`, etc.) consume old Pool State/LP Share UTXOs and produce new ones, enforcing AMM logic.
*   Virtual CPMMs start with bonding curve logic, transitioning to standard CPMM later.

**Required Components:**

1.  **State Representation:** Define the structure for:
    *   `PoolStateUTXO`: Contains `(pool_id, tokenA_asset_id, tokenB_asset_id, reserveA, reserveB, total_lp_shares)`. For Virtual CPMM, add bonding curve parameters and state (e.g., `current_supply`, `target_reserve`, `has_transitioned_flag`).
    *   `LPShareUTXO`: Contains `(pool_id, owner_pkh, lp_shares_amount)`.
2.  **New ZK Circuits:**
    *   `CreatePoolCircuit`: Initializes a new `PoolStateUTXO` (potentially restricted).
    *   `SwapCircuit`: Exchanges Token A for Token B.
    *   `AddLiquidityCircuit`: Adds liquidity, mints LP shares.
    *   `RemoveLiquidityCircuit`: Removes liquidity, burns LP shares.
    *   *(Virtual CPMM Specific):*
        *   `BuyTokenCircuit`: Buys native token using base asset (e.g., wBTC) along a bonding curve.
        *   `SellTokenCircuit`: Sells native token for base asset along bonding curve.
        *   `TransitionCircuit`: Converts the Virtual CPMM pool state to a standard CPMM state once conditions are met (e.g., target reserve reached).
3.  **Arithmetic Gadgets:** Ensure efficient fixed-point or scaled-integer arithmetic gadgets are available for price/amount calculations within circuits.

**Circuit Design (CPMM Example):**

*   **`SwapCircuit`:**
    *   **Inputs:** User's Input Token UTXO, *current* `PoolStateUTXO` for the pair, desired output token asset ID, min output amount, user signature.
    *   **Outputs:** User's Output Token UTXO, *new* `PoolStateUTXO`, User's Change Input Token UTXO (if any).
    *   **Logic:**
        1.  Verify user signature/ownership of input UTXO.
        2.  Consume input UTXO (register nullifier).
        3.  Consume the *current* `PoolStateUTXO` (register nullifier).
        4.  Calculate output amount using CPMM formula (`x*y=k`, including fees). Assert output amount >= min output amount.
        5.  Calculate new reserves (`reserveA_new`, `reserveB_new`).
        6.  Create the *new* `PoolStateUTXO` with updated reserves.
        7.  Create the user's Output Token UTXO.
        8.  Create change UTXO if needed.

*   **`AddLiquidityCircuit`:**
    *   **Inputs:** User's Token A UTXO, User's Token B UTXO, *current* `PoolStateUTXO`, user signature.
    *   **Outputs:** *New* `PoolStateUTXO`, User's `LPShareUTXO`, change UTXOs (if any).
    *   **Logic:** Similar flow - verify inputs, consume them, calculate LP shares based on deposit ratio relative to current reserves, update reserves in the new `PoolStateUTXO`, create LP share UTXO.

*   **`RemoveLiquidityCircuit`:**
    *   **Inputs:** User's `LPShareUTXO`, *current* `PoolStateUTXO`, user signature.
    *   **Outputs:** User's Token A UTXO, User's Token B UTXO, *New* `PoolStateUTXO`.
    *   **Logic:** Similar flow - verify inputs, consume them, calculate token amounts based on LP share percentage of total reserves, update reserves in the new `PoolStateUTXO`, create output token UTXOs.

*   **Virtual CPMM Circuits (`BuyTokenCircuit`, `SellTokenCircuit`):** Similar structure but use bonding curve math (`price = f(current_supply)`) instead of `x*y=k`. Update `current_supply` and reserves in the new `PoolStateUTXO`.
*   **`TransitionCircuit`:** Consumes the final Virtual CPMM `PoolStateUTXO`, creates a new standard CPMM `PoolStateUTXO` using the final reserves. Logic asserts transition conditions are met.

**MPC Operator Logic:**
*   Generally minimal for standard CPMM.
*   For Virtual CPMM, MPCs *could* be involved in triggering the `TransitionCircuit` or setting initial bonding curve parameters via attestations if required.

**User Interaction Flow:**
*   Users select the appropriate circuit (`Swap`, `AddLiquidity`, etc.).
*   Users provide their input UTXOs and necessary parameters.
*   Users must locate the *latest* `PoolStateUTXO` for the pool they want to interact with (this is a key challenge for UX).
*   Users generate and submit the proof.

**Key Considerations:**

*   **State UTXO Management:** Finding the *latest* unspent `PoolStateUTXO` for a given pool is crucial and non-trivial for users/frontends. This might require off-chain indexers. Each pool interaction consumes the old state and creates a new one, serializing operations on that specific pool.
*   **Circuit Complexity:** AMM calculations, especially with fees or bonding curves, can lead to high constraint counts. Efficient arithmetic gadgets are essential.
*   **Concurrency:** Only one operation can modify a specific pool's state at a time because it consumes the single `PoolStateUTXO`. This limits throughput per pool compared to account-based models.
*   **Virtual CPMM:** Requires careful design of the bonding curve parameters, transition conditions, and the `TransitionCircuit`.

---

### Feature 3: wBTC-Collateralized Stablecoin (`zUSD`) with MPC Price Attestation

**Goal:** Create a USD-pegged stablecoin (`zUSD`) within 0BTC Wire, primarily collateralized by wBTC, using MPCs to attest to the external BTC/USD price, avoiding global state in circuits.

**Architecture Overview:**

*   `zUSD` is backed by wBTC locked within the system (potentially via specific UTXO logic or an MPC-managed pool).
*   MPCs periodically fetch the BTC/USD price, reach consensus, and sign a timestamped Price Attestation.
*   Users obtain recent Price Attestations to use when minting or redeeming `zUSD`.
*   New ZK circuits (`StablecoinMintCircuit`, `StablecoinRedeemCircuit`) verify the Price Attestation signature and timestamp before executing the mint/redeem logic based on the attested price.

**Required Components:**

1.  **MPC Price Reporting Oracle:**
    *   Logic for MPCs to fetch prices from multiple reliable external sources.
    *   Consensus mechanism (e.g., medianizer) for the price.
    *   Mechanism to collectively sign `(timestamp, btc_usd_price)` using the MPC threshold key.
2.  **Attestation Distribution:** Publicly accessible endpoint/datastore for users to retrieve the latest signed Price Attestations.
3.  **New ZK Circuits:**
    *   `StablecoinMintCircuit`: Mints `zUSD` against wBTC collateral.
    *   `StablecoinRedeemCircuit`: Redeems `zUSD` for wBTC collateral.
4.  **Collateral Management Mechanism:** Strategy for ensuring redemptions are backed by sufficient collateral (see Challenges below). Requires careful design. *Option B (MPC Pre-Redemption Check) is recommended.*
5.  **(Optional) Native Governance Token (`WIRE-GOV`):** Could be introduced later for a fractional model or governance.

**Circuit Design:**

*   **`StablecoinMintCircuit`:**
    *   **Public Inputs:** Price Attestation `(timestamp, btc_usd_price, mpc_signature)`, MPC Public Key, Current Time/Block Height (for timestamp check), desired `zUSD` amount.
    *   **Private Inputs:** Input wBTC UTXO(s), user secret key.
    *   **Logic:**
        1.  Verify user signature/ownership of input wBTC UTXO(s).
        2.  Verify `mpc_signature` on `(timestamp, btc_usd_price)` using MPC Public Key.
        3.  Assert `Current Time/Block Height - timestamp < validity_window`.
        4.  Calculate `required_wBTC = zUSD_amount / btc_usd_price * overcollateralization_ratio`.
        5.  Assert `input_wBTC_amount >= required_wBTC`.
        6.  Consume input wBTC UTXO(s) (register nullifier).
        7.  *Mechanism to lock collateral:* Create a specific "Locked Collateral UTXO" OR transfer wBTC to an MPC-controlled pool (design choice needed).
        8.  Create new `zUSD` UTXO for the user.
        9.  Create change wBTC UTXO if `input_wBTC_amount > required_wBTC`.
    *   **Outputs:** `zUSD` UTXO commitment, change wBTC UTXO commitment (if any), Locked Collateral UTXO commitment / updated pool state (depending on design).

*   **`StablecoinRedeemCircuit`:**
    *   **Public Inputs:** Price Attestation `(timestamp, btc_usd_price, mpc_signature)`, MPC Public Key, Current Time/Block Height, *MPC "OK-to-Redeem" Attestation (Optional, see below)*.
    *   **Private Inputs:** Input `zUSD` UTXO(s), user secret key.
    *   **Logic:**
        1.  Verify user signature/ownership of input `zUSD` UTXO(s).
        2.  Verify `mpc_signature` on Price Attestation.
        3.  Assert `Current Time/Block Height - timestamp < validity_window`.
        4.  *(Option B - Recommended)* Verify the MPC "OK-to-Redeem" Attestation signature. This attestation confirms sufficient system-wide collateral exists *before* the user generates the proof.
        5.  Calculate `wBTC_to_return = zUSD_amount / btc_usd_price` (minus fees).
        6.  Consume input `zUSD` UTXO(s) (register nullifier).
        7.  *Mechanism to unlock collateral:* Consume the corresponding "Locked Collateral UTXO" OR authorize release from MPC pool.
        8.  Create output wBTC UTXO for the user.
    *   **Outputs:** wBTC UTXO commitment.

**MPC Operator Logic:**

*   **Price Oracle:** Fetch external BTC/USD price, reach consensus, sign `(timestamp, price)` data packet, publish attestation. Define validity window (e.g., 5 mins).
*   **(Option B - Recommended) Redemption Pre-Check:** Maintain an off-chain view (or monitor state UTXOs) of total locked wBTC collateral vs outstanding `zUSD`. When a user requests redemption, check sufficiency. If okay, quorum signs an "OK-to-Redeem" attestation `(user_pkh, zUSD_amount, timestamp, mpc_signature)` which the user includes in their `StablecoinRedeemCircuit` proof.
*   **(Alternative B) Pool Management:** If using an MPC-managed pool, MPCs need logic to accept wBTC deposits during mint and release them during redemption based on verified proofs.

**User Interaction Flow:**

*   **Minting:**
    1.  User gets the latest Price Attestation from MPCs.
    2.  User generates `StablecoinMintCircuit` proof using their wBTC UTXO and the attestation.
    3.  User submits proof; `zUSD` UTXO is created.
*   **Redeeming (Option B):**
    1.  User requests an "OK-to-Redeem" attestation from MPCs for a specific `zUSD` amount.
    2.  MPCs verify collateral sufficiency and issue the attestation.
    3.  User gets the latest Price Attestation from MPCs.
    4.  User generates `StablecoinRedeemCircuit` proof using their `zUSD` UTXO, Price Attestation, and "OK-to-Redeem" Attestation.
    5.  User submits proof; wBTC UTXO is created.
*   **Transferring `zUSD`:** Uses the standard, cheap `TransferCircuit`.

**Key Considerations:**

*   **Trust Model:** Heavy reliance on MPC honesty and liveness for price feeds and potentially redemption pre-checks. The integrity of the *peg* depends on the MPCs accurately reporting the price.
*   **Collateral Management:** Decide *how* collateral is locked/managed (Linked UTXOs vs. MPC Pool/Attestation). Option B (MPC Pre-Redemption Check) is strongly recommended for fungibility.
*   **Timestamp Oracle:** Need a reliable source for `current_time` within the circuit to check attestation validity.
*   **Over-Collateralization/Liquidations:** Design needed for handling volatility. Liquidations likely need to be MPC-triggered based on off-chain price monitoring.
*   **Circuit Complexity:** Mint/Redeem circuits are complex, involving price calculations and multiple signature verifications.

---

These instructions provide a high-level design. Detailed circuit implementation, MPC communication protocols, and specific off-chain service designs will require further specification. Remember to prioritize security reviews at each stage, especially for the MPC logic and the ZK circuits.