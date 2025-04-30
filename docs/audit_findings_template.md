# 0BTC Wire Audit Findings Template

## Overview

This document provides a template for reporting audit findings for the 0BTC Wire project. Auditors should use this template to ensure consistent and comprehensive reporting of issues.

## Severity Levels

Findings should be classified according to the following severity ratings:

- **Critical**: Vulnerabilities that can lead to asset loss, compromise of the system, or other severe security issues
- **High**: Vulnerabilities that can have a significant impact on the security of the system but do not immediately lead to asset loss
- **Medium**: Vulnerabilities that have a moderate impact on the security of the system
- **Low**: Vulnerabilities that have a minor impact on the security of the system
- **Informational**: Issues that do not pose a security risk but may affect the quality, maintainability, or performance of the system

## Finding Template

### [SEVERITY] - [TITLE]

#### Description

A clear and concise description of the finding.

#### Impact

A description of the potential impact of the finding, including:
- What assets or components are affected
- What security properties are violated
- What the potential consequences are

#### Likelihood

An assessment of how likely it is that the vulnerability will be exploited, including:
- Required preconditions
- Technical complexity
- Required access or privileges

#### Location

The specific location(s) in the codebase where the issue was found, including:
- File path
- Line number(s)
- Function or component name

#### Proof of Concept

A proof of concept demonstrating the vulnerability, if applicable. This could include:
- Code snippet
- Test case
- Exploit script

#### Recommendation

A clear and actionable recommendation for addressing the finding, including:
- Proposed solution
- Alternative approaches
- Considerations for implementation

#### References

Any relevant references, such as:
- Similar vulnerabilities in other projects
- Academic papers or articles
- Best practices or standards

## Example Finding

### HIGH - Signature Verification Bypass in WrappedAssetMint Circuit

#### Description

The signature verification in the WrappedAssetMint circuit can be bypassed due to improper constraint enforcement. The circuit does not properly constrain the relationship between the public key and the signature, allowing an attacker to forge a valid proof with an invalid signature.

#### Impact

An attacker could create a valid proof for minting wrapped assets without a valid signature from the custodian. This would allow unauthorized minting of wrapped assets, potentially leading to:
- Inflation of the wrapped asset supply
- Loss of peg between the wrapped asset and the underlying asset
- Loss of trust in the system

#### Likelihood

The likelihood of exploitation is high because:
- No special access or privileges are required
- The technical complexity is moderate
- The attack can be performed by anyone with basic knowledge of the system

#### Location

- File: `src/circuits/wrapped_asset_mint.rs`
- Lines: 150-175
- Function: `add_signature_verification_constraints`

#### Proof of Concept

```rust
// Create a circuit with an invalid signature
let recipient_pk_hash = vec![0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
let amount = 1_000_000; // 0.01 BTC in satoshis
let deposit_nonce = 42;
let custodian_pk_x = 0xfedcba0987654321;
let custodian_pk_y = 0x1122334455667788;
let invalid_signature_r_x = 0; // Invalid signature
let invalid_signature_r_y = 0; // Invalid signature
let invalid_signature_s = 0; // Invalid signature

// Generate proof with invalid signature
let result = WrappedAssetMintCircuit::generate_proof_static(
    &recipient_pk_hash,
    amount,
    deposit_nonce,
    custodian_pk_x,
    custodian_pk_y,
    invalid_signature_r_x,
    invalid_signature_r_y,
    invalid_signature_s,
);

// Proof generation succeeds despite invalid signature
assert!(result.is_ok());

// Proof verification also succeeds
let proof = result.unwrap();
let verification_result = WrappedAssetMintCircuit::verify_proof(&proof);
assert!(verification_result.is_ok());
```

#### Recommendation

Properly enforce the signature verification constraints by:

1. Adding explicit constraints to ensure the signature components are valid points on the curve
2. Ensuring the signature verification result is properly constrained to be true
3. Adding a check to verify that the signature corresponds to the message being signed

```rust
// Add constraints to ensure signature points are on the curve
builder.assert_on_curve(signature_r_x, signature_r_y);

// Add constraints to ensure signature verification result is true
let verification_result = verify_signature(
    message_hash,
    signature_r_x, signature_r_y, signature_s,
    custodian_pk_x, custodian_pk_y
);
builder.assert_eq(verification_result, builder.one());
```

#### References

- [EdDSA Signature Verification Best Practices](https://example.com/eddsa-best-practices)
- [Similar vulnerability in Project X](https://example.com/project-x-vulnerability)
- [Plonky2 Constraint System Documentation](https://example.com/plonky2-docs)
