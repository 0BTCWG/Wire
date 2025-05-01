# MPC Library Selection for 0BTC Wire

## Requirements

For the 0BTC Wire project, we need:

1. **Threshold Ed25519 Signatures**: For custodian attestations and fee consolidation operations
2. **Threshold ECDSA (Optional)**: For BTC withdrawals, if multisig is not sufficient
3. **Security**: Audited, well-maintained libraries
4. **Rust Implementation**: Compatible with our codebase
5. **License**: Open-source with compatible licensing

## Selected Libraries

### Primary: ZenGo-X/multi-party-eddsa

**Repository**: [https://github.com/ZenGo-X/multi-party-eddsa](https://github.com/ZenGo-X/multi-party-eddsa)

**Features**:
- Threshold EdDSA scheme based on provably secure distributed Schnorr signatures
- Supports {t,n} threshold scheme
- Uses DKG from "Fast Multiparty Threshold ECDSA with Fast Trustless Setup"
- Written in Rust
- Maintained by ZenGo, a company specializing in MPC cryptography

**Rationale**:
- Provides the required threshold Ed25519 functionality
- Rust implementation integrates well with our codebase
- Based on well-researched cryptographic protocols
- Active maintenance and development

### For Bitcoin Withdrawals

For Bitcoin withdrawals, we have two options:

1. **Use Bitcoin Multisig**: Simpler approach, well-tested on the Bitcoin network
   - Pros: Widely used, well-understood security properties
   - Cons: On-chain footprint is larger, less privacy

2. **Threshold ECDSA**: If greater privacy or smaller on-chain footprint is required
   - Potential library: [ZenGo-X/multi-party-ecdsa](https://github.com/ZenGo-X/multi-party-ecdsa)
   - Pros: Single signature on-chain, better privacy
   - Cons: More complex implementation, requires additional security review

**Decision**: We will initially implement Bitcoin withdrawals using standard Bitcoin multisig for simplicity and security, with the option to upgrade to threshold ECDSA in the future if needed.

## Integration Plan

1. Add `multi-party-eddsa` as a dependency
2. Create a Rust wrapper around the library to simplify integration
3. Implement the MPC operator tooling using this library
4. Create secure communication channels between MPC nodes
5. Implement the DKG (Distributed Key Generation) ceremony
6. Implement the signing ceremony for attestations and fee consolidation

## Security Considerations

- The library will need a thorough security review before production use
- We should consider engaging with ZenGo or other MPC experts for consultation
- A formal security audit should be conducted on our integration
