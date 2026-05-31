# Contributing to Veil Protocol

## How to Contribute

We welcome contributions in the following areas:

### High Priority
- **ARM Cortex-A53 benchmarks**: Measured Nova fold times on actual mobile hardware
- **Nova IVC integration**: `circuits/src/nova_fold.rs` — 8-step folding chain
- **Groth16 compression**: `circuits/src/groth16_compress.rs` — final SNARK with verifier binding
- **Networking layer**: libp2p gossip, relay routing, receipt exchange

### Medium Priority
- **Additional core modules**: `mailbox.rs`, `vouching.rs`, `bootstrap.rs`, `epoch.rs`
- **Simulation in Rust**: Port Python Monte Carlo to Rust for reproducibility
- **Test vectors**: Known-answer tests for Poseidon, Sphinx, ECDH

### Always Welcome
- Security audit findings
- Performance optimizations (must not increase constraint count)
- Documentation improvements
- Bug reports with reproduction steps

## Code Standards

- All cryptographic code must be constant-time (no data-dependent branches on secrets)
- New modules must include tests that verify both correct AND adversarial inputs
- Constraint count changes must be documented (any delta from 12,387 needs justification)
- Protocol parameter changes require whitepaper update

## Testing

```bash
cargo test --all              # All 53 tests must pass
cargo test -p veil-circuits   # Circuit soundness + constraint counts
```

## Security Tests

When adding new functionality, include an adversarial-input test that demonstrates the mechanism correctly rejects the attack. See `circuits/tests/security.rs` for examples.
