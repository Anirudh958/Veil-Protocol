# Veil Protocol

**Metadata-private messaging via Proof-of-Relay. No blockchain. No tokens. No trusted parties.**

Veil is a decentralized messaging protocol where sending a message requires a zero-knowledge proof that you have faithfully relayed messages for others. The relay work simultaneously provides the anonymizing infrastructure, storage incentives, spam metering, and Sybil cost.

> *"Making the work that earns the right to send identical to the work that provides privacy to others."*

## Why Veil Exists

4.5 billion people live under mass surveillance. Existing solutions require cryptocurrency (Nym), trusted servers (Signal), or volunteer infrastructure (Tor). Veil requires only a phone and intermittent connectivity — no economic investment, no bank account, no exchange access.

## Status: Research Release (v0.1.0)

**Phase 1 complete**: Core protocol + circuits validated against whitepaper claims.

| Claim | Whitepaper | Measured |
|-------|-----------|----------|
| Relay step constraints | ~16,400 | 12,387 (25% better) |
| CRDT merge order independence | Theorem 6 | Verified (50 permutations) |
| Credit lifecycle correctness | Theorem 4 | Full state machine tested |
| Adversary bound (f=0.22) | C(K,T)·f⁹ | Validated (35.5M trials) |
| Shamir threshold | K=5, T=3 | All C(5,3)=10 subsets pass |

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test --all    # 53 tests: 34 core + 9 circuit + 10 security
```

## Repository Structure

```
veil-protocol/
├── doc/                    # Whitepaper (LaTeX + PDF, 29 pages)
├── circuits/               # ZK proof circuits (arkworks, BN254/BabyJubjub)
│   ├── src/                #   Relay step, ECDH, Poseidon, Merkle gadgets
│   └── tests/security.rs  #   Adversarial-input tests (10 scenarios)
├── core/                   # Protocol logic (no networking)
│   └── src/                #   CRDT, credits, Sphinx, Shamir, cover traffic
├── simulation/             # Monte Carlo validation (Python, seed=42)
├── SECURITY.md             # Vulnerability reporting + known test gaps
├── CONTRIBUTING.md         # How to contribute
└── CHANGELOG.md            # Version history
```

## Key Results

- **12,387 R1CS constraints** per relay step (arkworks 0.4) — mobile-feasible (~150ms/fold)
- **Penalty-Log CRDT** converges in 5 gossip rounds under 22% adversarial withholding
- **Verifier-bound nullifiers** eliminate double-spend without any consensus mechanism
- **10 security tests** verify rejection of forged receipts, self-relay, cross-verifier reuse, and growth inflation

## Whitepaper

The full academic paper (targeting PETS 2027) is in [`doc/whitepaper.pdf`](doc/whitepaper.pdf).

Key contributions:
1. **Bilateral Credit Incentive Theorem** — dominant strategy equilibrium without global state
2. **Growth-Isolation Impossibility** — no CRDT can merge reputation growth safely; penalty-log resolves this
3. **Constructive Adversary Bound** — adversaries provide more privacy than they can extract

## License

Apache 2.0 — use, modify, and deploy without restriction.
