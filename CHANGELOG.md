# Changelog

## v0.1.0 (2026-05-31) — Initial Research Release

### Core Protocol (`core/`)
- Penalty-Log CRDT with proven commutativity/associativity/idempotency
- Reputation formula: R(n) = (1 - e^{-λk}) × Π(1 - severity)
- Credit state machine: accumulate → compress → consume
- Verifier-bound nullifiers (no-consensus anti-double-spend)
- Poseidon hash (t=3, α=5, BN254 scalar field)
- Sphinx packet construction and processing (header-only circuit, stream cipher payload)
- Shamir secret sharing (K=5, T=3)
- Cover traffic scheduler (Poisson process, slot replacement)

### Circuits (`circuits/`)
- Relay step circuit: 12,387 R1CS constraints (arkworks 0.4)
- ECDH gadget: 3,982 constraints (BabyJubjub variable-base scalar mult)
- Poseidon gadget: 240 constraints per hash
- Merkle membership gadget: 3,403 constraints (depth-14)
- Security tests: 10 adversarial-input validations

### Simulation (`simulation/`)
- Monte Carlo adversary bound: 35.5M trials, seed=42
- CRDT convergence: 5,000 nodes, O(log N) propagation verified

### Documentation (`doc/`)
- Complete whitepaper (29 pages, 5 theorems, 34 references)
- Compiled PDF
