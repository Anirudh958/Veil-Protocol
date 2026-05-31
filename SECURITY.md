# Security Policy

## Reporting Vulnerabilities

If you discover a security vulnerability in the Veil Protocol specification or implementation, please report it responsibly.

**Email**: security@veil-protocol.org (GPG key available on request)

**Do NOT** open a public GitHub issue for security vulnerabilities.

## Scope

Security reports are welcome for:
- Cryptographic weaknesses in the relay proof circuit
- Attacks that break sender anonymity, unlinkability, or unobservability
- Nullifier reuse across verifiers (double-spend)
- CRDT growth inflation attacks
- Sybil resistance bypass (vouching depth > 2, budget overflow)
- Sphinx packet correlation or replay attacks
- Cover traffic timing distinguishers

## Known Limitations of the Test Suite

The following attack vectors are documented but not yet tested in the automated suite:

1. **Grinding attack on nonce**: Adversary tries many nonces to produce nullifier collisions (DoS). Poseidon's 128-bit collision resistance makes this infeasible.
2. **Timing side-channel on proof verification**: Leaks whether a node is receiving real messages. Requires constant-time verification wrapper.
3. **Merkle root disagreement**: Two honest nodes with different CRDT convergence states accept different proofs. Bounded by O(log N) gossip rounds.

## Security Boundary

The relay proof circuit (12,387 R1CS constraints) guarantees:
- Receipt authenticity (can't fake relay work)
- Issuer reputation (can't earn credits from Sybils outside reputable set)
- Nullifier binding (can't reuse credits across verifiers)

The circuit does NOT prevent controlled-ring relay (8 adversary nodes with distinct keys relaying among themselves). This is by design — prevention lives at the reputation layer (social attestation cost). See test `sc5b_controlled_ring_relay_accepted_by_circuit` for documentation.
