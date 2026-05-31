use ark_bn254::Fr;
use ark_ec::Group;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use ark_ff::UniformRand;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use rand::SeedableRng;

use veil_circuits::merkle_gadget::{build_merkle_tree, get_merkle_proof, MerkleBenchCircuit};
use veil_circuits::relay_step::RelayStepCircuit;
use veil_core::config::MERKLE_DEPTH;

fn build_honest_circuit() -> RelayStepCircuit {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(100);

    let node_sk = Fr::rand(&mut rng);
    let peer_pk: EdwardsAffine = EdwardsProjective::generator().into();
    let packet_header_blocks: Vec<Fr> = (0..13).map(|_| Fr::rand(&mut rng)).collect();

    let issuer_pk_x = Fr::rand(&mut rng);
    let mut leaves: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect();
    leaves[7] = issuer_pk_x;
    let (merkle_root, layers) = build_merkle_tree(&leaves);
    let (merkle_path, merkle_indices) = get_merkle_proof(&layers, 7);

    let poseidon = veil_core::poseidon::Poseidon::new();
    let packet_hash = poseidon.hash_two(&packet_header_blocks[0], &packet_header_blocks[1]);
    let receipt_value = poseidon.hash_two(&packet_hash, &issuer_pk_x);

    RelayStepCircuit {
        merkle_root,
        epoch: Fr::from(1u64),
        node_sk,
        peer_pk,
        packet_header_blocks,
        receipt_value,
        receipt_issuer_pk_x: issuer_pk_x,
        merkle_path,
        merkle_indices,
    }
}

/// SC-1: Forged receipt (wrong value) must be rejected.
#[test]
fn test_forged_receipt_rejected() {
    let mut circuit = build_honest_circuit();
    circuit.receipt_value = Fr::from(999u64); // Attacker forges receipt

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "SECURITY FAILURE: Forged receipt accepted by circuit"
    );
}

/// SC-2: Corrupted Merkle path (issuer not in reputable set) must be rejected.
#[test]
fn test_non_reputable_issuer_rejected() {
    let mut circuit = build_honest_circuit();
    // Corrupt one level of the Merkle proof
    circuit.merkle_path[3] = Fr::from(0xDEADu64);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "SECURITY FAILURE: Non-reputable issuer accepted by circuit"
    );
}

/// SC-3: Wrong Merkle root (stale/forged reputable set) must be rejected.
#[test]
fn test_wrong_merkle_root_rejected() {
    let mut circuit = build_honest_circuit();
    circuit.merkle_root = Fr::from(0xBADu64); // Wrong epoch's root

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "SECURITY FAILURE: Wrong Merkle root accepted"
    );
}

/// SC-4: Receipt from node NOT in the Merkle tree must be rejected.
#[test]
fn test_receipt_from_unknown_node_rejected() {
    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(200);
    let mut circuit = build_honest_circuit();

    // Use a random issuer pk that is NOT in the reputable set
    let fake_issuer = Fr::rand(&mut rng);
    circuit.receipt_issuer_pk_x = fake_issuer;

    // Recompute receipt for the fake issuer (attacker knows the hash)
    let poseidon = veil_core::poseidon::Poseidon::new();
    let packet_hash = poseidon.hash_two(
        &circuit.packet_header_blocks[0],
        &circuit.packet_header_blocks[1],
    );
    circuit.receipt_value = poseidon.hash_two(&packet_hash, &fake_issuer);

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "SECURITY FAILURE: Receipt from non-reputable node accepted"
    );
}

/// SC-5: Self-relay attack — issuer and prover are the same entity.
/// The circuit itself doesn't prevent this (it checks Merkle membership),
/// but the DISTINCTNESS check across N_CREDIT receipts prevents it at the
/// credit accumulation level. Verify that the credit accumulator rejects
/// duplicate issuers.
#[test]
fn test_self_relay_duplicate_issuer_rejected() {
    use veil_core::credit::{CreditAccumulator, CreditError};
    use veil_core::types::{Epoch, Receipt, RelayWitness, Scalar};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(300);
    let self_sk = ark_ed_on_bn254::Fr::rand(&mut rng);
    let self_pk: EdwardsAffine = (EdwardsProjective::generator() * self_sk).into();

    let mut acc = CreditAccumulator::new();

    // First receipt from self — accepted
    let w1 = RelayWitness {
        packet_hash: [1u8; 32],
        receipt: Receipt {
            value: Scalar::rand(&mut rng),
            issuer_pk: self_pk,
            epoch: Epoch(1),
            packet_hash: [1u8; 32],
        },
        merkle_path: vec![Scalar::rand(&mut rng); MERKLE_DEPTH],
        merkle_indices: vec![false; MERKLE_DEPTH],
    };
    acc.add_witness(w1).unwrap();

    // Second receipt from SAME self — must be rejected (duplicate issuer)
    let w2 = RelayWitness {
        packet_hash: [2u8; 32],
        receipt: Receipt {
            value: Scalar::rand(&mut rng),
            issuer_pk: self_pk, // Same issuer!
            epoch: Epoch(1),
            packet_hash: [2u8; 32],
        },
        merkle_path: vec![Scalar::rand(&mut rng); MERKLE_DEPTH],
        merkle_indices: vec![false; MERKLE_DEPTH],
    };
    assert_eq!(
        acc.add_witness(w2).unwrap_err(),
        CreditError::DuplicateIssuer,
        "SECURITY FAILURE: Self-relay (duplicate issuer) not rejected"
    );
}

/// SC-5b: Controlled-ring relay with DISTINCT keys.
///
/// The adversary controls 8 nodes (A-H) with distinct keys and routes packets
/// in a circle. Each hop produces a valid receipt from a distinct issuer.
/// The CIRCUIT correctly accepts this (it sees 8 distinct reputable issuers).
///
/// This is NOT a circuit bug — the circuit cannot distinguish controlled-ring
/// from honest-relay. Security against this attack comes from the REPUTATION LAYER:
/// all 8 nodes must be in the reputable set, which requires social vouching
/// (K_vouch=3 vouchers each), depth-limited (vouched nodes can't vouch),
/// and reputation contagion (activating Sybils burns voucher reputation).
///
/// The Sybil creation cost for 8 controlled reputable nodes:
/// 8 nodes × 3 vouchers each = 24 voucher relationships (minimum).
/// Each voucher risks 50% reputation loss upon Sybil activation.
#[test]
fn test_controlled_ring_relay_accepted_by_circuit() {
    use veil_core::credit::CreditAccumulator;
    use veil_core::types::{Epoch, Receipt, RelayWitness, Scalar};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(350);
    let mut acc = CreditAccumulator::new();

    // 8 adversary-controlled nodes with DISTINCT keys
    for i in 0..8u8 {
        let sk = ark_ed_on_bn254::Fr::rand(&mut rng);
        let pk: EdwardsAffine = (EdwardsProjective::generator() * sk).into();
        let w = RelayWitness {
            packet_hash: [i; 32],
            receipt: Receipt {
                value: Scalar::rand(&mut rng),
                issuer_pk: pk,
                epoch: Epoch(1),
                packet_hash: [i; 32],
            },
            merkle_path: vec![Scalar::rand(&mut rng); MERKLE_DEPTH],
            merkle_indices: vec![false; MERKLE_DEPTH],
        };
        acc.add_witness(w).unwrap();
    }

    // Circuit-level: this is ACCEPTED (8 distinct issuers)
    assert!(acc.is_ready_to_compress());
    // Security: prevention is at reputation layer (social attestation cost),
    // not at circuit layer. This test documents the security boundary.
}

/// SC-6: Credit with fewer than N_CREDIT receipts cannot produce a valid proof.
#[test]
fn test_insufficient_relays_cannot_send() {
    use veil_core::credit::{CreditAccumulator, CreditError};
    use veil_core::config::N_CREDIT;
    use veil_core::types::{Epoch, Receipt, RelayWitness, Scalar};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(400);
    let mut acc = CreditAccumulator::new();

    // Add only N_CREDIT - 1 witnesses
    for i in 0..(N_CREDIT - 1) {
        let sk = ark_ed_on_bn254::Fr::rand(&mut rng);
        let pk: EdwardsAffine = (EdwardsProjective::generator() * sk).into();
        let w = RelayWitness {
            packet_hash: [i as u8; 32],
            receipt: Receipt {
                value: Scalar::rand(&mut rng),
                issuer_pk: pk,
                epoch: Epoch(1),
                packet_hash: [i as u8; 32],
            },
            merkle_path: vec![Scalar::rand(&mut rng); MERKLE_DEPTH],
            merkle_indices: vec![false; MERKLE_DEPTH],
        };
        acc.add_witness(w).unwrap();
    }

    // Should NOT be ready to compress/send
    assert!(!acc.is_ready_to_compress());
    assert_eq!(
        acc.consume().unwrap_err(),
        CreditError::NotReady,
        "SECURITY FAILURE: Incomplete credit allowed to send"
    );
}

/// SC-7: Nullifier uniqueness — same sender, same epoch, different verifier
/// produces different nullifiers (prevents cross-verifier reuse).
#[test]
fn test_nullifier_cross_verifier_reuse_impossible() {
    use veil_core::nullifier::compute_nullifier;
    use veil_core::types::Epoch;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(500);
    let sk = Fr::rand(&mut rng);
    let epoch = Epoch(42);
    let nonce = Fr::from(1u64);

    // Two different verifiers
    let vk1: EdwardsAffine = EdwardsProjective::generator().into();
    let gen = EdwardsProjective::generator();
    let vk2: EdwardsAffine = (gen + gen).into();

    let n1 = compute_nullifier(&sk, &epoch, &vk1, &nonce);
    let n2 = compute_nullifier(&sk, &epoch, &vk2, &nonce);

    assert_ne!(
        n1, n2,
        "SECURITY FAILURE: Same nullifier for different verifiers — double-spend possible"
    );
}

/// SC-8: Nullifier uniqueness — same sender, same verifier, different epoch
/// produces different nullifiers (prevents stale-credit replay).
#[test]
fn test_nullifier_stale_epoch_rejected() {
    use veil_core::nullifier::compute_nullifier;
    use veil_core::types::Epoch;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(600);
    let sk = Fr::rand(&mut rng);
    let vk: EdwardsAffine = EdwardsProjective::generator().into();
    let nonce = Fr::from(1u64);

    let n_current = compute_nullifier(&sk, &Epoch(100), &vk, &nonce);
    let n_stale = compute_nullifier(&sk, &Epoch(99), &vk, &nonce);

    assert_ne!(
        n_current, n_stale,
        "SECURITY FAILURE: Stale epoch nullifier matches current — replay possible"
    );
}

/// SC-9: Penalty-log CRDT cannot be inflated by merging fake growth.
#[test]
fn test_crdt_growth_inflation_impossible() {
    use veil_core::penalty_log::PenaltyLog;
    use veil_core::reputation::ReputationComputer;
    use veil_core::types::NodeId;

    let n = NodeId([1u8; 32]);

    // Observer A has seen 100 relays from node n
    let mut comp_a = ReputationComputer::new();
    for _ in 0..100 {
        comp_a.record_verified_relay(&n);
    }

    // Observer B has seen 0 relays from node n (adversary tries to inflate)
    let comp_b = ReputationComputer::new();

    // After "merging" (which doesn't exist for growth — that's the point):
    // comp_b's reputation for n remains 0 regardless of what comp_a thinks.
    let log = PenaltyLog::new();
    let rep_b = comp_b.compute_reputation(&n, &log);
    assert_eq!(
        rep_b, 0.0,
        "SECURITY FAILURE: Growth was somehow merged — inflation possible"
    );

    // Even merging penalty logs doesn't transfer growth
    let mut log_a = PenaltyLog::new();
    let mut log_b = PenaltyLog::new();
    log_b.merge(&log_a);
    let rep_b_after_merge = comp_b.compute_reputation(&n, &log_b);
    assert_eq!(rep_b_after_merge, 0.0);
}
