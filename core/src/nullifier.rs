use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::poseidon::Poseidon;
use crate::types::{AffinePoint, Epoch, Scalar};

/// Verifier-bound nullifier: prevents credit double-use without consensus.
///
/// nullifier = Poseidon(sk_sender || epoch || verifier_pk_x || nonce)
///
/// Properties:
/// - Same verifier: collision detected (local storage)
/// - Different verifier: SNARK enforces verifier_pk match → proof invalid elsewhere
/// - Different epoch: epoch field mismatches → rejected
pub fn compute_nullifier(
    sender_sk: &Scalar,
    epoch: &Epoch,
    verifier_pk: &AffinePoint,
    nonce: &Scalar,
) -> Scalar {
    let poseidon = Poseidon::new();

    let epoch_field = Fr::from(epoch.0);
    let vk_x = verifier_pk.x;

    // Chain multiple Poseidon calls for 4 inputs (width=3 allows 2 inputs per call)
    let h1 = poseidon.hash_two(sender_sk, &epoch_field);
    let h2 = poseidon.hash_two(&vk_x, nonce);
    poseidon.hash_two(&h1, &h2)
}

/// Derive nonce deterministically from the credit set being consumed.
/// This ensures the same credit set always produces the same nullifier.
pub fn derive_nonce(receipt_hashes: &[Scalar]) -> Scalar {
    let poseidon = Poseidon::new();
    let mut acc = Fr::from(0u64);
    for hash in receipt_hashes {
        acc = poseidon.hash_two(&acc, hash);
    }
    acc
}

/// Nullifier store: each verifier maintains a set of used nullifiers per epoch.
/// Cleared when epoch expires (bounded storage).
pub struct NullifierStore {
    used: std::collections::HashMap<Epoch, std::collections::HashSet<[u8; 32]>>,
}

impl NullifierStore {
    pub fn new() -> Self {
        Self {
            used: std::collections::HashMap::new(),
        }
    }

    pub fn check_and_insert(&mut self, epoch: &Epoch, nullifier: &Scalar) -> bool {
        use ark_serialize::CanonicalSerialize;
        let mut bytes = [0u8; 32];
        nullifier
            .serialize_compressed(&mut bytes[..])
            .expect("serialization failed");

        let set = self.used.entry(epoch.clone()).or_default();
        set.insert(bytes)
    }

    pub fn clear_epoch(&mut self, epoch: &Epoch) {
        self.used.remove(epoch);
    }

    pub fn epoch_count(&self, epoch: &Epoch) -> usize {
        self.used.get(epoch).map(|s| s.len()).unwrap_or(0)
    }
}

impl Default for NullifierStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, Group};
    use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    #[test]
    fn test_nullifier_deterministic() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(1);
        let sk = Fr::rand(&mut rng);
        let epoch = Epoch(10);
        let vk: EdwardsAffine = EdwardsProjective::generator().into();
        let nonce = Fr::from(99u64);

        let n1 = compute_nullifier(&sk, &epoch, &vk, &nonce);
        let n2 = compute_nullifier(&sk, &epoch, &vk, &nonce);
        assert_eq!(n1, n2);
    }

    #[test]
    fn test_different_verifier_different_nullifier() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
        let sk = Fr::rand(&mut rng);
        let epoch = Epoch(10);
        let nonce = Fr::from(99u64);

        let gen = EdwardsProjective::generator();
        let vk1: EdwardsAffine = gen.into();
        let vk2: EdwardsAffine = (gen + gen).into();

        let n1 = compute_nullifier(&sk, &epoch, &vk1, &nonce);
        let n2 = compute_nullifier(&sk, &epoch, &vk2, &nonce);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_different_epoch_different_nullifier() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(3);
        let sk = Fr::rand(&mut rng);
        let vk: EdwardsAffine = EdwardsProjective::generator().into();
        let nonce = Fr::from(99u64);

        let n1 = compute_nullifier(&sk, &Epoch(1), &vk, &nonce);
        let n2 = compute_nullifier(&sk, &Epoch(2), &vk, &nonce);
        assert_ne!(n1, n2);
    }

    #[test]
    fn test_nullifier_store_rejects_duplicate() {
        let mut store = NullifierStore::new();
        let epoch = Epoch(1);
        let nullifier = Fr::from(12345u64);

        assert!(store.check_and_insert(&epoch, &nullifier));
        assert!(!store.check_and_insert(&epoch, &nullifier));
    }

    #[test]
    fn test_nullifier_store_clear() {
        let mut store = NullifierStore::new();
        let epoch = Epoch(1);
        let nullifier = Fr::from(12345u64);

        store.check_and_insert(&epoch, &nullifier);
        assert_eq!(store.epoch_count(&epoch), 1);

        store.clear_epoch(&epoch);
        assert_eq!(store.epoch_count(&epoch), 0);

        assert!(store.check_and_insert(&epoch, &nullifier));
    }
}
