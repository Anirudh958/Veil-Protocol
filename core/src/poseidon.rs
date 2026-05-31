use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

use crate::config::{POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_WIDTH};

/// Poseidon hash over BN254 scalar field.
///
/// Parameters: t=3 (width), α=5 (S-box), 8 full rounds, 57 partial rounds.
/// ~300 R1CS constraints per invocation.
///
/// This is a reference implementation for correctness testing.
/// The circuit version uses arkworks constraint gadgets.
pub struct Poseidon {
    round_constants: Vec<Fr>,
    mds_matrix: Vec<Vec<Fr>>,
}

impl Poseidon {
    pub fn new() -> Self {
        let t = POSEIDON_WIDTH;
        let total_rounds = POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS;
        let num_constants = t * total_rounds;

        // Deterministic round constants from seed (Grain LFSR in real impl)
        let round_constants = Self::generate_round_constants(num_constants);
        let mds_matrix = Self::generate_mds_matrix(t);

        Self {
            round_constants,
            mds_matrix,
        }
    }

    pub fn hash(&self, inputs: &[Fr]) -> Fr {
        assert!(
            inputs.len() < POSEIDON_WIDTH,
            "Input length must be < width"
        );

        let mut state = vec![Fr::ZERO; POSEIDON_WIDTH];
        for (i, input) in inputs.iter().enumerate() {
            state[i] = *input;
        }

        let t = POSEIDON_WIDTH;
        let r_f = POSEIDON_FULL_ROUNDS / 2;
        let r_p = POSEIDON_PARTIAL_ROUNDS;
        let mut round_ctr = 0;

        // First half of full rounds
        for _ in 0..r_f {
            self.add_round_constants(&mut state, round_ctr);
            self.full_sbox(&mut state);
            self.mds_mix(&mut state);
            round_ctr += t;
        }

        // Partial rounds
        for _ in 0..r_p {
            self.add_round_constants(&mut state, round_ctr);
            self.partial_sbox(&mut state);
            self.mds_mix(&mut state);
            round_ctr += t;
        }

        // Second half of full rounds
        for _ in 0..r_f {
            self.add_round_constants(&mut state, round_ctr);
            self.full_sbox(&mut state);
            self.mds_mix(&mut state);
            round_ctr += t;
        }

        state[0]
    }

    pub fn hash_two(&self, left: &Fr, right: &Fr) -> Fr {
        self.hash(&[*left, *right])
    }

    fn add_round_constants(&self, state: &mut [Fr], offset: usize) {
        for (i, s) in state.iter_mut().enumerate() {
            *s += self.round_constants[offset + i];
        }
    }

    fn full_sbox(&self, state: &mut [Fr]) {
        for s in state.iter_mut() {
            let s2 = *s * *s;
            let s4 = s2 * s2;
            *s = s4 * *s; // s^5
        }
    }

    fn partial_sbox(&self, state: &mut [Fr]) {
        let s = &mut state[0];
        let s2 = *s * *s;
        let s4 = s2 * s2;
        *s = s4 * *s;
    }

    fn mds_mix(&self, state: &mut [Fr]) {
        let t = state.len();
        let mut new_state = vec![Fr::ZERO; t];
        for i in 0..t {
            for j in 0..t {
                new_state[i] += self.mds_matrix[i][j] * state[j];
            }
        }
        state.copy_from_slice(&new_state);
    }

    fn generate_round_constants(count: usize) -> Vec<Fr> {
        use sha2::{Digest, Sha256};
        let mut constants = Vec::with_capacity(count);
        for i in 0..count {
            let mut hasher = Sha256::new();
            hasher.update(b"veil_poseidon_rc");
            hasher.update((i as u64).to_le_bytes());
            let hash = hasher.finalize();
            let val = Fr::from_le_bytes_mod_order(&hash);
            constants.push(val);
        }
        constants
    }

    fn generate_mds_matrix(t: usize) -> Vec<Vec<Fr>> {
        // Cauchy matrix construction (secure MDS)
        let mut matrix = vec![vec![Fr::ZERO; t]; t];
        let xs: Vec<Fr> = (0..t).map(|i| Fr::from((i + 1) as u64)).collect();
        let ys: Vec<Fr> = (0..t).map(|i| Fr::from((t + i + 1) as u64)).collect();
        for i in 0..t {
            for j in 0..t {
                matrix[i][j] = (xs[i] + ys[j]).inverse().unwrap();
            }
        }
        matrix
    }
}

impl Default for Poseidon {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic() {
        let poseidon = Poseidon::new();
        let input = [Fr::from(42u64), Fr::from(43u64)];
        let h1 = poseidon.hash(&input);
        let h2 = poseidon.hash(&input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_different_inputs_different_outputs() {
        let poseidon = Poseidon::new();
        let h1 = poseidon.hash(&[Fr::from(1u64), Fr::from(2u64)]);
        let h2 = poseidon.hash(&[Fr::from(1u64), Fr::from(3u64)]);
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_preimage_resistance_sanity() {
        let poseidon = Poseidon::new();
        let h = poseidon.hash(&[Fr::from(0u64), Fr::from(0u64)]);
        assert_ne!(h, Fr::ZERO);
    }
}
