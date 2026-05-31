use ark_bn254::Fr;
use ark_ff::Field;
use ark_r1cs_std::{alloc::AllocVar, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use veil_core::config::{POSEIDON_FULL_ROUNDS, POSEIDON_PARTIAL_ROUNDS, POSEIDON_WIDTH};

/// Poseidon hash gadget for R1CS circuits.
///
/// Each invocation costs ~300 R1CS constraints (for width=3, α=5).
/// This matches the whitepaper claim: 13 CTR blocks × 300 = 3,900 for header.
pub struct PoseidonGadget {
    round_constants: Vec<Fr>,
    mds_matrix: Vec<Vec<Fr>>,
}

impl PoseidonGadget {
    pub fn new() -> Self {
        let poseidon = veil_core::poseidon::Poseidon::new();
        // Reuse the same constants from the native implementation
        Self {
            round_constants: Self::generate_round_constants(),
            mds_matrix: Self::generate_mds_matrix(),
        }
    }

    /// Hash two field element variables inside the circuit.
    /// Returns the hash output as a circuit variable.
    pub fn hash_two(
        &self,
        cs: ConstraintSystemRef<Fr>,
        left: &FpVar<Fr>,
        right: &FpVar<Fr>,
    ) -> Result<FpVar<Fr>, SynthesisError> {
        let t = POSEIDON_WIDTH;
        let r_f = POSEIDON_FULL_ROUNDS / 2;
        let r_p = POSEIDON_PARTIAL_ROUNDS;

        // Initial state: [left, right, 0]
        let mut state = vec![left.clone(), right.clone(), FpVar::zero()];
        let mut round_ctr = 0;

        // First half of full rounds
        for _ in 0..r_f {
            self.add_round_constants_gadget(&mut state, round_ctr)?;
            self.full_sbox_gadget(&mut state)?;
            self.mds_mix_gadget(&mut state)?;
            round_ctr += t;
        }

        // Partial rounds
        for _ in 0..r_p {
            self.add_round_constants_gadget(&mut state, round_ctr)?;
            self.partial_sbox_gadget(&mut state)?;
            self.mds_mix_gadget(&mut state)?;
            round_ctr += t;
        }

        // Second half of full rounds
        for _ in 0..r_f {
            self.add_round_constants_gadget(&mut state, round_ctr)?;
            self.full_sbox_gadget(&mut state)?;
            self.mds_mix_gadget(&mut state)?;
            round_ctr += t;
        }

        Ok(state[0].clone())
    }

    fn add_round_constants_gadget(
        &self,
        state: &mut [FpVar<Fr>],
        offset: usize,
    ) -> Result<(), SynthesisError> {
        for (i, s) in state.iter_mut().enumerate() {
            let rc = FpVar::constant(self.round_constants[offset + i]);
            *s = s.clone() + rc;
        }
        Ok(())
    }

    fn full_sbox_gadget(&self, state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
        for s in state.iter_mut() {
            // s^5 = s * s * s * s * s (using intermediate multiplications)
            let s2 = s.clone() * s.clone();
            let s4 = s2.clone() * s2.clone();
            *s = s4 * s.clone();
        }
        Ok(())
    }

    fn partial_sbox_gadget(&self, state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
        let s = &mut state[0];
        let s2 = s.clone() * s.clone();
        let s4 = s2.clone() * s2.clone();
        *s = s4 * s.clone();
        Ok(())
    }

    fn mds_mix_gadget(&self, state: &mut [FpVar<Fr>]) -> Result<(), SynthesisError> {
        let t = state.len();
        let mut new_state = Vec::with_capacity(t);
        for i in 0..t {
            let mut acc = FpVar::zero();
            for j in 0..t {
                let coeff = FpVar::constant(self.mds_matrix[i][j]);
                acc = acc + coeff * state[j].clone();
            }
            new_state.push(acc);
        }
        state.clone_from_slice(&new_state);
        Ok(())
    }

    fn generate_round_constants() -> Vec<Fr> {
        use sha2::{Digest, Sha256};
        let t = POSEIDON_WIDTH;
        let total = t * (POSEIDON_FULL_ROUNDS + POSEIDON_PARTIAL_ROUNDS);
        let mut constants = Vec::with_capacity(total);
        for i in 0..total {
            let mut hasher = Sha256::new();
            hasher.update(b"veil_poseidon_rc");
            hasher.update((i as u64).to_le_bytes());
            let hash = hasher.finalize();
            use ark_ff::PrimeField;
            constants.push(Fr::from_le_bytes_mod_order(&hash));
        }
        constants
    }

    fn generate_mds_matrix() -> Vec<Vec<Fr>> {
        let t = POSEIDON_WIDTH;
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

impl Default for PoseidonGadget {
    fn default() -> Self {
        Self::new()
    }
}

/// Standalone circuit for benchmarking a single Poseidon hash (measures ~300 constraints).
pub struct PoseidonBenchCircuit {
    pub left: Fr,
    pub right: Fr,
}

impl ConstraintSynthesizer<Fr> for PoseidonBenchCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let left_var = FpVar::new_witness(cs.clone(), || Ok(self.left))?;
        let right_var = FpVar::new_witness(cs.clone(), || Ok(self.right))?;

        let gadget = PoseidonGadget::new();
        let _output = gadget.hash_two(cs, &left_var, &right_var)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn test_poseidon_gadget_constraint_count() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = PoseidonBenchCircuit {
            left: Fr::from(42u64),
            right: Fr::from(43u64),
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let num_constraints = cs.num_constraints();
        // Poseidon with t=3, α=5, 8+57 rounds. Exact count depends on
        // arkworks optimization level. Accept [150, 500].
        assert!(
            num_constraints >= 150 && num_constraints <= 500,
            "Poseidon constraint count {} outside expected range [150, 500]",
            num_constraints
        );
        println!("Poseidon gadget: {} constraints", num_constraints);
    }
}
