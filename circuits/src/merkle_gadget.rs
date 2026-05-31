use ark_bn254::Fr;
use ark_r1cs_std::{alloc::AllocVar, eq::EqGadget, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};

use crate::poseidon_gadget::PoseidonGadget;
use veil_core::config::MERKLE_DEPTH;

/// Merkle membership proof gadget using Poseidon hash.
///
/// Depth-14 tree supports up to 16,384 nodes.
/// Cost: 14 × ~300 = ~4,200 R1CS constraints.
pub struct MerkleGadget;

impl MerkleGadget {
    /// Verify that `leaf` is a member of the tree with `root`, given `path` and `indices`.
    pub fn verify_membership(
        cs: ConstraintSystemRef<Fr>,
        leaf: &FpVar<Fr>,
        path: &[FpVar<Fr>],
        indices: &[Boolean<Fr>],
        root: &FpVar<Fr>,
    ) -> Result<(), SynthesisError> {
        assert_eq!(path.len(), MERKLE_DEPTH);
        assert_eq!(indices.len(), MERKLE_DEPTH);

        let poseidon = PoseidonGadget::new();
        let mut current = leaf.clone();

        for i in 0..MERKLE_DEPTH {
            let sibling = &path[i];
            let is_right = &indices[i];

            // If is_right: hash(sibling, current), else: hash(current, sibling)
            let left = is_right.select(sibling, &current)?;
            let right = is_right.select(&current, sibling)?;

            current = poseidon.hash_two(cs.clone(), &left, &right)?;
        }

        current.enforce_equal(root)?;
        Ok(())
    }
}

/// Standalone circuit for benchmarking Merkle proof verification.
pub struct MerkleBenchCircuit {
    pub leaf: Fr,
    pub path: Vec<Fr>,
    pub indices: Vec<bool>,
    pub root: Fr,
}

impl ConstraintSynthesizer<Fr> for MerkleBenchCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let leaf_var = FpVar::new_witness(cs.clone(), || Ok(self.leaf))?;
        let root_var = FpVar::new_input(cs.clone(), || Ok(self.root))?;

        let path_vars: Vec<FpVar<Fr>> = self
            .path
            .iter()
            .map(|p| FpVar::new_witness(cs.clone(), || Ok(*p)))
            .collect::<Result<_, _>>()?;

        let index_vars: Vec<Boolean<Fr>> = self
            .indices
            .iter()
            .map(|b| Boolean::new_witness(cs.clone(), || Ok(*b)))
            .collect::<Result<_, _>>()?;

        MerkleGadget::verify_membership(cs, &leaf_var, &path_vars, &index_vars, &root_var)?;

        Ok(())
    }
}

/// Native Merkle tree construction for testing.
pub fn build_merkle_tree(leaves: &[Fr]) -> (Fr, Vec<Vec<Fr>>) {
    let poseidon = veil_core::poseidon::Poseidon::new();
    let n = 1 << MERKLE_DEPTH; // Pad to power of 2
    let mut layer: Vec<Fr> = leaves.to_vec();
    layer.resize(n, Fr::from(0u64));

    let mut layers = vec![layer.clone()];

    while layer.len() > 1 {
        let mut next_layer = Vec::with_capacity(layer.len() / 2);
        for chunk in layer.chunks(2) {
            next_layer.push(poseidon.hash_two(&chunk[0], &chunk[1]));
        }
        layers.push(next_layer.clone());
        layer = next_layer;
    }

    (layer[0], layers)
}

/// Get Merkle proof for a leaf at given index.
pub fn get_merkle_proof(layers: &[Vec<Fr>], leaf_index: usize) -> (Vec<Fr>, Vec<bool>) {
    let mut path = Vec::with_capacity(MERKLE_DEPTH);
    let mut indices = Vec::with_capacity(MERKLE_DEPTH);
    let mut idx = leaf_index;

    for layer in layers.iter().take(MERKLE_DEPTH) {
        let is_right = idx % 2 == 1;
        let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
        let sibling = if sibling_idx < layer.len() {
            layer[sibling_idx]
        } else {
            Fr::from(0u64)
        };
        path.push(sibling);
        indices.push(is_right);
        idx /= 2;
    }

    (path, indices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::UniformRand;
    use ark_relations::r1cs::ConstraintSystem;
    use rand::SeedableRng;

    #[test]
    fn test_merkle_constraint_count() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let leaves: Vec<Fr> = (0..100).map(|_| Fr::rand(&mut rng)).collect();

        let (root, layers) = build_merkle_tree(&leaves);
        let (path, indices) = get_merkle_proof(&layers, 7);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let circuit = MerkleBenchCircuit {
            leaf: leaves[7],
            path,
            indices,
            root,
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        let num_constraints = cs.num_constraints();
        // 14 levels × Poseidon per level. Accept [2000, 7000].
        assert!(
            num_constraints >= 2000 && num_constraints <= 7000,
            "Merkle proof constraint count {} outside expected range [2000, 7000]",
            num_constraints
        );
        println!("Merkle gadget (depth {}): {} constraints", MERKLE_DEPTH, num_constraints);
    }

    #[test]
    fn test_merkle_valid_proof_satisfies() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(43);
        let leaves: Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();
        let (root, layers) = build_merkle_tree(&leaves);

        for idx in [0, 7, 25, 49] {
            let (path, indices) = get_merkle_proof(&layers, idx);
            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = MerkleBenchCircuit {
                leaf: leaves[idx],
                path,
                indices,
                root,
            };
            circuit.generate_constraints(cs.clone()).unwrap();
            assert!(cs.is_satisfied().unwrap(), "Failed for leaf index {}", idx);
        }
    }

    #[test]
    fn test_merkle_invalid_leaf_fails() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(44);
        let leaves: Vec<Fr> = (0..50).map(|_| Fr::rand(&mut rng)).collect();
        let (root, layers) = build_merkle_tree(&leaves);
        let (path, indices) = get_merkle_proof(&layers, 5);

        let cs = ConstraintSystem::<Fr>::new_ref();
        let wrong_leaf = Fr::from(999999u64);
        let circuit = MerkleBenchCircuit {
            leaf: wrong_leaf,
            path,
            indices,
            root,
        };
        circuit.generate_constraints(cs.clone()).unwrap();
        assert!(!cs.is_satisfied().unwrap());
    }
}
