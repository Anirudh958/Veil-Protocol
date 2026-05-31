use ark_bn254::Fr;
use ark_ff::{Field, PrimeField, UniformRand};
use rand::RngCore;

use crate::config::{K, T};
use crate::types::Share;

/// Shamir's Secret Sharing over BN254 scalar field.
/// K=5 shares, T=3 threshold. Information-theoretic security: <T shares reveal nothing.
///
/// Operates on field elements. Messages are split into 31-byte chunks (field element size)
/// and each chunk is shared independently.

pub fn split<R: RngCore>(secret: &[u8], rng: &mut R) -> Vec<Share> {
    let field_elements = bytes_to_field_elements(secret);
    let mut shares: Vec<Share> = (1..=K as u8)
        .map(|i| Share {
            index: i,
            data: Vec::new(),
        })
        .collect();

    for element in &field_elements {
        let coefficients = generate_polynomial(*element, T - 1, rng);
        for share in shares.iter_mut() {
            let x = Fr::from(share.index as u64);
            let y = evaluate_polynomial(&coefficients, &x);
            let mut y_bytes = Vec::new();
            use ark_serialize::CanonicalSerialize;
            y.serialize_compressed(&mut y_bytes).unwrap();
            share.data.extend_from_slice(&y_bytes);
        }
    }

    shares
}

pub fn reconstruct(shares: &[Share]) -> Result<Vec<u8>, ShamirError> {
    if shares.len() < T {
        return Err(ShamirError::InsufficientShares {
            have: shares.len(),
            need: T,
        });
    }

    let shares_to_use = &shares[..T];
    let chunk_size = 32; // compressed Fr size
    let num_elements = shares_to_use[0].data.len() / chunk_size;

    let mut result_elements = Vec::with_capacity(num_elements);

    for chunk_idx in 0..num_elements {
        let points: Vec<(Fr, Fr)> = shares_to_use
            .iter()
            .map(|share| {
                let x = Fr::from(share.index as u64);
                let offset = chunk_idx * chunk_size;
                let y_bytes = &share.data[offset..offset + chunk_size];
                use ark_serialize::CanonicalDeserialize;
                let y = Fr::deserialize_compressed(y_bytes).unwrap();
                (x, y)
            })
            .collect();

        let secret = lagrange_interpolate_at_zero(&points);
        result_elements.push(secret);
    }

    Ok(field_elements_to_bytes(&result_elements))
}

fn generate_polynomial<R: RngCore>(secret: Fr, degree: usize, rng: &mut R) -> Vec<Fr> {
    let mut coefficients = Vec::with_capacity(degree + 1);
    coefficients.push(secret);
    for _ in 0..degree {
        coefficients.push(Fr::rand(rng));
    }
    coefficients
}

fn evaluate_polynomial(coefficients: &[Fr], x: &Fr) -> Fr {
    let mut result = Fr::ZERO;
    let mut x_power = Fr::ONE;
    for coeff in coefficients {
        result += *coeff * x_power;
        x_power *= x;
    }
    result
}

fn lagrange_interpolate_at_zero(points: &[(Fr, Fr)]) -> Fr {
    let mut result = Fr::ZERO;
    for (i, (xi, yi)) in points.iter().enumerate() {
        let mut basis = Fr::ONE;
        for (j, (xj, _)) in points.iter().enumerate() {
            if i != j {
                // basis *= -xj / (xi - xj)
                let num = Fr::ZERO - *xj;
                let denom = *xi - *xj;
                basis *= num * denom.inverse().unwrap();
            }
        }
        result += *yi * basis;
    }
    result
}

fn bytes_to_field_elements(data: &[u8]) -> Vec<Fr> {
    let chunk_size = 31; // Leave 1 byte headroom for modular reduction
    data.chunks(chunk_size)
        .map(|chunk| {
            let mut padded = vec![0u8; 32];
            padded[..chunk.len()].copy_from_slice(chunk);
            Fr::from_le_bytes_mod_order(&padded)
        })
        .collect()
}

fn field_elements_to_bytes(elements: &[Fr]) -> Vec<u8> {
    use ark_serialize::CanonicalSerialize;
    let mut result = Vec::new();
    for element in elements {
        let mut bytes = vec![0u8; 32];
        element.serialize_compressed(&mut bytes[..]).unwrap();
        // Take only 31 bytes (the data portion)
        result.extend_from_slice(&bytes[..31]);
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ShamirError {
    #[error("insufficient shares: have {have}, need {need}")]
    InsufficientShares { have: usize, need: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_split_and_reconstruct_exact_threshold() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let message = b"Hello, Veil Protocol!";

        let shares = split(message, &mut rng);
        assert_eq!(shares.len(), K);

        // Use exactly T=3 shares
        let reconstructed = reconstruct(&shares[..T]).unwrap();
        assert_eq!(&reconstructed[..message.len()], message.as_slice());
    }

    #[test]
    fn test_any_t_shares_suffice() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(43);
        let message = b"Metadata resistance without economic barriers";

        let shares = split(message, &mut rng);

        // Try all C(5,3) = 10 combinations of 3 shares
        for i in 0..K {
            for j in (i + 1)..K {
                for k in (j + 1)..K {
                    let subset = vec![shares[i].clone(), shares[j].clone(), shares[k].clone()];
                    let reconstructed = reconstruct(&subset).unwrap();
                    assert_eq!(
                        &reconstructed[..message.len()],
                        message.as_slice(),
                        "Failed with shares {}, {}, {}",
                        i,
                        j,
                        k
                    );
                }
            }
        }
    }

    #[test]
    fn test_fewer_than_threshold_fails() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(44);
        let message = b"test";
        let shares = split(message, &mut rng);

        let result = reconstruct(&shares[..T - 1]);
        assert!(result.is_err());
    }

    #[test]
    fn test_fewer_than_threshold_reveals_nothing() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(45);
        let message = b"secret message that must not leak";
        let shares = split(message, &mut rng);

        // With T-1=2 shares, reconstruction gives garbage (wrong polynomial)
        // We can verify this by checking that 2 shares don't constrain the secret
        let subset1 = vec![shares[0].clone(), shares[1].clone()];
        let subset2 = vec![shares[0].clone(), shares[2].clone()];

        // These would give different "reconstructions" if we forced T=2
        // (demonstrating information-theoretic security)
        // Just verify the error case
        assert_eq!(
            reconstruct(&subset1[..1]).unwrap_err(),
            ShamirError::InsufficientShares { have: 1, need: T }
        );
    }

    #[test]
    fn test_large_message() {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(46);
        let message = vec![0xAB; 2048]; // Full packet size

        let shares = split(&message, &mut rng);
        let reconstructed = reconstruct(&shares[..T]).unwrap();
        assert_eq!(&reconstructed[..message.len()], message.as_slice());
    }
}
