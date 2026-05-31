use crate::config::N_CREDIT;
use crate::types::{AffinePoint, CreditProof, Epoch, Receipt, RelayWitness, Scalar};

/// Credit state machine: tracks relay work and manages proof lifecycle.
///
/// States: Accumulating → Ready → Consumed
///
/// - Accumulating: collecting relay receipts (< N_CREDIT)
/// - Ready: N_CREDIT receipts collected, proof compressed and cached
/// - Consumed: proof was attached to a message and verified
#[derive(Clone, Debug)]
pub struct CreditAccumulator {
    witnesses: Vec<RelayWitness>,
    cached_proof: Option<CreditProof>,
    consumed: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreditState {
    Accumulating { count: usize },
    Ready,
    Consumed,
}

impl CreditAccumulator {
    pub fn new() -> Self {
        Self {
            witnesses: Vec::with_capacity(N_CREDIT),
            cached_proof: None,
            consumed: false,
        }
    }

    pub fn state(&self) -> CreditState {
        if self.consumed {
            CreditState::Consumed
        } else if self.cached_proof.is_some() {
            CreditState::Ready
        } else {
            CreditState::Accumulating {
                count: self.witnesses.len(),
            }
        }
    }

    pub fn add_witness(&mut self, witness: RelayWitness) -> Result<(), CreditError> {
        if self.consumed {
            return Err(CreditError::AlreadyConsumed);
        }
        if self.witnesses.len() >= N_CREDIT {
            return Err(CreditError::AlreadyFull);
        }

        // Verify distinct issuers
        let new_pk = witness.receipt.issuer_pk;
        for existing in &self.witnesses {
            if existing.receipt.issuer_pk == new_pk {
                return Err(CreditError::DuplicateIssuer);
            }
        }

        self.witnesses.push(witness);

        if self.witnesses.len() == N_CREDIT {
            // In real impl: trigger background Groth16 compression here
            // For now, mark as compressible
        }

        Ok(())
    }

    pub fn witnesses_collected(&self) -> usize {
        self.witnesses.len()
    }

    pub fn is_ready_to_compress(&self) -> bool {
        self.witnesses.len() == N_CREDIT && self.cached_proof.is_none() && !self.consumed
    }

    /// Called after background Groth16 compression completes.
    /// In real impl, this receives the proof from the proving thread.
    pub fn set_compressed_proof(&mut self, proof: CreditProof) {
        assert!(self.witnesses.len() == N_CREDIT);
        self.cached_proof = Some(proof);
    }

    /// Consume the credit (attach to outbound message).
    /// Returns the proof to attach, or error if not ready.
    pub fn consume(&mut self) -> Result<CreditProof, CreditError> {
        if self.consumed {
            return Err(CreditError::AlreadyConsumed);
        }
        match self.cached_proof.take() {
            Some(proof) => {
                self.consumed = true;
                Ok(proof)
            }
            None => Err(CreditError::NotReady),
        }
    }

    pub fn get_receipt_hashes(&self) -> Vec<Scalar> {
        self.witnesses.iter().map(|w| w.receipt.value).collect()
    }

    pub fn get_witnesses(&self) -> &[RelayWitness] {
        &self.witnesses
    }
}

impl Default for CreditAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages multiple credit accumulators (pipeline: while one is consumed,
/// the next is accumulating).
pub struct CreditManager {
    current: CreditAccumulator,
    pipeline: Vec<CreditAccumulator>,
}

impl CreditManager {
    pub fn new() -> Self {
        Self {
            current: CreditAccumulator::new(),
            pipeline: Vec::new(),
        }
    }

    pub fn add_relay_witness(&mut self, witness: RelayWitness) -> Result<(), CreditError> {
        match self.current.add_witness(witness.clone()) {
            Ok(()) => Ok(()),
            Err(CreditError::AlreadyFull) | Err(CreditError::AlreadyConsumed) => {
                self.pipeline.push(std::mem::take(&mut self.current));
                self.current = CreditAccumulator::new();
                self.current.add_witness(witness)
            }
            Err(e) => Err(e),
        }
    }

    pub fn ready_credits(&self) -> usize {
        let current_ready = if self.current.state() == CreditState::Ready {
            1
        } else {
            0
        };
        let pipeline_ready = self
            .pipeline
            .iter()
            .filter(|a| a.state() == CreditState::Ready)
            .count();
        current_ready + pipeline_ready
    }

    pub fn can_send(&self) -> bool {
        self.ready_credits() > 0
    }
}

impl Default for CreditManager {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CreditError {
    #[error("credit already consumed")]
    AlreadyConsumed,
    #[error("accumulator already has N_CREDIT witnesses")]
    AlreadyFull,
    #[error("duplicate receipt issuer")]
    DuplicateIssuer,
    #[error("credit proof not yet ready (not compressed)")]
    NotReady,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ec::{AffineRepr, Group};
    use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
    use ark_ff::UniformRand;
    use rand::SeedableRng;

    fn make_witness(i: u8) -> RelayWitness {
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(i as u64);
        let sk = ark_ed_on_bn254::Fr::rand(&mut rng);
        let pk: AffinePoint = (EdwardsProjective::generator() * sk).into();

        RelayWitness {
            packet_hash: [i; 32],
            receipt: Receipt {
                value: Scalar::rand(&mut rng),
                issuer_pk: pk,
                epoch: Epoch(1),
                packet_hash: [i; 32],
            },
            merkle_path: vec![Scalar::rand(&mut rng); 14],
            merkle_indices: vec![false; 14],
        }
    }

    #[test]
    fn test_accumulation_lifecycle() {
        let mut acc = CreditAccumulator::new();
        assert_eq!(
            acc.state(),
            CreditState::Accumulating { count: 0 }
        );

        for i in 0..N_CREDIT {
            acc.add_witness(make_witness(i as u8)).unwrap();
            if i < N_CREDIT - 1 {
                assert_eq!(
                    acc.state(),
                    CreditState::Accumulating { count: i + 1 }
                );
            }
        }

        assert!(acc.is_ready_to_compress());

        // Simulate compression
        acc.set_compressed_proof(CreditProof {
            proof_bytes: vec![0u8; 128],
            nullifier: Scalar::from(1u64),
            epoch: Epoch(1),
            verifier_pk: EdwardsProjective::generator().into(),
        });

        assert_eq!(acc.state(), CreditState::Ready);

        let proof = acc.consume().unwrap();
        assert_eq!(acc.state(), CreditState::Consumed);
        assert!(!proof.proof_bytes.is_empty());
    }

    #[test]
    fn test_duplicate_issuer_rejected() {
        let mut acc = CreditAccumulator::new();
        let w = make_witness(1);
        acc.add_witness(w.clone()).unwrap();

        let result = acc.add_witness(w);
        assert_eq!(result.unwrap_err(), CreditError::DuplicateIssuer);
    }

    #[test]
    fn test_cannot_consume_twice() {
        let mut acc = CreditAccumulator::new();
        for i in 0..N_CREDIT as u8 {
            acc.add_witness(make_witness(i)).unwrap();
        }
        acc.set_compressed_proof(CreditProof {
            proof_bytes: vec![0u8; 128],
            nullifier: Scalar::from(1u64),
            epoch: Epoch(1),
            verifier_pk: EdwardsProjective::generator().into(),
        });

        acc.consume().unwrap();
        assert_eq!(acc.consume().unwrap_err(), CreditError::AlreadyConsumed);
    }

    #[test]
    fn test_cannot_consume_before_ready() {
        let mut acc = CreditAccumulator::new();
        acc.add_witness(make_witness(1)).unwrap();
        assert_eq!(acc.consume().unwrap_err(), CreditError::NotReady);
    }
}
