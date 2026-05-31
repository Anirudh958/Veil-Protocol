use ark_bn254::Fr as BN254Fr;
use ark_ed_on_bn254::{EdwardsAffine, EdwardsProjective};
use serde::{Deserialize, Serialize};

/// BN254 scalar field — used for Poseidon, SNARKs, and as the base field
/// of BabyJubjub (which is embedded in BN254).
pub type Scalar = BN254Fr;
pub type Point = EdwardsProjective;
pub type AffinePoint = EdwardsAffine;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(pub [u8; 32]);

/// Key pair for BabyJubjub. The secret key is in the curve's scalar field (EdFr),
/// which is different from BN254's scalar field (used for Poseidon/SNARKs).
#[derive(Clone, Debug)]
pub struct KeyPair {
    pub secret: ark_ed_on_bn254::Fr,
    pub public: AffinePoint,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Epoch(pub u64);

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PenaltyEventId(pub [u8; 32]);

#[derive(Clone, Debug, PartialEq)]
pub struct PenaltyEvent {
    pub event_id: PenaltyEventId,
    pub target: NodeId,
    pub severity: f64,
    pub epoch: Epoch,
    pub evidence_hash: [u8; 32],
}

impl Eq for PenaltyEvent {}
impl std::hash::Hash for PenaltyEvent {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.event_id.hash(state);
    }
}

#[derive(Clone, Debug)]
pub struct Receipt {
    pub value: Scalar,
    pub issuer_pk: AffinePoint,
    pub epoch: Epoch,
    pub packet_hash: [u8; 32],
}

#[derive(Clone, Debug)]
pub struct RelayWitness {
    pub packet_hash: [u8; 32],
    pub receipt: Receipt,
    pub merkle_path: Vec<Scalar>,
    pub merkle_indices: Vec<bool>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodePhase {
    Bootstrap { relays_completed: usize },
    Active { layer: usize },
}

#[derive(Clone, Debug)]
pub struct CreditProof {
    pub proof_bytes: Vec<u8>,
    pub nullifier: Scalar,
    pub epoch: Epoch,
    pub verifier_pk: AffinePoint,
}

#[derive(Clone, Debug)]
pub struct SphinxPacket {
    pub header: [u8; 400],
    pub payload: [u8; 1648],
}

#[derive(Clone, Debug)]
pub struct Share {
    pub index: u8,
    pub data: Vec<u8>,
}
