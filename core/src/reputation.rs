use crate::config::{R_MIN, REPUTATION_LAMBDA};
use crate::penalty_log::PenaltyLog;
use crate::types::NodeId;

/// Reputation computation: R(n) = (1 - e^{-λ·k_n}) × Π_{p ∈ P_n}(1 - p.severity)
///
/// Growth (1 - e^{-λ·k}) is computed from locally-verified relay proofs.
/// Penalty factor comes from the CRDT (merged via set union).
///
/// Growth is NEVER merged between nodes. Each node counts only what it has
/// directly witnessed or verified via SNARK.
pub struct ReputationComputer {
    local_relay_counts: std::collections::HashMap<NodeId, u64>,
}

impl ReputationComputer {
    pub fn new() -> Self {
        Self {
            local_relay_counts: std::collections::HashMap::new(),
        }
    }

    pub fn record_verified_relay(&mut self, node_id: &NodeId) {
        *self.local_relay_counts.entry(node_id.clone()).or_default() += 1;
    }

    pub fn local_relay_count(&self, node_id: &NodeId) -> u64 {
        self.local_relay_counts.get(node_id).copied().unwrap_or(0)
    }

    pub fn compute_growth(&self, node_id: &NodeId) -> f64 {
        let k = self.local_relay_count(node_id) as f64;
        1.0 - (-REPUTATION_LAMBDA * k).exp()
    }

    pub fn compute_reputation(&self, node_id: &NodeId, penalty_log: &PenaltyLog) -> f64 {
        let growth = self.compute_growth(node_id);
        let penalty_factor = penalty_log.penalty_factor(node_id);
        growth * penalty_factor
    }

    pub fn is_reputable(&self, node_id: &NodeId, penalty_log: &PenaltyLog) -> bool {
        self.compute_reputation(node_id, penalty_log) >= R_MIN
    }
}

impl Default for ReputationComputer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::penalty_log::PenaltyLog;
    use crate::types::{Epoch, NodeId, PenaltyEvent, PenaltyEventId};

    fn node(id: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        NodeId(bytes)
    }

    #[test]
    fn test_zero_relays_zero_reputation() {
        let comp = ReputationComputer::new();
        let log = PenaltyLog::new();
        let n = node(1);
        assert_eq!(comp.compute_reputation(&n, &log), 0.0);
    }

    #[test]
    fn test_growth_monotonic() {
        let mut comp = ReputationComputer::new();
        let log = PenaltyLog::new();
        let n = node(1);

        let mut prev = 0.0;
        for _ in 0..1000 {
            comp.record_verified_relay(&n);
            let current = comp.compute_reputation(&n, &log);
            assert!(current >= prev);
            prev = current;
        }
    }

    #[test]
    fn test_growth_saturates() {
        let mut comp = ReputationComputer::new();
        let log = PenaltyLog::new();
        let n = node(1);

        for _ in 0..100_000 {
            comp.record_verified_relay(&n);
        }
        let r = comp.compute_reputation(&n, &log);
        assert!(r <= 1.0);
        assert!(r > 0.99);
    }

    #[test]
    fn test_penalty_reduces_reputation() {
        let mut comp = ReputationComputer::new();
        let n = node(1);
        for _ in 0..5000 {
            comp.record_verified_relay(&n);
        }

        let log_empty = PenaltyLog::new();
        let before = comp.compute_reputation(&n, &log_empty);

        let mut log = PenaltyLog::new();
        let mut eid = [0u8; 32];
        eid[0] = 1;
        log.insert(PenaltyEvent {
            event_id: PenaltyEventId(eid),
            target: n.clone(),
            severity: 0.5,
            epoch: Epoch(1),
            evidence_hash: [0u8; 32],
        });

        let after = comp.compute_reputation(&n, &log);
        assert!(after < before);
        assert!((after - before * 0.5).abs() < 1e-10);
    }

    #[test]
    fn test_r_min_threshold() {
        let mut comp = ReputationComputer::new();
        let log = PenaltyLog::new();
        let n = node(1);

        assert!(!comp.is_reputable(&n, &log));

        // R_MIN = 0.3, lambda = 0.001
        // 1 - e^{-0.001 * k} >= 0.3  =>  k >= -ln(0.7)/0.001 ≈ 357
        for _ in 0..357 {
            comp.record_verified_relay(&n);
        }
        assert!(comp.compute_reputation(&n, &log) >= R_MIN);
        assert!(comp.is_reputable(&n, &log));
    }
}
