use std::collections::{HashMap, HashSet};

use crate::types::{NodeId, PenaltyEvent, PenaltyEventId};

/// Penalty-Log CRDT: Resolution to the Growth-Isolation Impossibility (Theorem 6).
///
/// Merge = set union of penalty events. Growth is NEVER merged — it is computed
/// locally from independently-verified relay proofs.
///
/// Properties:
/// - Commutative: merge(A, B) == merge(B, A)
/// - Associative: merge(merge(A, B), C) == merge(A, merge(B, C))
/// - Idempotent: merge(A, A) == A
/// - Inflation resistant: penalties can only decrease reputation
/// - Deflation resistant: no stale state can decrease growth (growth is unmerged)
#[derive(Clone, Debug, Default)]
pub struct PenaltyLog {
    penalties: HashMap<NodeId, HashSet<PenaltyEventId>>,
    events: HashMap<PenaltyEventId, PenaltyEvent>,
}

impl PenaltyLog {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, event: PenaltyEvent) {
        let id = event.event_id.clone();
        let target = event.target.clone();
        self.events.insert(id.clone(), event);
        self.penalties.entry(target).or_default().insert(id);
    }

    pub fn merge(&mut self, other: &PenaltyLog) {
        for (node_id, event_ids) in &other.penalties {
            let entry = self.penalties.entry(node_id.clone()).or_default();
            for id in event_ids {
                if !entry.contains(id) {
                    entry.insert(id.clone());
                    if let Some(event) = other.events.get(id) {
                        self.events.insert(id.clone(), event.clone());
                    }
                }
            }
        }
    }

    pub fn get_penalties(&self, node_id: &NodeId) -> Vec<&PenaltyEvent> {
        self.penalties
            .get(node_id)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| self.events.get(id))
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn penalty_factor(&self, node_id: &NodeId) -> f64 {
        self.get_penalties(node_id)
            .iter()
            .map(|p| 1.0 - p.severity)
            .product()
    }

    pub fn contains_event(&self, event_id: &PenaltyEventId) -> bool {
        self.events.contains_key(event_id)
    }

    pub fn event_count(&self) -> usize {
        self.events.len()
    }

    pub fn all_events(&self) -> impl Iterator<Item = &PenaltyEvent> {
        self.events.values()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Epoch;

    fn make_penalty(id: u8, target: &NodeId, severity: f64) -> PenaltyEvent {
        let mut event_id = [0u8; 32];
        event_id[0] = id;
        PenaltyEvent {
            event_id: PenaltyEventId(event_id),
            target: target.clone(),
            severity,
            epoch: Epoch(1),
            evidence_hash: [0u8; 32],
        }
    }

    fn node(id: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        NodeId(bytes)
    }

    #[test]
    fn test_commutativity() {
        let n = node(1);
        let p1 = make_penalty(1, &n, 0.3);
        let p2 = make_penalty(2, &n, 0.5);

        let mut log_a = PenaltyLog::new();
        log_a.insert(p1.clone());
        let mut log_b = PenaltyLog::new();
        log_b.insert(p2.clone());

        let mut merged_ab = log_a.clone();
        merged_ab.merge(&log_b);

        let mut merged_ba = log_b.clone();
        merged_ba.merge(&log_a);

        let factor_ab = merged_ab.penalty_factor(&n);
        let factor_ba = merged_ba.penalty_factor(&n);
        assert!((factor_ab - factor_ba).abs() < 1e-10);
    }

    #[test]
    fn test_associativity() {
        let n = node(1);
        let p1 = make_penalty(1, &n, 0.2);
        let p2 = make_penalty(2, &n, 0.3);
        let p3 = make_penalty(3, &n, 0.4);

        let mut a = PenaltyLog::new();
        a.insert(p1);
        let mut b = PenaltyLog::new();
        b.insert(p2);
        let mut c = PenaltyLog::new();
        c.insert(p3);

        // (A merge B) merge C
        let mut ab = a.clone();
        ab.merge(&b);
        let mut abc_left = ab;
        abc_left.merge(&c);

        // A merge (B merge C)
        let mut bc = b.clone();
        bc.merge(&c);
        let mut abc_right = a.clone();
        abc_right.merge(&bc);

        let f_left = abc_left.penalty_factor(&n);
        let f_right = abc_right.penalty_factor(&n);
        assert!((f_left - f_right).abs() < 1e-10);
    }

    #[test]
    fn test_idempotency() {
        let n = node(1);
        let p1 = make_penalty(1, &n, 0.5);

        let mut log = PenaltyLog::new();
        log.insert(p1);

        let before = log.penalty_factor(&n);
        let clone = log.clone();
        log.merge(&clone);
        let after = log.penalty_factor(&n);

        assert!((before - after).abs() < 1e-10);
        assert_eq!(log.event_count(), 1);
    }

    #[test]
    fn test_penalties_only_decrease_reputation() {
        let n = node(1);

        let mut log = PenaltyLog::new();
        assert_eq!(log.penalty_factor(&n), 1.0);

        log.insert(make_penalty(1, &n, 0.3));
        assert!(log.penalty_factor(&n) < 1.0);

        let before = log.penalty_factor(&n);
        log.insert(make_penalty(2, &n, 0.2));
        assert!(log.penalty_factor(&n) < before);
    }

    #[test]
    fn test_merge_order_independence_many_events() {
        let n = node(1);
        let events: Vec<PenaltyEvent> = (0..20)
            .map(|i| make_penalty(i, &n, 0.05 + (i as f64) * 0.02))
            .collect();

        use rand::seq::SliceRandom;
        use rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);

        let mut results = Vec::new();
        for _ in 0..50 {
            let mut shuffled = events.clone();
            shuffled.shuffle(&mut rng);

            let mut log = PenaltyLog::new();
            for e in shuffled {
                log.insert(e);
            }
            results.push(log.penalty_factor(&n));
        }

        let first = results[0];
        for r in &results[1..] {
            assert!(
                (first - r).abs() < 1e-10,
                "Merge order dependence detected: {} vs {}",
                first,
                r
            );
        }
    }
}
