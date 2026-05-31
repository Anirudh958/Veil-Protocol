use rand::RngCore;
use rand_chacha::ChaCha8Rng;

use crate::config::{LAMBDA_DROP, LAMBDA_LOOP, LAMBDA_MOBILE_FACTOR, LAMBDA_PAYLOAD};

/// Cover traffic scheduler: generates Poisson-distributed emission events.
///
/// Real messages REPLACE cover slots — they are NOT additive.
/// An observer must see constant-rate traffic regardless of actual sending.
#[derive(Clone, Debug)]
pub struct CoverTrafficScheduler {
    mobile_mode: bool,
    pending_real_shares: Vec<PendingShare>,
}

#[derive(Clone, Debug)]
pub struct PendingShare {
    pub data: Vec<u8>,
    pub path: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq)]
pub enum EmissionEvent {
    LoopCover,
    DropCover,
    PayloadCover,
    RealShare(usize), // index into pending_real_shares
}

impl CoverTrafficScheduler {
    pub fn new(mobile_mode: bool) -> Self {
        Self {
            mobile_mode,
            pending_real_shares: Vec::new(),
        }
    }

    pub fn queue_real_share(&mut self, share: PendingShare) {
        self.pending_real_shares.push(share);
    }

    pub fn has_pending_shares(&self) -> bool {
        !self.pending_real_shares.is_empty()
    }

    /// Sample next emission event. The Poisson process determines WHEN to emit;
    /// the type is determined by which process fires first (or by real share queue).
    ///
    /// Returns (delay_ms, event_type).
    pub fn next_emission<R: RngCore>(&mut self, rng: &mut R) -> (f64, EmissionEvent) {
        let factor = if self.mobile_mode {
            LAMBDA_MOBILE_FACTOR
        } else {
            1.0
        };

        let lambda_loop = LAMBDA_LOOP * factor;
        let lambda_drop = LAMBDA_DROP * factor;
        let lambda_payload = LAMBDA_PAYLOAD * factor;

        // Sample inter-arrival time for each process
        let t_loop = exponential_sample(lambda_loop, rng);
        let t_drop = exponential_sample(lambda_drop, rng);
        let t_payload = exponential_sample(lambda_payload, rng);

        // The next event is whichever fires first
        let (delay, cover_type) = if t_loop <= t_drop && t_loop <= t_payload {
            (t_loop, EmissionEvent::LoopCover)
        } else if t_drop <= t_payload {
            (t_drop, EmissionEvent::DropCover)
        } else {
            (t_payload, EmissionEvent::PayloadCover)
        };

        // If we have a real share queued, REPLACE the cover slot
        if !self.pending_real_shares.is_empty() {
            let idx = self.pending_real_shares.len() - 1;
            (delay, EmissionEvent::RealShare(idx))
        } else {
            (delay, cover_type)
        }
    }

    /// Acknowledge that a real share was emitted (remove from queue).
    pub fn acknowledge_emission(&mut self, idx: usize) {
        if idx < self.pending_real_shares.len() {
            self.pending_real_shares.remove(idx);
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending_real_shares.len()
    }
}

/// Sample from exponential distribution with rate λ.
/// Returns time in seconds.
fn exponential_sample<R: RngCore>(lambda: f64, rng: &mut R) -> f64 {
    let u: f64 = loop {
        let bits = rng.next_u64();
        let val = (bits as f64) / (u64::MAX as f64);
        if val > 0.0 && val < 1.0 {
            break val;
        }
    };
    -u.ln() / lambda
}

/// Sample mixing delay for a given layer.
pub fn sample_mixing_delay<R: RngCore>(layer: usize, rng: &mut R) -> f64 {
    let mu = crate::config::MU_LAYER[layer];
    let lambda = 1000.0 / mu; // Convert mean (ms) to rate (per second)
    exponential_sample(lambda, rng) * 1000.0 // Return in ms
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;

    #[test]
    fn test_exponential_distribution_mean() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let lambda = 0.217;
        let n = 100_000;

        let sum: f64 = (0..n).map(|_| exponential_sample(lambda, &mut rng)).sum();
        let mean = sum / n as f64;
        let expected = 1.0 / lambda;

        assert!(
            (mean - expected).abs() / expected < 0.02,
            "Mean {} deviates from expected {} by more than 2%",
            mean,
            expected
        );
    }

    #[test]
    fn test_real_shares_replace_cover() {
        let mut rng = ChaCha8Rng::seed_from_u64(43);
        let mut scheduler = CoverTrafficScheduler::new(false);

        // Without real shares, get cover events
        let (_, event) = scheduler.next_emission(&mut rng);
        assert!(matches!(
            event,
            EmissionEvent::LoopCover | EmissionEvent::DropCover | EmissionEvent::PayloadCover
        ));

        // With real share queued, it replaces the cover
        scheduler.queue_real_share(PendingShare {
            data: vec![1, 2, 3],
            path: vec![],
        });
        let (_, event) = scheduler.next_emission(&mut rng);
        assert!(matches!(event, EmissionEvent::RealShare(_)));
    }

    #[test]
    fn test_mobile_mode_slower_rate() {
        let mut rng = ChaCha8Rng::seed_from_u64(44);

        let mut full_delays = Vec::new();
        let mut sched = CoverTrafficScheduler::new(false);
        for _ in 0..10_000 {
            let (delay, _) = sched.next_emission(&mut rng);
            full_delays.push(delay);
        }

        let mut rng = ChaCha8Rng::seed_from_u64(44);
        let mut mobile_delays = Vec::new();
        let mut sched = CoverTrafficScheduler::new(true);
        for _ in 0..10_000 {
            let (delay, _) = sched.next_emission(&mut rng);
            mobile_delays.push(delay);
        }

        let full_mean: f64 = full_delays.iter().sum::<f64>() / full_delays.len() as f64;
        let mobile_mean: f64 = mobile_delays.iter().sum::<f64>() / mobile_delays.len() as f64;

        // Mobile should be ~4× slower (4× longer inter-arrival times)
        let ratio = mobile_mean / full_mean;
        assert!(
            (ratio - 4.0).abs() < 0.5,
            "Mobile/full ratio {} should be ~4.0",
            ratio
        );
    }

    #[test]
    fn test_mixing_delay_mean() {
        let mut rng = ChaCha8Rng::seed_from_u64(45);
        let n = 100_000;

        for layer in 0..3 {
            let sum: f64 = (0..n)
                .map(|_| sample_mixing_delay(layer, &mut rng))
                .sum();
            let mean = sum / n as f64;
            let expected = crate::config::MU_LAYER[layer];

            assert!(
                (mean - expected).abs() / expected < 0.02,
                "Layer {} mean {} deviates from expected {} ms",
                layer,
                mean,
                expected
            );
        }
    }
}
