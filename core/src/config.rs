use std::time::Duration;

pub const L: usize = 3;
pub const K: usize = 5;
pub const T: usize = 3;
pub const N_CREDIT: usize = 8;
pub const PACKET_SIZE: usize = 2048;
pub const HEADER_SIZE: usize = 400;
pub const PAYLOAD_SIZE: usize = PACKET_SIZE - HEADER_SIZE;

pub const EPOCH_DURATION: Duration = Duration::from_secs(86400);
pub const CREDIT_WINDOW: Duration = Duration::from_secs(24 * 86400);
pub const CREDIT_VALIDITY_WINDOWS: usize = 2;

pub const MU_LAYER: [f64; L] = [500.0, 1000.0, 500.0];

pub const LAMBDA_LOOP: f64 = 0.1;
pub const LAMBDA_DROP: f64 = 1.0 / 15.0;
pub const LAMBDA_PAYLOAD: f64 = 0.05;
pub const LAMBDA_TOTAL: f64 = LAMBDA_LOOP + LAMBDA_DROP + LAMBDA_PAYLOAD;
pub const LAMBDA_MOBILE_FACTOR: f64 = 0.25;

pub const K_VOUCH: usize = 3;
pub const B_MAX: usize = 3;
pub const VOUCH_DEPTH: usize = 2;
pub const GAMMA_CONTAGION: f64 = 0.5;
pub const GAMMA_DIRECT: f64 = 0.9;

pub const TAU: f64 = 0.05;
pub const F_MAX: f64 = 0.22;
pub const W_MIN: usize = 500;
pub const W_BOOTSTRAP: usize = 500;
pub const BOOTSTRAP_CREDITS: usize = 2;

pub const D_MAILBOXES: usize = 5;
pub const T_RETRIEVE: Duration = Duration::from_secs(30);
pub const MAX_STORE_DURATION: Duration = Duration::from_secs(7 * 86400);

pub const MERKLE_DEPTH: usize = 14;
pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_FULL_ROUNDS: usize = 8;
pub const POSEIDON_PARTIAL_ROUNDS: usize = 57;

pub const GOSSIP_FANOUT: usize = 8;
pub const REPUTATION_LAMBDA: f64 = 0.001;
pub const R_MIN: f64 = 0.3;

pub const CONSTRAINTS_PER_STEP: usize = 16_400;
pub const TARGET_FOLD_TIME_MS: u64 = 200;
pub const TARGET_COMPRESS_TIME_MS: u64 = 2000;
