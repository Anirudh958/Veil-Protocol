"""
Monte Carlo Simulation: Constructive Adversary Bound (Theorem 11)
Veil Protocol — PETS 2027

Validates: P(deanon) <= C(K,T) * f^(L*T) with hypergeometric correction.

Simulates message sends across varying adversary fractions f,
measuring empirical deanonymization rate vs. theoretical upper bound.
"""

import numpy as np
from math import comb, log2
from collections import defaultdict
import json
import sys

# Protocol parameters
L = 3          # Mix layers
K = 5          # Total shares per message
T = 3          # Reconstruction threshold
N_TOTAL = 5000 # Total network nodes

# Adversary fractions to test
F_VALUES = [0.05, 0.08, 0.10, 0.12, 0.15, 0.18, 0.20, 0.22]

# Use higher trial counts for larger f where events are more likely
def get_trials(f):
    """More trials where the bound is larger to reduce statistical noise."""
    if f >= 0.15:
        return 10_000_000
    elif f >= 0.12:
        return 2_000_000
    else:
        return 500_000


def theoretical_bound(f, N_l, L, K, T):
    """
    Compute theoretical upper bound on P(deanon).

    Simple bound: C(K,T) * f^(L*T) — assumes perfect independence.
    Conservative bound: accounts for sampling without replacement within layers
    across T shares. Since adversarial nodes are shared across shares (same pool),
    the actual probability is slightly HIGHER than the independent assumption.

    Conservative formula: C(K,T) * prod_{j=0}^{T-1} prod_{l=0}^{L-1} (A_l / N_l)
    where A_l = adversary count in layer l. This equals C(K,T) * f^(L*T) when
    shares sample independently WITH replacement (our case, since N_l >> K).

    For a true upper bound we add a correlation correction:
    bound = C(K,T) * f^(L*T) * (1 + T*(T-1)/(2*N_l))
    which accounts for birthday-collision positive covariance.
    """
    simple = comb(K, T) * (f ** (L * T))

    # Correlation correction for finite layer size (birthday bound on T shares)
    correction = 1.0 + T * (T - 1) / (2.0 * N_l)
    conservative = simple * correction

    return simple, conservative


def simulate_batch(N_l, f, L, K, T, trials):
    """
    Vectorized simulation: for each trial, sample K paths (each L hops),
    check if >= T paths are fully adversarial.
    """
    n_adversary = int(f * N_l)

    # For each trial, for each share (K), for each layer (L),
    # sample a random node and check if it's adversarial (< n_adversary)
    # Shape: (trials, K, L)
    nodes = np.random.randint(0, N_l, size=(trials, K, L))

    # A node is adversarial if its index < n_adversary
    is_adversarial = nodes < n_adversary  # (trials, K, L) boolean

    # A path is fully compromised if ALL L hops are adversarial
    path_compromised = is_adversarial.all(axis=2)  # (trials, K) boolean

    # Message is deanonymized if >= T paths are compromised
    compromised_count = path_compromised.sum(axis=1)  # (trials,)
    deanonymized = compromised_count >= T

    return deanonymized.sum()


def compute_entropy_contribution(f, N, L):
    """Expected entropy: (1 - f^(L-1)) * log2(f * N)"""
    if f * N < 1:
        return 0.0
    return (1 - f**(L-1)) * log2(f * N)


def run_simulation():
    """Run full Monte Carlo simulation across all adversary fractions."""
    N_l = N_TOTAL // L  # Nodes per layer

    results = []

    print(f"Veil Protocol: Constructive Adversary Bound Monte Carlo")
    print(f"Parameters: N={N_TOTAL}, L={L}, K={K}, T={T}, N_l={N_l}")
    print(f"{'='*90}")
    print(f"{'f':>6} | {'Trials':>10} | {'Empirical P(deanon)':>20} | {'Conservative Bound':>20} | "
          f"{'Ratio emp/bound':>15} | {'Bound?':>7} | {'Entropy':>8}")
    print(f"{'-'*90}")

    for f in F_VALUES:
        trials = get_trials(f)
        deanon_count = simulate_batch(N_l, f, L, K, T, trials)

        empirical_rate = deanon_count / trials
        simple_bound, conservative_bound = theoretical_bound(f, N_l, L, K, T)

        # Bound check: Poisson hypothesis test.
        # H0: true rate <= conservative_bound. Reject at α=0.05 only if
        # observing this many events is extremely unlikely under H0.
        if deanon_count == 0:
            ratio = 0.0
            bound_holds = True
        else:
            ratio = empirical_rate / conservative_bound
            # Expected events if true rate = conservative bound
            expected_under_h0 = conservative_bound * trials
            # One-sided Poisson test: P(X >= observed | lambda = expected)
            from scipy.stats import poisson
            p_value = 1.0 - poisson.cdf(deanon_count - 1, expected_under_h0)
            # Bound holds unless we can reject H0 at 5% significance
            bound_holds = p_value >= 0.05

        entropy = compute_entropy_contribution(f, N_TOTAL, L)

        results.append({
            'f': f,
            'trials': trials,
            'deanon_count': int(deanon_count),
            'empirical_deanon_rate': float(empirical_rate),
            'theoretical_simple': simple_bound,
            'theoretical_conservative': conservative_bound,
            'ratio': float(ratio),
            'bound_holds': bool(bound_holds),
            'entropy_bits': entropy,
            'constructive': entropy > 0 and empirical_rate < 0.01
        })

        status = "HOLDS" if bound_holds else "EXCEEDS"
        print(f"{f:>6.2f} | {trials:>10,} | {empirical_rate:>20.2e} | {conservative_bound:>20.2e} | "
              f"{ratio:>15.4f} | {status:>7} | {entropy:>8.2f}")

    print(f"{'='*90}")

    all_hold = all(r['bound_holds'] for r in results)
    all_constructive = all(r['constructive'] for r in results)

    print(f"\nSUMMARY:")
    print(f"  Theoretical bound holds across all f values: {'YES' if all_hold else 'NO'}")
    print(f"  Constructive property (entropy > 0, deanon << 1): {'VERIFIED' if all_constructive else 'PARTIAL'}")
    total_trials = sum(r['trials'] for r in results)
    print(f"  Total trials: {total_trials:,}")
    print(f"  Resolution floor at 500K trials: {1/500_000:.2e}")
    print(f"  Resolution floor at 10M trials: {1/10_000_000:.2e}")

    print(f"\n  CONSTRUCTIVE ADVERSARY VERIFICATION:")
    print(f"  {'f':>6} | {'Entropy provided (bits)':>24} | {'P(deanon)':>12} | {'Verdict':>30}")
    for r in results:
        verdict = "YES (constructive)" if r['constructive'] else "MARGINAL"
        print(f"  {r['f']:>6.2f} | {r['entropy_bits']:>24.2f} | {r['empirical_deanon_rate']:>12.2e} | {verdict:>30}")

    return results


def sensitivity_analysis():
    """Network size sensitivity."""
    print(f"\n{'='*90}")
    print(f"SENSITIVITY: Network size (f=0.10, 1M trials each)")
    print(f"{'N':>8} | {'N_l':>6} | {'Empirical':>12} | {'Theoretical':>14} | {'Ratio':>8}")
    print(f"{'-'*55}")

    f = 0.10
    trials = 1_000_000
    for N in [500, 1000, 2000, 5000, 10000, 50000]:
        N_l = N // L
        deanon = simulate_batch(N_l, f, L, K, T, trials)
        emp = deanon / trials
        _, theo = theoretical_bound(f, N_l, L, K, T)
        ratio = emp / theo if theo > 0 and emp > 0 else 0.0
        print(f"{N:>8} | {N_l:>6} | {emp:>12.2e} | {theo:>14.2e} | {ratio:>8.4f}")


def sybil_time_sensitivity():
    """Sybil creation time vs. seed count."""
    print(f"\n{'='*90}")
    print(f"SYBIL CREATION TIME: Sensitivity to adversary seed count")
    print(f"{'='*90}")

    target_f = 0.50
    target_sybils = int(target_f * N_TOTAL)
    B_max = 3
    credit_window_days = 24

    print(f"Target: {target_sybils} Sybil nodes (f={target_f} of N={N_TOTAL})")
    print(f"Vouching budget: B_max = {B_max} per credit window ({credit_window_days} days)")
    print(f"{'Seeds (s)':>10} | {'Credit windows':>15} | {'Time (years)':>14} | {'Note':>30}")
    print(f"{'-'*75}")

    for s in [5, 10, 20, 50, 100, 200, 500]:
        windows = target_sybils / (s * B_max)
        years = (windows * credit_window_days) / 365.25
        note = ""
        if s >= 50:
            note = f"Requires {s} reputable seeds (high cost)"
        print(f"{s:>10} | {windows:>15.1f} | {years:>14.1f} | {note:>40}")

    print(f"\n  NOTE: Each seed must itself be reputable (R > R_min), requiring prior")
    print(f"  honest relay work. Acquiring 100 reputable seeds already requires the")
    print(f"  adversary to invest significant honest relay contribution to the network.")


if __name__ == '__main__':
    np.random.seed(42)

    results = run_simulation()
    sensitivity_analysis()
    sybil_time_sensitivity()

    # Convert numpy/bool types for JSON
    clean_results = []
    for r in results:
        clean_results.append({k: bool(v) if isinstance(v, (bool, np.bool_)) else v for k, v in r.items()})

    output = {
        'parameters': {
            'N': N_TOTAL, 'L': L, 'K': K, 'T': T,
            'N_l': N_TOTAL // L, 'seed': 42
        },
        'results': clean_results
    }

    import os
    output_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'adversary_bound_results.json')
    with open(output_path, 'w') as f_out:
        json.dump(output, f_out, indent=2)

    print(f"\nResults saved to simulation/adversary_bound_results.json")
