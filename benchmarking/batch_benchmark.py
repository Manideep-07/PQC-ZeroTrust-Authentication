"""
PQC Framework — CPU Batch Benchmark
====================================
Measures throughput and latency of PQC operations under concurrent load
using Python ThreadPoolExecutor (CPU-level parallelism via liboqs C threads).

Outputs per-operation stats (mean, std dev, p95, p99, ops/sec) for
batch sizes 1, 5, 10, 20, 50 — producing a scaling curve suitable
for research publication.

Run:
    python benchmarking/batch_benchmark.py

Output:
    benchmarking/batch_results.csv
    Console table with all metrics
"""

import sys
import os
import time
import statistics
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Handle Windows DLL loading (unchanged from original pattern)
import ctypes
if os.name == 'nt':
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dll_path = os.path.join(project_root, "liboqs.dll")
    if os.path.exists(dll_path):
        os.environ["PATH"] = project_root + os.pathsep + os.environ["PATH"]
        if hasattr(os, 'add_dll_directory'):
            try:
                os.add_dll_directory(project_root)
            except Exception:
                pass
        try:
            ctypes.CDLL(dll_path)
        except Exception:
            pass

from crypto.kyber import KyberWrapper
from crypto.dilithium import DilithiumWrapper
from crypto.aes_gcm import AESGCMWrapper

OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "batch_results.csv")
BATCH_SIZES = [1, 5, 10, 20, 50]
REPEATS_PER_BATCH = 3   # repeat each batch size N times and average — reduces noise


# ─────────────────────────────────────────────────────────────────────────────
# Single-operation workers (called inside thread pool)
# ─────────────────────────────────────────────────────────────────────────────

def _kyber_full_cycle(_):
    """Keygen + Encap + Decap for one Kyber768 exchange."""
    t0 = time.perf_counter()
    kyber_a = KyberWrapper("Kyber768")
    pk, _ = kyber_a.generate_keypair()
    t_keygen = time.perf_counter()

    kyber_b = KyberWrapper("Kyber768")
    kyber_b._kem.generate_keypair()   # needed to initialise encapsulator
    ct, ss_enc = kyber_a._kem.encap_secret(pk)
    t_encap = time.perf_counter()

    kyber_a._kem.decap_secret(ct)
    t_decap = time.perf_counter()

    return {
        "keygen":  t_keygen - t0,
        "encap":   t_encap  - t_keygen,
        "decap":   t_decap  - t_encap,
        "total":   t_decap  - t0,
    }


def _dilithium_full_cycle(_):
    """Keygen + Sign + Verify for one Dilithium3 exchange."""
    import secrets as _secrets
    msg = _secrets.token_bytes(64)
    t0 = time.perf_counter()
    d = DilithiumWrapper("Dilithium3")
    pk, _ = d.generate_keypair()
    t_keygen = time.perf_counter()

    sig = d.sign(msg)
    t_sign = time.perf_counter()

    d.verify(pk, msg, sig)
    t_verify = time.perf_counter()

    return {
        "keygen": t_keygen - t0,
        "sign":   t_sign   - t_keygen,
        "verify": t_verify - t_sign,
        "total":  t_verify - t0,
    }


def _aes_full_cycle(_):
    """Encrypt + Decrypt one 256-byte message with AES-256-GCM."""
    import secrets as _secrets
    key = _secrets.token_bytes(32)
    msg = _secrets.token_bytes(256)
    aes = AESGCMWrapper(key)
    t0 = time.perf_counter()
    nonce, ct = aes.encrypt(msg)
    t_enc = time.perf_counter()
    aes.decrypt(nonce, ct)
    t_dec = time.perf_counter()
    return {
        "encrypt": t_enc - t0,
        "decrypt": t_dec - t_enc,
        "total":   t_dec - t0,
    }


# ─────────────────────────────────────────────────────────────────────────────
# Batch runner
# ─────────────────────────────────────────────────────────────────────────────

def _percentile(data, pct):
    sorted_d = sorted(data)
    idx = int(len(sorted_d) * pct / 100)
    idx = min(idx, len(sorted_d) - 1)
    return sorted_d[idx]


def run_batch(worker_fn, batch_size, label):
    """Run worker_fn batch_size times in parallel, return stats dict."""
    wall_start = time.perf_counter()
    totals = []
    with ThreadPoolExecutor(max_workers=batch_size) as pool:
        futures = [pool.submit(worker_fn, i) for i in range(batch_size)]
        for f in as_completed(futures):
            totals.append(f.result()["total"])
    wall_end = time.perf_counter()
    wall_time = wall_end - wall_start

    mean   = statistics.mean(totals)
    stdev  = statistics.stdev(totals) if len(totals) > 1 else 0.0
    p95    = _percentile(totals, 95)
    p99    = _percentile(totals, 99)
    ops_s  = batch_size / wall_time

    return {
        "operation":  label,
        "batch_size": batch_size,
        "mean_s":     round(mean,   6),
        "stdev_s":    round(stdev,  6),
        "p95_s":      round(p95,    6),
        "p99_s":      round(p99,    6),
        "wall_s":     round(wall_time, 4),
        "ops_per_sec": round(ops_s, 2),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main():
    print("=" * 70)
    print("  PQC Framework — CPU Batch Benchmark")
    print(f"  Batch sizes : {BATCH_SIZES}   Repeats per size: {REPEATS_PER_BATCH}")
    print("=" * 70)

    ops = [
        ("Kyber768 (keygen+encap+decap)", _kyber_full_cycle),
        ("Dilithium3 (keygen+sign+verify)", _dilithium_full_cycle),
        ("AES-256-GCM (encrypt+decrypt)", _aes_full_cycle),
    ]

    all_rows = []

    for label, fn in ops:
        print(f"\n  [{label}]")
        print(f"  {'Batch':>6}  {'Mean(s)':>10}  {'StdDev(s)':>10}  {'p95(s)':>10}  {'p99(s)':>10}  {'ops/sec':>10}")
        print(f"  {'-'*6}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}  {'-'*10}")

        for bs in BATCH_SIZES:
            # Average over REPEATS_PER_BATCH runs to reduce noise
            rep_rows = [run_batch(fn, bs, label) for _ in range(REPEATS_PER_BATCH)]
            avg_row = {
                "operation":   label,
                "batch_size":  bs,
                "mean_s":      round(statistics.mean(r["mean_s"]    for r in rep_rows), 6),
                "stdev_s":     round(statistics.mean(r["stdev_s"]   for r in rep_rows), 6),
                "p95_s":       round(statistics.mean(r["p95_s"]     for r in rep_rows), 6),
                "p99_s":       round(statistics.mean(r["p99_s"]     for r in rep_rows), 6),
                "wall_s":      round(statistics.mean(r["wall_s"]    for r in rep_rows), 4),
                "ops_per_sec": round(statistics.mean(r["ops_per_sec"] for r in rep_rows), 2),
            }
            all_rows.append(avg_row)
            print(
                f"  {bs:>6}  {avg_row['mean_s']:>10.6f}  "
                f"{avg_row['stdev_s']:>10.6f}  {avg_row['p95_s']:>10.6f}  "
                f"{avg_row['p99_s']:>10.6f}  {avg_row['ops_per_sec']:>10.2f}"
            )

    # Write CSV
    fieldnames = ["operation", "batch_size", "mean_s", "stdev_s", "p95_s", "p99_s", "wall_s", "ops_per_sec"]
    with open(OUTPUT_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print(f"\n  Results saved to: {OUTPUT_FILE}")
    print("=" * 70)


if __name__ == "__main__":
    main()
