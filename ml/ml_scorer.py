#!/usr/bin/env python3
"""
IDS ML Scorer — Isolation Forest anomaly detector.
Protocol: reads CSV lines from stdin, writes a score (0.0 or 1.0) to stdout.
Prints "READY" on startup after model initialization.
"""

import sys
import os

# Silence warnings before importing sklearn
os.environ["PYTHONWARNINGS"] = "ignore"

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False


# ─── Training data (synthetic "normal" baseline) ──────────────────────────
# Each row: [packet_rate, unique_ports, syn_count, avg_packet_size, conn_count]
NORMAL_PROFILES = np.array([
    # Web browsing patterns
    [10.0,   2.0,   1.0,  800.0,  10.0],
    [15.0,   3.0,   2.0,  750.0,  15.0],
    [8.0,    1.0,   1.0,  900.0,   8.0],
    [20.0,   4.0,   3.0,  700.0,  20.0],
    [5.0,    2.0,   1.0, 1000.0,   5.0],
    # File transfers
    [30.0,   1.0,   1.0, 1400.0,  30.0],
    [50.0,   1.0,   1.0, 1450.0,  50.0],
    [40.0,   2.0,   1.0, 1380.0,  40.0],
    # Mixed
    [12.0,   3.0,   2.0,  850.0,  12.0],
    [18.0,   4.0,   2.0,  780.0,  18.0],
    [25.0,   3.0,   3.0,  820.0,  25.0],
    [7.0,    2.0,   1.0,  950.0,   7.0],
], dtype=np.float32)

# ─── Attack profiles added as contaminants to tune sensitivity ────────────
ATTACK_PROFILES = np.array([
    # Port scan
    [20.0,  50.0,  15.0,  64.0,  50.0],
    [30.0, 100.0,  25.0,  64.0, 100.0],
    # SYN flood
    [200.0,  2.0, 180.0,  60.0, 200.0],
    [500.0,  1.0, 490.0,  60.0, 500.0],
    # DoS
    [600.0,  1.0,   5.0, 120.0, 600.0],
    [800.0,  2.0,  10.0, 100.0, 800.0],
], dtype=np.float32)

ALL_TRAINING = np.vstack([NORMAL_PROFILES, ATTACK_PROFILES])


def build_model():
    if not ML_AVAILABLE:
        return None
    model = IsolationForest(
        n_estimators=100,
        contamination=0.15,   # ~15% contamination from attack profiles
        random_state=42,
        max_features=5,
        n_jobs=1
    )
    model.fit(ALL_TRAINING)
    return model


def score_sample(model, features: list) -> float:
    """Returns 1.0 if anomaly, 0.0 if normal."""
    if model is None:
        # Fallback heuristics when sklearn unavailable
        pkt_rate, unique_ports, syn_count, avg_pkt_size, conn_count = features
        if unique_ports > 20 or syn_count > 40 or pkt_rate > 400:
            return 1.0
        return 0.0

    x = np.array(features, dtype=np.float32).reshape(1, -1)
    pred = model.predict(x)   # -1 = anomaly, 1 = normal
    # Also get the raw score for soft output
    raw = model.score_samples(x)[0]
    # Map: score < -0.1 → anomaly
    if pred[0] == -1:
        # Confidence-weighted: deeper negative = closer to 1.0
        confidence = min(1.0, max(0.5, -raw * 2))
        return round(confidence, 3)
    return 0.0


def main():
    model = build_model()
    # Signal readiness to C++ parent
    print("READY", flush=True)

    MAX_LINE_LEN = 1024  # Defense-in-depth: cap input line length (CWE-400)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        if len(line) > MAX_LINE_LEN:
            print("0.0", flush=True)
            continue
        try:
            parts = [float(x) for x in line.split(",")]
            if len(parts) != 5:
                print("0.0", flush=True)
                continue
            result = score_sample(model, parts)
            print(f"{result:.4f}", flush=True)
        except Exception:
            print("0.0", flush=True)


if __name__ == "__main__":
    main()
