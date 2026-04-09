#!/usr/bin/env python3
"""
train_model.py — Offline trainer for the IDS Isolation Forest model.

Generates a synthetic training dataset and saves the fitted model to model.pkl.
Run once before deployment, or retrain with real captured data.

Usage:
    python3 train_model.py [--data path/to/data.csv] [--output model.pkl]
"""

import argparse
import os
import sys
import pickle

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler
    from sklearn.pipeline import Pipeline
    from sklearn.metrics import classification_report
except ImportError:
    print("Missing dependencies. Run:  pip install -r requirements.txt")
    sys.exit(1)


# ─── Feature columns ──────────────────────────────────────────────────────────
FEATURES = ["packet_rate", "unique_ports", "syn_count", "avg_packet_size", "conn_count"]


# ─── Synthetic data generation ────────────────────────────────────────────────
def generate_normal_data(n=2000, seed=42):
    rng = np.random.default_rng(seed)
    data = np.column_stack([
        rng.lognormal(mean=2.5, sigma=0.8, size=n),     # packet_rate
        rng.choice([1, 2, 3, 4, 5], size=n,
                   p=[0.5, 0.25, 0.15, 0.07, 0.03]),     # unique_ports
        rng.choice([0, 1, 2, 3], size=n,
                   p=[0.6, 0.25, 0.1, 0.05]),             # syn_count
        rng.normal(800, 200, size=n).clip(64, 1500),     # avg_packet_size
        rng.lognormal(mean=2.5, sigma=0.8, size=n),     # conn_count
    ])
    return data


def generate_attack_data(n=300, seed=99):
    rng = np.random.default_rng(seed)

    port_scans = np.column_stack([
        rng.uniform(10, 80, n // 3),
        rng.uniform(30, 150, n // 3),
        rng.uniform(10, 40, n // 3),
        rng.uniform(40, 100, n // 3),
        rng.uniform(30, 150, n // 3),
    ])

    syn_floods = np.column_stack([
        rng.uniform(150, 800, n // 3),
        rng.choice([1, 2], n // 3),
        rng.uniform(120, 700, n // 3),
        rng.uniform(40, 80, n // 3),
        rng.uniform(150, 800, n // 3),
    ])

    dos = np.column_stack([
        rng.uniform(500, 2000, n // 3),
        rng.choice([1, 2, 3], n // 3),
        rng.uniform(2, 20, n // 3),
        rng.uniform(60, 200, n // 3),
        rng.uniform(500, 2000, n // 3),
    ])

    return np.vstack([port_scans, syn_floods, dos])


# ─── Train ────────────────────────────────────────────────────────────────────
def train(output_path: str):
    print("[IDS Trainer] Generating training data...")
    X_normal = generate_normal_data(2000)
    X_attack = generate_attack_data(300)
    X_all    = np.vstack([X_normal, X_attack])
    y_labels = np.array([1] * len(X_normal) + [-1] * len(X_attack))

    contamination = len(X_attack) / len(X_all)
    print(f"  Normal samples : {len(X_normal)}")
    print(f"  Attack samples : {len(X_attack)}")
    print(f"  Contamination  : {contamination:.3f}")

    print("[IDS Trainer] Fitting Isolation Forest pipeline...")
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=200,
            contamination=contamination,
            max_features=5,
            random_state=42,
            n_jobs=-1,
            verbose=0,
        ))
    ])
    pipeline.fit(X_all)

    # Quick eval on training set
    preds = pipeline.predict(X_all)
    print("\n[IDS Trainer] Training-set report:")
    print(classification_report(y_labels, preds, target_names=["ATTACK", "NORMAL"]))

    # Save
    with open(output_path, "wb") as f:
        pickle.dump(pipeline, f)
    size_kb = os.path.getsize(output_path) / 1024
    print(f"[IDS Trainer] Model saved → {output_path}  ({size_kb:.1f} KB)")


# ─── Train from CSV ───────────────────────────────────────────────────────────
def train_from_csv(csv_path: str, output_path: str):
    """
    CSV format expected:
      packet_rate,unique_ports,syn_count,avg_packet_size,conn_count[,label]
    label: 1=normal, -1=attack (optional)
    """
    import csv
    rows = []
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append([float(row[c]) for c in FEATURES])

    X = np.array(rows)
    print(f"[IDS Trainer] Loaded {len(X)} rows from {csv_path}")

    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("iforest", IsolationForest(
            n_estimators=200,
            contamination=0.1,
            max_features=5,
            random_state=42,
            n_jobs=-1,
        ))
    ])
    pipeline.fit(X)

    with open(output_path, "wb") as f:
        pickle.dump(pipeline, f)
    print(f"[IDS Trainer] Model saved → {output_path}")


# ─── Entry point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="IDS Isolation Forest trainer")
    parser.add_argument("--data",   default=None,        help="CSV file with real traffic data")
    parser.add_argument("--output", default="model.pkl", help="Output model file (default: model.pkl)")
    args = parser.parse_args()

    if args.data:
        train_from_csv(args.data, args.output)
    else:
        train(args.output)