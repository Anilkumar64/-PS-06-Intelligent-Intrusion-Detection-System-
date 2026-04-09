#!/usr/bin/env python3
"""
train_model.py — Train both ML models for IIDS.

Model 1: Isolation Forest  (unsupervised anomaly detector)
    Input : data_normal.csv  — normal traffic only
    Output: model_iforest.pkl

Model 2: Random Forest classifier  (supervised attack typer)
    Input : data_labelled.csv — all traffic with labels
    Output: model_rf.pkl

Usage:
    python3 train_model.py --data /path/to/ml/
    python3 train_model.py --synthetic   (no CSVs needed, uses synthetic data)
"""

import argparse, os, sys, pickle
import numpy as np

try:
    import pandas as pd
    from sklearn.ensemble import IsolationForest, RandomForestClassifier
    from sklearn.preprocessing import StandardScaler, LabelEncoder
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report
except ImportError:
    print("Run: pip install scikit-learn numpy pandas")
    sys.exit(1)

FEATURES = ['packet_rate', 'unique_ports', 'syn_count', 'avg_packet_size', 'conn_count']

def generate_synthetic_normal(n=2000, seed=42):
    rng = np.random.default_rng(seed)
    return np.column_stack([
        rng.lognormal(2.5, 0.8, n),
        rng.choice([1,2,3,4,5], n, p=[0.5,0.25,0.15,0.07,0.03]),
        rng.choice([0,1,2,3], n, p=[0.6,0.25,0.1,0.05]),
        rng.normal(800, 200, n).clip(64, 1500),
        rng.lognormal(2.5, 0.8, n),
    ])

def generate_synthetic_attacks(n=300, seed=99):
    rng = np.random.default_rng(seed)
    r = n // 3
    ps  = np.column_stack([rng.uniform(10,80,r),  rng.uniform(30,150,r), rng.uniform(10,40,r),  rng.uniform(40,100,r),  rng.uniform(30,150,r)])
    sf  = np.column_stack([rng.uniform(150,800,r), rng.choice([1,2],r),   rng.uniform(120,700,r),rng.uniform(40,80,r),   rng.uniform(150,800,r)])
    dos = np.column_stack([rng.uniform(500,2000,r),rng.choice([1,2,3],r), rng.uniform(2,20,r),   rng.uniform(60,200,r),  rng.uniform(500,2000,r)])
    return np.vstack([ps,sf,dos]), ['PortScan']*r + ['SYNFlood']*r + ['DoS']*r

def train_iforest(X_normal, output_path):
    print(f"\n[Model 1] Isolation Forest on {len(X_normal):,} normal samples...")
    pipe = Pipeline([
        ('scaler',  StandardScaler()),
        ('iforest', IsolationForest(n_estimators=200, contamination=0.01,
                                    max_features=5, random_state=42, n_jobs=-1))
    ])
    pipe.fit(X_normal)
    with open(output_path, 'wb') as f:
        pickle.dump(pipe, f)
    print(f"[Model 1] Saved → {output_path}  ({os.path.getsize(output_path)//1024} KB)")
    return pipe

def train_rf(X, y_raw, output_path):
    print(f"\n[Model 2] Random Forest on {len(X):,} samples...")
    le = LabelEncoder()
    y  = le.fit_transform(y_raw)
    print(f"[Model 2] Classes: {list(le.classes_)}")
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    pipe = Pipeline([
        ('scaler', StandardScaler()),
        ('rf', RandomForestClassifier(n_estimators=200, max_depth=20,
                                       min_samples_leaf=5, class_weight='balanced',
                                       random_state=42, n_jobs=-1))
    ])
    pipe.fit(X_tr, y_tr)
    print(f"\n[Model 2] Test report:")
    print(classification_report(y_te, pipe.predict(X_te), target_names=le.classes_))
    bundle = {'pipeline': pipe, 'label_encoder': le}
    with open(output_path, 'wb') as f:
        pickle.dump(bundle, f)
    print(f"[Model 2] Saved → {output_path}  ({os.path.getsize(output_path)//1024} KB)")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data',      default='ml', help='Dir with data_normal.csv / data_labelled.csv')
    parser.add_argument('--output',    default=None, help='Dir to save .pkl files (default: same as --data)')
    parser.add_argument('--synthetic', action='store_true', help='Use synthetic data, skip CSVs')
    args = parser.parse_args()

    out_dir = args.output or args.data
    os.makedirs(out_dir, exist_ok=True)
    iforest_path = os.path.join(out_dir, 'model_iforest.pkl')
    rf_path      = os.path.join(out_dir, 'model_rf.pkl')

    if args.synthetic:
        print("[Trainer] Synthetic mode")
        X_norm          = generate_synthetic_normal()
        X_atk, y_atk   = generate_synthetic_attacks()
        X_all = np.vstack([X_norm, X_atk])
        y_all = np.array(['Normal']*len(X_norm) + y_atk)
        train_iforest(X_norm, iforest_path)
        train_rf(X_all, y_all, rf_path)
    else:
        for fname in ['data_normal.csv', 'data_labelled.csv']:
            if not os.path.exists(os.path.join(args.data, fname)):
                print(f"Missing {fname} — run preprocess.py first, or use --synthetic")
                sys.exit(1)

        print("[Trainer] Loading data_normal.csv...")
        df_n = pd.read_csv(os.path.join(args.data, 'data_normal.csv'))
        if len(df_n) > 500_000:
            df_n = df_n.sample(500_000, random_state=42)
        train_iforest(df_n[FEATURES].values, iforest_path)

        print("[Trainer] Loading data_labelled.csv...")
        df_all = pd.read_csv(os.path.join(args.data, 'data_labelled.csv'))
        print(df_all['label'].value_counts().to_string())

        atk = df_all[df_all['label'] != 'Normal']
        nor = df_all[df_all['label'] == 'Normal'].sample(
              min(len(df_all[df_all['label']=='Normal']), len(atk)*3), random_state=42)
        df_b = pd.concat([nor, atk]).sample(frac=1, random_state=42)
        train_rf(df_b[FEATURES].values, df_b['label'].values, rf_path)

    print(f"\n[Trainer] Done.\n  {iforest_path}\n  {rf_path}")
    print("\nNext: copy both .pkl files next to ml_scorer.py")

if __name__ == '__main__':
    main()