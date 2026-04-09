#!/usr/bin/env python3
"""
preprocess.py — CIC-IDS-2017 → IIDS feature vector

Maps the 78-column CIC dataset to your 5-feature FeatureVector:
    [packet_rate, unique_ports, syn_count, avg_packet_size, conn_count]

Output: two CSVs ready for training:
    data_normal.csv   — BENIGN rows only  (for Isolation Forest)
    data_labelled.csv — all rows with label (for Random Forest)

Usage:
    python3 preprocess.py --input /path/to/MachineLearningCVE --output /path/to/ml/
"""

import argparse
import glob
import os
import sys
import numpy as np
import pandas as pd

# ── CIC column → IIDS feature mapping ────────────────────────────────────────
CIC_COLS = {
    'packet_rate':     ' Flow Packets/s',
    'syn_count':       ' SYN Flag Count',
    'avg_packet_size': ' Average Packet Size',
    'conn_count':      ' Total Fwd Packets',
    'dst_port':        ' Destination Port',   # binned → unique_ports
    'label':           ' Label',
}

# ── Label normalisation ───────────────────────────────────────────────────────
# Maps raw CIC labels → clean class names your classifier will output
LABEL_MAP = {
    'BENIGN':                        'Normal',
    'DoS Hulk':                      'DoS',
    'DoS GoldenEye':                 'DoS',
    'DoS slowloris':                 'DoS',
    'DoS Slowhttptest':              'DoS',
    'Heartbleed':                    'DoS',
    'DDoS':                          'DDoS',
    'PortScan':                      'PortScan',
    'FTP-Patator':                   'BruteForce',
    'SSH-Patator':                   'BruteForce',
    'Web Attack  Brute Force':       'WebAttack',
    'Web Attack  XSS':               'WebAttack',
    'Web Attack  Sql Injection':     'WebAttack',
    'Infiltration':                  'Infiltration',
    'Bot':                           'Botnet',
}


def bin_port(port: float) -> float:
    """
    Convert a destination port number into an approximate 'unique ports
    accessed' count bucket.  In real flows this would be a per-IP count;
    here we approximate by treating well-known ranges as low diversity
    and ephemeral ports as high diversity.
    """
    if port < 1024:
        return 1.0          # single well-known service
    elif port < 10000:
        return 3.0          # registered service range
    else:
        return float(int(port / 10000) + 4)   # ephemeral → 4-10


def load_and_clean(filepath: str) -> pd.DataFrame:
    needed = list(CIC_COLS.values())
    df = pd.read_csv(filepath, usecols=needed, low_memory=False)

    # Strip whitespace from label
    df[' Label'] = df[' Label'].str.strip()

    # Drop rows with inf or NaN in numeric columns
    num_cols = [c for c in needed if c != ' Label']
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)
    df.dropna(subset=num_cols, inplace=True)

    # Clip packet_rate to sane range (negatives are noise, cap at 1M pps)
    df[' Flow Packets/s'] = df[' Flow Packets/s'].clip(0, 1_000_000)

    # Clip avg_packet_size (max Ethernet frame = 1518 bytes)
    df[' Average Packet Size'] = df[' Average Packet Size'].clip(0, 1518)

    # Build output frame
    out = pd.DataFrame()
    out['packet_rate']     = df[' Flow Packets/s']
    out['unique_ports']    = df[' Destination Port'].apply(bin_port)
    out['syn_count']       = df[' SYN Flag Count'].clip(0, 500)
    out['avg_packet_size'] = df[' Average Packet Size']
    out['conn_count']      = df[' Total Fwd Packets'].clip(0, 100_000)
    out['label']           = df[' Label'].map(LABEL_MAP).fillna('Other')

    return out


def main():
    parser = argparse.ArgumentParser(description="CIC-IDS-2017 preprocessor")
    parser.add_argument('--input',  required=True, help='Directory with CIC CSV files')
    parser.add_argument('--output', required=True, help='Output directory for processed CSVs')
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)

    csv_files = sorted(glob.glob(os.path.join(args.input, '*.csv')))
    if not csv_files:
        print(f"[preprocess] No CSV files found in {args.input}")
        sys.exit(1)

    print(f"[preprocess] Found {len(csv_files)} CSV files")

    frames = []
    for f in csv_files:
        name = os.path.basename(f)
        print(f"  Loading {name}...", end=' ', flush=True)
        df = load_and_clean(f)
        print(f"{len(df):,} rows  labels: {df['label'].value_counts().to_dict()}")
        frames.append(df)

    all_data = pd.concat(frames, ignore_index=True)
    print(f"\n[preprocess] Total rows: {len(all_data):,}")
    print(f"[preprocess] Label distribution:\n{all_data['label'].value_counts()}")

    # ── Normal-only CSV (for Isolation Forest) ────────────────────────────────
    normal = all_data[all_data['label'] == 'Normal'].drop(columns=['label'])
    normal_path = os.path.join(args.output, 'data_normal.csv')
    normal.to_csv(normal_path, index=False)
    print(f"\n[preprocess] Saved {len(normal):,} normal rows → {normal_path}")

    # ── Labelled CSV (for Random Forest) ─────────────────────────────────────
    labelled_path = os.path.join(args.output, 'data_labelled.csv')
    all_data.to_csv(labelled_path, index=False)
    print(f"[preprocess] Saved {len(all_data):,} labelled rows → {labelled_path}")


if __name__ == '__main__':
    main()