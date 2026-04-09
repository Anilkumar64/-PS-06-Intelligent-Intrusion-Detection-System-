#!/usr/bin/env python3
"""
ml_scorer.py — IIDS ML scorer (production version)

Loads model_iforest.pkl and model_rf.pkl at startup.
Protocol:
  stdin  : "packet_rate,unique_ports,syn_count,avg_packet_size,conn_count"
  stdout : "score,label"  e.g. "0.8700,PortScan" or "0.0000,Normal"

Prints "READY" after both models loaded. All debug → stderr.
"""

import sys, os, pickle
os.environ["PYTHONWARNINGS"] = "ignore"

try:
    import numpy as np
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False

SCRIPT_DIR   = os.path.dirname(os.path.realpath(__file__))
IFOREST_PATH = os.path.join(SCRIPT_DIR, 'model_iforest.pkl')
RF_PATH      = os.path.join(SCRIPT_DIR, 'model_rf.pkl')


def load_models():
    iforest = rf_pipe = le = None
    if not ML_AVAILABLE:
        return None, None, None
    if os.path.exists(IFOREST_PATH):
        with open(IFOREST_PATH, 'rb') as f:
            iforest = pickle.load(f)
        print(f"[ml_scorer] Loaded {IFOREST_PATH}", file=sys.stderr)
    else:
        print(f"[ml_scorer] WARNING: {IFOREST_PATH} missing", file=sys.stderr)
    if os.path.exists(RF_PATH):
        with open(RF_PATH, 'rb') as f:
            bundle = pickle.load(f)
        rf_pipe = bundle['pipeline']
        le      = bundle['label_encoder']
        print(f"[ml_scorer] Loaded {RF_PATH}  classes={list(le.classes_)}", file=sys.stderr)
    else:
        print(f"[ml_scorer] WARNING: {RF_PATH} missing", file=sys.stderr)
    return iforest, rf_pipe, le


def heuristic(features):
    pr, up, sc, aps, cc = features
    if up > 20 or sc > 40 or pr > 400:
        label = 'PortScan' if up > 20 else ('SYNFlood' if sc > 40 else 'DoS')
        return 1.0, label
    if pr > 100 or sc > 15:
        return 0.7, 'Suspicious'
    return 0.0, 'Normal'


def score_sample(iforest, rf_pipe, le, features):
    if not ML_AVAILABLE or (iforest is None and rf_pipe is None):
        return heuristic(features)
    x = __import__('numpy').array(features, dtype=float).reshape(1, -1)
    anomaly_score = 0.0
    is_anomaly    = False
    if iforest:
        pred = iforest.predict(x)[0]
        raw  = iforest.score_samples(x)[0]
        if pred == -1:
            is_anomaly    = True
            anomaly_score = float(min(1.0, max(0.5, -raw * 2)))

        label = 'Normal'

# Run Random Forest if available
    if rf_pipe and le:
     label = le.inverse_transform([rf_pipe.predict(x)[0]])[0]

     # Adjust anomaly score based on RF result
    if label != 'Normal':
     anomaly_score = max(anomaly_score, 0.6)
    elif not is_anomaly:
     anomaly_score = 0.0

    return round(anomaly_score, 4), label

def main():
    iforest, rf_pipe, le = load_models()
    print("READY", flush=True)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            parts = [float(x) for x in line.split(',')]
            if len(parts) != 5:
                print("0.0000,Normal", flush=True)
                continue
            s, lbl = score_sample(iforest, rf_pipe, le, parts)
            print(f"{s:.4f},{lbl}", flush=True)
        except Exception as e:
            print(f"[ml_scorer] error: {e}", file=sys.stderr)
            print("0.0000,Normal", flush=True)

if __name__ == '__main__':
    main()