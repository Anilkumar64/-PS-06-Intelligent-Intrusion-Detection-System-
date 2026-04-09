#!/usr/bin/env python3
"""
Run after generating labeled traffic.
Usage: python3 evaluate.py --log ml_predictions.log
"""
import argparse
from sklearn.metrics import (classification_report, confusion_matrix,
                             accuracy_score)

def parse_log(path):
    y_true, y_pred = [], []
    with open(path) as f:
        for line in f:
            if 'ACTUAL=' in line and 'PRED=' in line:
                parts = dict(p.split('=') for p in line.strip().split())
                y_true.append(parts['ACTUAL'])
                y_pred.append(parts['PRED'])
    return y_true, y_pred

if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--log', required=True)
    args = ap.parse_args()

    y_true, y_pred = parse_log(args.log)
    if not y_true:
        print("No labeled predictions found.")
        print("Add 'ACTUAL=<label> PRED=<label>' lines to your ML log.")
        raise SystemExit(1)

    print(f"Total samples: {len(y_true)}")
    print(f"Accuracy: {accuracy_score(y_true, y_pred):.3f}\n")
    print(classification_report(y_true, y_pred, zero_division=0))
    print("Confusion matrix:")
    labels = sorted(set(y_true) | set(y_pred))
    print("Labels:", labels)
    print(confusion_matrix(y_true, y_pred, labels=labels))
