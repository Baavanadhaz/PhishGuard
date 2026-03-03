# train_model.py  (run from backend/ root)
"""
Usage:
    python train_model.py --dataset path/to/dataset.csv

The CSV must have columns:  url, label
label can be  "phishing"/"safe"  OR  1/0

Outputs:
    app/ml/ml_model.joblib
    app/ml/feature_columns.json
"""

import argparse
import json
import os
import sys

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    classification_report, confusion_matrix,
)
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
import joblib

# Make sure app/ is importable when running from backend/
sys.path.insert(0, os.path.dirname(__file__))
from app.ml.feature_extractor import extract_features


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args():
    p = argparse.ArgumentParser(description="Train phishing-URL classifier")
    p.add_argument("--dataset",  required=True, help="Path to CSV with url,label columns")
    p.add_argument("--model",    default="rf",  choices=["rf", "lr"],
                   help="rf = RandomForest (default), lr = LogisticRegression")
    p.add_argument("--test-size", type=float, default=0.2)
    p.add_argument("--label-col", default="label", help="Name of the label column")
    p.add_argument("--out-dir",  default="app/ml", help="Where to save model files")
    return p.parse_args()


# ── Label normaliser ──────────────────────────────────────────────────────────

def normalise_label(val):
    """Map 'phishing'/1/'1' → 1 and 'safe'/'legitimate'/0/'0' → 0."""
    s = str(val).strip().lower()
    if s in ("1", "phishing", "malicious", "bad"):
        return 1
    if s in ("0", "safe", "legitimate", "benign", "good"):
        return 0
    raise ValueError(f"Unknown label value: {val!r}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    # ── Load & validate CSV ───────────────────────────────────────────────────
    print(f"[1/6] Loading dataset: {args.dataset}")
    df = pd.read_csv(args.dataset)

    required_cols = {"url", "label"}
    missing = required_cols - set(df.columns.str.lower())
    if missing:
        sys.exit(f"ERROR: CSV is missing columns: {missing}")

    df.columns = df.columns.str.lower()
    df = df[["url", args.label_col]].dropna()
    df = df.rename(columns={args.label_col: "label"})
    df["label"] = df["label"].apply(normalise_label)

    print(f"    Total samples : {len(df):,}")
    print(f"    Phishing (1)  : {df['label'].sum():,}")
    print(f"    Safe (0)      : {(df['label'] == 0).sum():,}")

    # ── Extract features ──────────────────────────────────────────────────────
    print("[2/6] Extracting features …")
    feature_dicts = []
    errors = 0
    for url in df["url"]:
        try:
            feature_dicts.append(extract_features(str(url)))
        except Exception:
            feature_dicts.append({})
            errors += 1

    if errors:
        print(f"    ⚠  {errors} URLs failed feature extraction and were zeroed out.")

    X = pd.DataFrame(feature_dicts).fillna(0)
    y = df["label"].values

    feature_columns = list(X.columns)
    print(f"    Features ({len(feature_columns)}): {feature_columns}")

    # ── Train / test split ────────────────────────────────────────────────────
    print(f"[3/6] Splitting: {int((1-args.test_size)*100)}% train / {int(args.test_size*100)}% test")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=args.test_size, random_state=42, stratify=y
    )

    # ── Build pipeline ────────────────────────────────────────────────────────
    print(f"[4/6] Training {'RandomForest' if args.model == 'rf' else 'LogisticRegression'} …")
    if args.model == "rf":
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=None,
            min_samples_leaf=2,
            n_jobs=-1,
            random_state=42,
        )
        pipe = Pipeline([("clf", clf)])
    else:
        clf = LogisticRegression(max_iter=1000, C=1.0, random_state=42)
        pipe = Pipeline([("scaler", StandardScaler()), ("clf", clf)])

    pipe.fit(X_train, y_train)

    # ── Evaluate ──────────────────────────────────────────────────────────────
    print("[5/6] Evaluating …")
    y_pred = pipe.predict(X_test)

    acc  = accuracy_score(y_test, y_pred)
    prec = precision_score(y_test, y_pred, zero_division=0)
    rec  = recall_score(y_test, y_pred, zero_division=0)
    f1   = f1_score(y_test, y_pred, zero_division=0)

    print("\n" + "="*50)
    print("  EVALUATION RESULTS")
    print("="*50)
    print(f"  Accuracy  : {acc:.4f}")
    print(f"  Precision : {prec:.4f}")
    print(f"  Recall    : {rec:.4f}")
    print(f"  F1 Score  : {f1:.4f}")
    print("\n  Classification Report:")
    print(classification_report(y_test, y_pred, target_names=["safe", "phishing"]))
    print("  Confusion Matrix:")
    cm = confusion_matrix(y_test, y_pred)
    print(f"    TN={cm[0,0]}  FP={cm[0,1]}")
    print(f"    FN={cm[1,0]}  TP={cm[1,1]}")
    print("="*50 + "\n")

    # Print feature importances for RandomForest
    if args.model == "rf":
        importances = pipe.named_steps["clf"].feature_importances_
        top = sorted(zip(feature_columns, importances), key=lambda x: -x[1])[:10]
        print("  Top-10 feature importances:")
        for feat, imp in top:
            print(f"    {feat:<30} {imp:.4f}")
        print()

    # ── Save artifacts ────────────────────────────────────────────────────────
    print(f"[6/6] Saving model to {args.out_dir}/")
    os.makedirs(args.out_dir, exist_ok=True)

    model_path   = os.path.join(args.out_dir, "ml_model.joblib")
    columns_path = os.path.join(args.out_dir, "feature_columns.json")

    joblib.dump(pipe, model_path)
    with open(columns_path, "w") as f:
        json.dump(feature_columns, f, indent=2)

    print(f"    ✓ Model   saved → {model_path}")
    print(f"    ✓ Columns saved → {columns_path}")
    print("\nDone! ✅")


if __name__ == "__main__":
    main()
