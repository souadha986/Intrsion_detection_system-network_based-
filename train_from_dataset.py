"""Train + evaluate the Isolation Forest on the labelled dataset set in settings.py.

    python train_from_dataset.py                        # uses settings.DATASET_GLOB
    python train_from_dataset.py "other/*.csv" --contamination 0.02
"""
import argparse

import numpy as np
import pandas as pd
from sklearn.metrics import confusion_matrix, precision_recall_fscore_support, roc_auc_score

import settings
from anomaly_detector import AnomalyDetector
from dataset_loader import expand_paths, prepare, read_csvs


def train_and_evaluate(det, X, y, labels, contamination=settings.CONTAMINATION, max_train=300_000, seed=42):
    """Train on 70% of BENIGN rows; test on the other 30% of benign + ALL attacks."""
    rng = np.random.default_rng(seed)
    benign = np.flatnonzero(y.values == 0)
    rng.shuffle(benign)
    cut = int(len(benign) * 0.7)
    train_idx, test_benign = benign[:cut][:max_train], benign[cut:]
    test_idx = np.concatenate([test_benign, np.flatnonzero(y.values == 1)])

    det.contamination = contamination
    det.fit_array(X.iloc[train_idx].values, features=list(X.columns), source="dataset")

    Xt, yt, lt = X.iloc[test_idx].values, y.iloc[test_idx].values, labels.iloc[test_idx].values
    pred, score = det.predict_array(Xt), det.anomaly_scores(Xt)
    p, r, f1, _ = precision_recall_fscore_support(yt, pred, average="binary", zero_division=0)
    tn, fp, fn, tp = confusion_matrix(yt, pred, labels=[0, 1]).ravel()
    auc = roc_auc_score(yt, score) if len(set(yt)) == 2 else float("nan")

    per = (pd.DataFrame({"label": lt, "flagged": pred})
           .groupby("label").agg(rows=("flagged", "size"), flagged_pct=("flagged", "mean")))
    per["flagged_pct"] = (per.flagged_pct * 100).round(1)   # benign row = false-positive rate
    return {"precision": p, "recall": r, "f1": f1, "auc": auc,
            "fpr": fp / max(fp + tn, 1), "cm": [[int(tn), int(fp)], [int(fn), int(tp)]],
            "per_label": per.sort_values("flagged_pct", ascending=False),
            "n_train": len(train_idx), "n_test": len(test_idx), "features": list(X.columns)}


def train_from_files(det, spec=settings.DATASET_GLOB, label_col=settings.LABEL_COLUMN,
                     benign=settings.BENIGN_LABEL, max_rows=settings.MAX_ROWS_PER_FILE,
                     contamination=settings.CONTAMINATION, all_numeric=False):
    """One call used by both the command line and the UI."""
    files = expand_paths(spec) if isinstance(spec, str) else list(spec)   # path/wildcard or uploaded files
    if not files:
        raise ValueError("No dataset found. Upload CSV files, or put them in the data/ folder.")
    X, y, labels = prepare(read_csvs(files, max_rows or None), label_col, benign, all_numeric)
    return train_and_evaluate(det, X, y, labels, contamination)


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("files", nargs="*", default=[settings.DATASET_GLOB], help="CSV paths or wildcards")
    ap.add_argument("--label-col", default=settings.LABEL_COLUMN)
    ap.add_argument("--benign", default=settings.BENIGN_LABEL)
    ap.add_argument("--contamination", type=float, default=settings.CONTAMINATION)
    ap.add_argument("--max-rows", type=int, default=settings.MAX_ROWS_PER_FILE, help="rows per file (0 = all)")
    ap.add_argument("--all-numeric", action="store_true", help="evaluation only (not usable live)")
    ap.add_argument("--model-path", default=settings.MODEL_PATH)
    a = ap.parse_args()

    det = AnomalyDetector(model_path=a.model_path)
    rep = train_from_files(det, ",".join(a.files), a.label_col, a.benign, a.max_rows,
                           a.contamination, a.all_numeric)
    print(f"Features: {rep['features']}\nTrain (benign only): {rep['n_train']:,} | Test: {rep['n_test']:,}")
    print(f"Precision {rep['precision']:.3f} | Recall {rep['recall']:.3f} | F1 {rep['f1']:.3f} "
          f"| ROC-AUC {rep['auc']:.3f} | False-positive rate {rep['fpr']:.3f}")
    print("Confusion matrix [[TN, FP], [FN, TP]]:", rep["cm"])
    print("\nFlagged % per label (BENIGN row = false positives):\n", rep["per_label"])
    print(f"\nSaved {a.model_path}" + ("" if det.live_compatible else "  (NOT usable for live packets)"))
