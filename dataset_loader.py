"""Load labelled flow CSVs (CICIDS2017 style) into (X, y, labels)."""
import glob
import numpy as np
import pandas as pd

# our feature -> possible column names in the dataset (lower-case, stripped)
LIVE_COLUMNS = {
    'packet_size': ['average packet size', 'packet length mean'],
    'packet_rate': ['flow packets/s'],
    'byte_rate':   ['flow bytes/s'],
    'window_size': ['init_win_bytes_forward', 'init fwd win byt'],
}
LABEL_CANDIDATES = ['label', 'class', 'attack', 'attack_cat']


def expand_paths(spec):
    """'data/*.csv, other.csv' -> list of files."""
    out = []
    for part in str(spec).split(","):
        part = part.strip()
        if part:
            out += sorted(glob.glob(part)) or []
    return out


def read_csvs(sources, max_rows_per_file=None):
    if not sources:
        raise ValueError("No CSV files found.")
    frames = []
    for s in sources:
        df = pd.read_csv(s, nrows=max_rows_per_file, low_memory=False, encoding_errors="replace")
        df.columns = [str(c).strip() for c in df.columns]   # CICIDS has ' Label', ' Flow Packets/s'...
        frames.append(df)
    return pd.concat(frames, ignore_index=True)


def prepare(df, label_col=None, benign="BENIGN", all_numeric=False):
    """Return X (DataFrame), y (0 benign / 1 attack), labels (original strings)."""
    lower = {c.lower(): c for c in df.columns}
    if label_col:
        label_col = lower.get(label_col.strip().lower())
    else:
        label_col = next((lower[c] for c in LABEL_CANDIDATES if c in lower), None)
    if label_col is None:
        raise ValueError(f"Label column not found. Columns: {list(df.columns)[:30]}")

    labels = df[label_col].astype(str).str.strip()
    y = (labels.str.lower() != benign.strip().lower()).astype(int)

    if all_numeric:
        X = df.drop(columns=[label_col]).select_dtypes("number")
    else:
        cols = {}
        for feat, names in LIVE_COLUMNS.items():
            found = next((lower[n] for n in names if n in lower), None)
            if found is None:
                raise ValueError(f"No column for '{feat}' (looked for {names}). "
                                 f"Your columns: {list(df.columns)[:40]}. "
                                 f"Use --all-numeric to train on every numeric column instead.")
            cols[feat] = df[found]
        X = pd.DataFrame(cols)

    X = X.apply(pd.to_numeric, errors="coerce").replace([np.inf, -np.inf], np.nan)
    ok = X.notna().all(axis=1)
    if y[ok].sum() == len(y[ok]):
        raise ValueError(f"No rows labelled '{benign}'. Labels seen: {labels.unique()[:10]}")
    return X[ok].reset_index(drop=True), y[ok].reset_index(drop=True), labels[ok].reset_index(drop=True)
