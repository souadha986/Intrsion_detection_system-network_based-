"""Project settings. Edit this file instead of the code."""
from pathlib import Path

ROOT = Path(__file__).resolve().parent

# ---- training dataset (labelled flow CSVs, CICIDS2017 style) ----
DATASET_GLOB = str(ROOT / "data" / "*.csv")   # put your CSV files in the data/ folder
LABEL_COLUMN = "Label"
BENIGN_LABEL = "BENIGN"
MAX_ROWS_PER_FILE = 200_000                   # 0 = read everything
CONTAMINATION = 0.01                          # share of normal traffic allowed to be flagged

# ---- output files ----
MODEL_PATH = str(ROOT / "models" / "model.joblib")
ALERT_LOG = str(ROOT / "logs" / "alerts.jsonl")
