"""Isolation Forest anomaly detector.

Trained ONLY on normal (benign) traffic. Anything that is easy to "isolate"
from that baseline is flagged as an anomaly.

Training: fit_array(X) with the benign rows of a labelled CSV dataset
(see train_from_dataset.py). The trained model is saved to settings.MODEL_PATH
and loaded automatically on start-up.
"""
import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import FunctionTransformer, StandardScaler

import settings

# features the live pipeline can compute for every packet
LIVE_FEATURES = ['packet_size', 'packet_rate', 'byte_rate',
                 'tcp_flags', 'window_size', 'distinct_ports']
FEATURES = LIVE_FEATURES
# the subset that CICIDS-style flow CSVs also contain
DATASET_FEATURES = ['packet_size', 'packet_rate', 'byte_rate', 'window_size']
MODEL_VERSION = 2


def signed_log1p(X):
    """Squash heavy tails (bytes/s can be 0 .. 1e9) while keeping order."""
    X = np.asarray(X, dtype=float)
    return np.sign(X) * np.log1p(np.abs(X))


def _num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return float(int(v))          # scapy FlagValue


class AnomalyDetector:
    def __init__(self, contamination=0.002, n_estimators=150,
                 model_path=settings.MODEL_PATH, features=None):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model_path = model_path
        self.features = list(features or LIVE_FEATURES)
        self.model = None
        self.n_trained_on = 0
        self.trained_from = None
        if os.path.exists(model_path):
            self.load()

    @property
    def ready(self):
        return self.model is not None

    @property
    def live_compatible(self):
        """Can this model score live packets? (needs every feature to exist live)"""
        return all(f in LIVE_FEATURES for f in self.features)

    # ---------------- training ----------------
    def fit_array(self, X, features=None, source="array"):
        X = np.asarray(X, dtype=float)
        if len(X) < 200:
            raise ValueError(f"Need at least 200 normal samples, got {len(X)}")
        if features is not None:
            self.features = list(features)
        self.model = make_pipeline(
            FunctionTransformer(signed_log1p),
            StandardScaler(),
            IsolationForest(n_estimators=self.n_estimators,
                            contamination=self.contamination,
                            random_state=42, n_jobs=-1))
        self.model.fit(X)
        self._single_thread()
        self.n_trained_on, self.trained_from = len(X), source
        self.save()

    def _single_thread(self):
        """Scoring one packet at a time: thread start-up would cost more than the work itself."""
        self.model[-1].n_jobs = 1

    # ---------------- scoring ----------------
    def anomaly_scores(self, X):
        """Higher = more anomalous."""
        return -self.model.score_samples(np.asarray(X, dtype=float))

    def predict_array(self, X):
        """1 = anomaly, 0 = normal."""
        return (self.model.predict(np.asarray(X, dtype=float)) == -1).astype(int)

    def row(self, features):
        """One packet's features as a list of numbers, in the order the model was trained on."""
        return [_num(features.get(n, 0)) for n in self.features]

    def score_rows(self, rows):
        """Score MANY packets in one call. Returns (is_anomaly flags, scores).
        One call costs about the same for 1 or 256 rows, so batching is ~200x faster per packet."""
        X = np.asarray(rows, dtype=float)
        iso = self.model[-1]
        s = iso.score_samples(self.model[:-1].transform(X))
        return s < iso.offset_, -s

    def predict(self, features):
        """Live use: return a threat dict if this packet looks anomalous."""
        if not self.ready or not self.live_compatible:
            return None
        X = [[_num(features.get(n, 0)) for n in self.features]]
        if self.predict_array(X)[0]:
            score = float(self.anomaly_scores(X)[0])
            return {'type': 'anomaly', 'rule': 'isolation_forest',
                    'confidence': round(float(np.clip(score, 0, 1)), 3)}
        return None

    # ---------------- persistence ----------------
    def save(self):
        os.makedirs(os.path.dirname(self.model_path) or ".", exist_ok=True)
        joblib.dump({'v': MODEL_VERSION, 'model': self.model, 'n': self.n_trained_on,
                     'features': self.features, 'from': self.trained_from}, self.model_path)

    def load(self):
        try:
            d = joblib.load(self.model_path)
            if d.get('v') != MODEL_VERSION:      # old model, different preprocessing
                return
            self.model, self.n_trained_on = d['model'], d['n']
            self.features, self.trained_from = d['features'], d.get('from')
            self._single_thread()
        except Exception:
            self.model = None