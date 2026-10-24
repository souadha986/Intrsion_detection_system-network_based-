"""Scores the SAVED model (trained from the dataset) on simulated traffic. No training happens here."""
import itertools, os, random, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from anomaly_detector import AnomalyDetector, _num
from engine import ml_features
from simulator import attack_burst, normal_stream
from traffic_analysis import TrafficAnalyzer

det = AnomalyDetector()
if not det.ready:
    sys.exit("No trained model found. Run:  python train_from_dataset.py")


def rows(packets, analyzer):
    out = []
    for p in packets:
        f = ml_features(analyzer, p, analyzer.analyze_packet(p))
        out.append([_num(f.get(n, 0)) for n in det.features])
    return out


rng = random.Random(5)
an = TrafficAnalyzer()
warm = list(itertools.islice(normal_stream(rng), 3000))
rows(warm, an)
exfil = rows(attack_burst("exfiltration", float(warm[-1].time) + 0.01, rng), an)
fresh = rows(itertools.islice(normal_stream(random.Random(9)), 6000), TrafficAnalyzer())

print(f"model trained on {det.n_trained_on:,} samples from {det.trained_from}; features: {det.features}")
print(f"normal packets flagged (false positives): {det.predict_array(fresh).mean():.2%}")
print(f"exfiltration packets flagged (last 40 of 60): {det.predict_array(exfil[20:]).mean():.0%}")
