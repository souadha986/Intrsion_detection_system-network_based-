# Network Intrusion Detection System

Signature rules + DDoS detector + Isolation Forest anomaly model, with a dark Streamlit dashboard.

## Run
```
pip install -r requirements.txt
python train_from_dataset.py        # trains from the CSVs in data/  (or use the Model tab)
streamlit run app.py
```
Live capture needs admin/root (and Npcap on Windows): open the terminal as Administrator before `streamlit run app.py`.

## Layout
| File | Role |
|---|---|
| `app.py` | Dashboard (Live monitor, Alerts, Model and dataset) |
| `settings.py` | Dataset path, label names, model and log paths |
| `host_detector.py` | Scan and flood detection per host (quiet on normal traffic) |
| `engine.py` | Glues capture, analysis, detection and alerts together |
| `anomaly_detector.py` | Isolation Forest (trained only on normal traffic) |
| `train_from_dataset.py`, `dataset_loader.py` | Train and evaluate from the CSV dataset |
| `alert_system.py` | Severity, de-duplication, `logs/alerts.jsonl` |
| `Packet_Capture.py`, `traffic_analysis.py`, `signatures.py` | Teammate's modules |
| `packet_sources.py`, `simulator.py` | Simulation and PCAP replay |
| `tests/` | Signature, scapy and model checks |
| `.streamlit/config.toml` | Dark theme |

Put your dataset in `data/` (any CICIDS2017-style CSVs with a `Label` column).
