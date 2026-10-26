# Network Intrusion Detection System
Network Intrusion Detection System (NIDS)

An Intrusion Detection System (IDS) acts like a security camera for your network. Just as physical security cameras monitor spaces for suspicious activity, an IDS inspects network traffic in real time to identify cyber attacks and security breaches.

This repository provides a hybrid NIDS built with Python, Scapy, Scikit-Learn, and Streamlit. It combines multi-threaded packet processing, rule-based signature checks, and machine learning (Isolation Forest) to analyze live network streams.

 System Architecture

The NIDS consists of four core components:

Packet Capture Engine (Packet_Capture.py)
Uses Scapy to perform promiscuous packet sniffing on live network interfaces (eth0, lo), placing raw IP/TCP packets into a thread-safe queue.

Traffic Analysis Module (traffic_analysis.py)
Groups individual packets into connection flows to track duration, packet counts, byte counts, TCP flag distributions, and packet rates in real time.

Detection Engine (engine.py, signatures.py, anomaly_detector.py)

Signature-Based: Matches known attack patterns (e.g., SYN floods, port scans).

Anomaly-Based: Evaluates flow features using an Isolation Forest model trained on the CICIDS2017 dataset to flag unknown (zero-day) behavior.

Alert System (alert_system.py)
Logs structured JSON threat alerts (logs/alerts.jsonl) and escalates high-confidence detections for live display on the Streamlit dashboard.




