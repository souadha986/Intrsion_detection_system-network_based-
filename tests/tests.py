"""Offline tests for signatures.py, traffic_analysis.py and DetectionEngine.
Run:  pytest -v test_ids.py
No root, network or real capture needed: packets are crafted with scapy.
"""
import sys
import types

import pytest
from scapy.all import IP, TCP

# --- use the real modules when they import; stub them only if they can't (e.g. no sklearn) ---
import importlib

_STUBS = {
    "settings": {"ALERT_LOG": "alerts_test.jsonl"},
    "alert_system": {"AlertSystem": object},
    "anomaly_detector": {"AnomalyDetector": object},
    "host_detector": {"HostDetector": type("HostDetector", (), {"check": lambda self, p: []})},
    "packet_sources": {"make_capture": lambda *a, **k: None},
}
for _name, _attrs in _STUBS.items():
    try:
        importlib.import_module(_name)
    except Exception:
        _mod = types.ModuleType(_name)
        _mod.__dict__.update(_attrs)
        sys.modules[_name] = _mod

from engine import DetectionEngine, ml_features          # noqa: E402
from signatures import DDoSDetector, check_signatures    # noqa: E402
from traffic_analysis import TrafficAnalyzer             # noqa: E402


def pkt(src="10.0.0.1", dst="10.0.0.99", sport=1234, dport=80, flags="A", t=0.0):
    p = IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags)
    p.time = t
    return p


def feats(flags, rate=0, size=60, ports=0):
    return {"tcp_flags": int(flags), "packet_rate": rate, "packet_size": size,
            "distinct_ports": ports}


def rules(threats):
    return {t["rule"] for t in threats}


# ---------------- signatures ----------------
def test_null_xmas_synfin_detected():
    assert "null_scan" in rules(check_signatures(feats(0)))
    assert "xmas_scan" in rules(check_signatures(feats(0x29)))
    assert "syn_fin" in rules(check_signatures(feats(0x03)))


def test_normal_traffic_is_clean():
    for flags in (0x10, 0x18, 0x11, 0x12, 0x04):     # ACK, PSH+ACK, FIN+ACK, SYN+ACK, RST
        assert check_signatures(feats(flags)) == []


def test_ecn_bits_do_not_hide_a_syn_flood():
    assert "syn_flood" in rules(check_signatures(feats(0x42, rate=500)))   # SYN+ECE
    assert "syn_flood" not in rules(check_signatures(feats(0x12, rate=500)))  # SYN+ACK


def test_all_matching_rules_fire_not_first_match():
    r = rules(check_signatures(feats(0x02, rate=500, size=40)))
    assert {"syn_flood", "dos_flood", "port_scan"} <= r


# ---------------- DDoS detector ----------------
def flood(d, n, start=0.0, step=0.005, sources=30, flags="S"):
    out = []
    for i in range(n):
        out += d.check(pkt(src=f"10.1.0.{i % sources}", t=start + i * step, flags=flags))
    return out


def test_ddos_fires_once_not_per_packet():
    d = DDoSDetector()
    alerts = flood(d, 1000)                    # 5 s, 30 sources
    assert len(alerts) == 1 and alerts[0]["rule"] == "ddos"
    assert d.is_active("10.0.0.99", 5.0)


def test_ddos_refires_after_cooldown():
    d = DDoSDetector()
    assert len(flood(d, 1000)) == 1
    assert len(flood(d, 1000, start=20.0)) == 1


def test_no_ddos_with_few_sources_or_few_packets():
    assert flood(DDoSDetector(), 1000, sources=5) == []
    assert flood(DDoSDetector(), 300) == []


def test_ddos_state_is_pruned():
    d = DDoSDetector()
    flood(d, 1000)
    d._prune(now=500.0)
    assert not d.recent and not d._srcs and not d.active and not d._last_alert


# ---------------- engine: DDoS vs NULL scan ----------------
def test_ddos_with_null_flags_reports_ddos_first_then_suppresses_null_scan():
    eng = DetectionEngine(anomaly=None)
    an = TrafficAnalyzer()
    seen = []
    for i in range(1000):
        p = pkt(src=f"10.1.0.{i % 30}", sport=1000 + i, flags=0, t=i * 0.005)
        f = an.analyze_packet(p)
        seen.append([t["rule"] for t in eng.detect_threats(p, f, ml_features(an, p, f))])
    first_ddos = next(i for i, r in enumerate(seen) if "ddos" in r)
    assert seen[first_ddos][0] == "ddos"                     # highest severity first
    assert all("null_scan" not in r for r in seen[first_ddos:])   # suppressed afterwards
    assert any("null_scan" in r for r in seen[:first_ddos])  # still reported before the incident


def test_null_scan_still_reported_without_ddos():
    eng = DetectionEngine(anomaly=None)
    an = TrafficAnalyzer()
    p = pkt(flags=0)
    f = an.analyze_packet(p)
    assert "null_scan" in rules(eng.detect_threats(p, f, ml_features(an, p, f)))


# ---------------- traffic analyzer ----------------
def test_distinct_ports_counts_a_scan():
    an = TrafficAnalyzer()
    f = None
    for i in range(25):
        f = an.analyze_packet(pkt(dport=1000 + i, t=i * 0.1, flags="S"))
    assert f["distinct_ports"] == 25
    assert isinstance(f["tcp_flags"], int)


def test_distinct_ports_window_expires():
    an = TrafficAnalyzer()
    for i in range(25):
        an.analyze_packet(pkt(dport=1000 + i, t=i * 0.1))
    f = an.analyze_packet(pkt(dport=80, t=60.0))
    assert f["distinct_ports"] == 1


def test_non_tcp_returns_none():
    assert TrafficAnalyzer().analyze_packet(IP(src="1.1.1.1", dst="2.2.2.2")) is None


def test_prune_keeps_memory_bounded():
    an = TrafficAnalyzer()
    for i in range(50):
        an.analyze_packet(pkt(sport=2000 + i, t=0.0))
    an._prune(now=100.0)
    assert not an.flow_stats and not an.port_history


# ---------------- host detector ----------------
def test_host_detector_finds_scan_and_flood_and_prunes():
    hd = pytest.importorskip("host_detector")
    if not hasattr(hd.HostDetector, "_prune"):
        pytest.skip("stubbed HostDetector")
    d = hd.HostDetector()
    found = set()
    for i in range(30):                                   # one source, 30 ports, SYN only
        found |= rules(d.check(pkt(dport=1000 + i, flags="S", t=i * 0.05)))
    assert "port_scan_multi" in found
    d2 = hd.HostDetector()
    found = set()
    for i in range(150):                                  # same 2 ports, very fast, all SYN
        found |= rules(d2.check(pkt(dport=80 + i % 2, flags="S", t=i * 0.001)))
    assert "syn_flood" in found
    d._prune(now=1000.0)
    assert not d._probes and not d._flood and not d._flood_syns


# ---------------- alert system ----------------
def test_alert_system_dedups_ddos_per_victim_and_prunes(tmp_path):
    al_mod = pytest.importorskip("alert_system")
    if al_mod.AlertSystem is object:
        pytest.skip("stubbed AlertSystem")
    al = al_mod.AlertSystem(log_path=str(tmp_path / "a.jsonl"), cooldown=3.0)
    t = {"type": "signature", "rule": "ddos", "confidence": 1.0}
    got = [al.generate_alert(t, {"source_ip": f"1.1.1.{i}", "destination_ip": "9.9.9.9"})
           for i in range(50)]
    assert sum(a is not None for a in got) == 1           # one alert per victim
    for i in range(al_mod.MAX_COOLDOWN_KEYS + 5):         # many sources -> cooldown table must not grow forever
        al._last[("null_scan", f"s{i}")] = 0              # long expired
    al.generate_alert({"type": "signature", "rule": "null_scan", "confidence": 1.0},
                      {"source_ip": "x", "destination_ip": "y"})
    assert len(al._last) < 100