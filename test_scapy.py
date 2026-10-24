from scapy.all import IP, TCP, Raw
from traffic_analysis_modifie import TrafficAnalyzer
from signatures import check_signatures, DDoSDetector

def run_test(name, packets):
    analyzer = TrafficAnalyzer()
    threats = []
    for p in packets:
        features = analyzer.analyze_packet(p)
        threats = check_signatures(features)
    print(f"{name}: {[t['rule'] for t in threats]}")

# SYN flood: 200 SYN packets, ~200 per second, one conversation
flood = []
for i in range(200):
    p = IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=4444, dport=80, flags="S")
    p.time = i * 0.005
    flood.append(p)
run_test("SYN flood", flood)

# Normal traffic: big packets, 2 per second
normal = []
for i in range(10):
    p = IP(src="10.0.0.7", dst="10.0.0.1") / TCP(sport=5555, dport=80, flags="PA") / Raw(b"x" * 500)
    p.time = i * 0.5
    normal.append(p)
run_test("Normal traffic", normal)

# Single-packet flag tests
for label, flags in [("NULL scan", ""), ("XMAS scan", "FPU"), ("SYN+FIN", "SF")]:
    p = IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=6000, dport=22, flags=flags)
    p.time = 0
    run_test(label, [p])

# Port scan: one source, 30 different ports
scan = []
for i in range(30):
    p = IP(src="10.0.0.9", dst="10.0.0.1") / TCP(sport=6000 + i, dport=1000 + i, flags="S")
    p.time = i * 0.01
    scan.append(p)
run_test("Port scan", scan)

# DDoS: 600 packets from many different sources, all within ~1 second
detector = DDoSDetector()
result = []
for i in range(600):
    src = f"10.0.{i % 30}.{i % 250 + 1}"
    p = IP(src=src, dst="10.0.0.1") / TCP(sport=4000 + i, dport=80, flags="S")
    p.time = i * 0.002
    result = detector.check(p)
print(f"DDoS (many sources): {[t['rule'] for t in result]}")

# Same number of packets from ONE source: should NOT be a DDoS
detector = DDoSDetector()
result = []
for i in range(600):
    p = IP(src="10.0.0.99", dst="10.0.0.1") / TCP(sport=4000 + i, dport=80, flags="S")
    p.time = i * 0.002
    result = detector.check(p)
print(f"DDoS (one source): {[t['rule'] for t in result]}")