from collections import defaultdict, deque
from scapy.all import IP

SIGNATURE_RULES = {
    # SYN flood: lots of SYN packets, very fast
    'syn_flood': lambda f: int(f['tcp_flags']) == 2 and f['packet_rate'] > 100,

    # Port scan (simple): lots of tiny packets, fast
    'port_scan': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50,


    # Real port scan: one source touching many different ports
    'port_scan_multi': lambda f: f.get('distinct_ports', 0) > 20,

    # NULL scan: a packet with no flags at all
    'null_scan': lambda f: int(f['tcp_flags']) == 0,

    # XMAS scan: FIN + PSH + URG set together (1 + 8 + 32 = 41)
    'xmas_scan': lambda f: int(f['tcp_flags']) == 41,

    # SYN+FIN: start and end a connection at the same time (2 + 1 = 3)
    'syn_fin': lambda f: int(f['tcp_flags']) == 3,

    # DoS flood: ANY type of packet arriving extremely fast in one flow
    'dos_flood': lambda f: f['packet_rate'] > 200,

    # Real port scan: one source touching many different ports
    'port_scan_multi': lambda f: f.get('distinct_ports', 0) > 20,
}


def check_signatures(features):
    threats = []
    for name, rule in SIGNATURE_RULES.items():
        if rule(features):
            threats.append({
                'type': 'signature',
                'rule': name,
                'confidence': 1.0
            })
    return threats

#------------------------detector.check(packet) for each captured packet in main.py---------------------------
class DDoSDetector:
    def __init__(self, window=5, min_sources=20, min_packets=500):
        self.window = window              # look at the last 5 seconds
        self.min_sources = min_sources    # how many different attackers
        self.min_packets = min_packets    # how many packets in total
        self.recent = defaultdict(deque)  # target IP -> list of (time, source IP)

    def check(self, packet):
        if IP not in packet:
            return []

        target = packet[IP].dst
        now = packet.time

        # Remember this packet
        q = self.recent[target]
        q.append((now, packet[IP].src))

        # Forget packets older than the window
        while q and now - q[0][0] > self.window:
            q.popleft()

        # Count how many different sources are hitting this target
        sources = {src for _, src in q}

        if len(q) > self.min_packets and len(sources) > self.min_sources:
            return [{'type': 'signature', 'rule': 'ddos', 'confidence': 1.0}]
        return []