from collections import Counter, defaultdict, deque

from scapy.all import IP

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def _flags(f):
    """Flags as a plain int, ignoring the ECE/CWR bits (0x40/0x80)."""
    return int(f['tcp_flags']) & 0x3F


# Every matching rule fires (this is NOT first-match). Priority is decided by SEVERITY below.
SIGNATURE_RULES = {
    # SYN flood: SYN set, no ACK/RST/FIN, very fast
    'syn_flood': lambda f: (_flags(f) & (SYN | ACK | RST | FIN)) == SYN and f['packet_rate'] > 100,

    # Port scan (simple): lots of tiny packets, fast
    'port_scan': lambda f: f['packet_size'] < 100 and f['packet_rate'] > 50,

    # Real port scan: one source touching many different ports
    'port_scan_multi': lambda f: f.get('distinct_ports', 0) > 20,

    # NULL scan: a packet with no flags at all
    'null_scan': lambda f: _flags(f) == 0,

    # XMAS scan: FIN + PSH + URG (1 + 8 + 32 = 41)
    'xmas_scan': lambda f: _flags(f) == (FIN | PSH | URG),

    # SYN+FIN: start and end a connection at the same time
    'syn_fin': lambda f: (_flags(f) & (SYN | FIN)) == (SYN | FIN),

    # DoS flood: ANY type of packet arriving extremely fast in one flow
    'dos_flood': lambda f: f['packet_rate'] > 200,
}

# Higher = more important. Alerts are raised in this order.
SEVERITY = {
    'ddos': 100, 'syn_flood': 90, 'dos_flood': 80, 'port_scan_multi': 60,
    'port_scan': 50, 'xmas_scan': 40, 'syn_fin': 40, 'null_scan': 30,
}

# Per-packet "odd flags" rules that are just noise while a DDoS is hitting that target
SUPPRESSED_BY_DDOS = {'null_scan', 'syn_fin', 'xmas_scan'}


def check_signatures(features):
    threats = []
    for name, rule in SIGNATURE_RULES.items():
        if rule(features):
            threats.append({'type': 'signature', 'rule': name, 'confidence': 1.0})
    return threats


PRUNE_EVERY = 5000


class DDoSDetector:
    """Many different sources hitting one target within a short window."""

    def __init__(self, window=5, min_sources=20, min_packets=500, cooldown=10, active_for=10):
        self.window = window              # look at the last N seconds
        self.min_sources = min_sources    # how many different attackers
        self.min_packets = min_packets    # how many packets in total
        self.cooldown = cooldown          # at most one ddos alert per target per N seconds
        self.active_for = active_for      # target counts as "under attack" this long after the last trigger
        self.recent = defaultdict(deque)   # target IP -> (time, source IP)
        self._srcs = defaultdict(Counter)  # target IP -> packets per source in the window
        self.active = {}                   # target IP -> last time thresholds were met
        self._last_alert = {}              # target IP -> last time an alert was returned
        self._checks = 0

    def is_active(self, target, now):
        return now - self.active.get(target, float('-inf')) < self.active_for

    def check(self, packet):
        if IP not in packet:
            return []

        target, src = packet[IP].dst, packet[IP].src
        now = float(packet.time)

        q, counts = self.recent[target], self._srcs[target]
        q.append((now, src))
        counts[src] += 1

        # Forget packets older than the window
        while q and now - q[0][0] > self.window:
            _, old = q.popleft()
            counts[old] -= 1
            if counts[old] <= 0:
                del counts[old]

        self._checks += 1
        if self._checks % PRUNE_EVERY == 0:
            self._prune(now)

        if len(q) > self.min_packets and len(counts) > self.min_sources:
            self.active[target] = now
            if now - self._last_alert.get(target, float('-inf')) >= self.cooldown:
                self._last_alert[target] = now
                return [{'type': 'signature', 'rule': 'ddos', 'confidence': 1.0}]
        return []

    def _prune(self, now):
        """Drop targets that went quiet so memory stays bounded."""
        for t in [t for t, q in self.recent.items() if not q or now - q[-1][0] > self.window]:
            del self.recent[t]
            self._srcs.pop(t, None)
        for d in (self.active, self._last_alert):
            for t in [t for t, ts in d.items() if now - ts > 60]:
                del d[t]