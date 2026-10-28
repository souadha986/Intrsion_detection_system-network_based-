from collections import Counter, defaultdict, deque

from scapy.all import IP, TCP

ACK, RST, SYN = 0x10, 0x04, 0x02
PRUNE_EVERY = 5000      # packets between clean-ups


def _threat(rule):
    return {'type': 'signature', 'rule': rule, 'confidence': 1.0}


def _slide(q, counter, now, window):
    """Drop entries older than the window; returns the dropped entries."""
    gone = []
    while q and now - q[0][0] > window:
        gone.append(q.popleft())
    for e in gone:
        counter[e[1]] -= 1
        if counter[e[1]] <= 0:
            del counter[e[1]]
    return gone


class HostDetector:
    def __init__(self, scan_ports=20, scan_window=5.0, flood_packets=100,
                 flood_window=1.0, flood_max_ports=5):
        self.scan_ports, self.scan_window = scan_ports, scan_window
        self.flood_packets, self.flood_window = flood_packets, flood_window
        self.flood_max_ports = flood_max_ports
        self._probes = defaultdict(deque)       # src -> (time, dport)
        self._probe_ports = defaultdict(Counter)
        self._flood = defaultdict(deque)        # (src, dst) -> (time, dport, is_syn)
        self._flood_ports = defaultdict(Counter)
        self._flood_syns = defaultdict(int)
        self._checks = 0

    def check(self, packet):
        if IP not in packet or TCP not in packet:
            return []
        flags = int(packet[TCP].flags)
        if flags & (ACK | RST):
            return []
        now, src, dst, dport = float(packet.time), packet[IP].src, packet[IP].dst, packet[TCP].dport
        threats = []

        # ---- port scan: many different ports from one source ----
        q, c = self._probes[src], self._probe_ports[src]
        q.append((now, dport))
        c[dport] += 1
        _slide(q, c, now, self.scan_window)
        if len(c) > self.scan_ports:
            threats.append(_threat('port_scan_multi'))

        # ---- flood: lots of probes at the same few ports ----
        key = (src, dst)
        q, c = self._flood[key], self._flood_ports[key]
        is_syn = flags == SYN
        q.append((now, dport, is_syn))
        c[dport] += 1
        self._flood_syns[key] += is_syn
        for _, _, s in _slide(q, c, now, self.flood_window):
            self._flood_syns[key] -= s
        if len(q) > self.flood_packets and len(c) <= self.flood_max_ports:
            threats.append(_threat('syn_flood' if self._flood_syns[key] >= 0.8 * len(q) else 'dos_flood'))

        self._checks += 1
        if self._checks % PRUNE_EVERY == 0:
            self._prune(now)
        return threats

    def _prune(self, now):
        """Forget sources/pairs that went quiet so memory stays bounded (spoofed floods)."""
        for k in [k for k, q in self._probes.items() if not q or now - q[-1][0] > self.scan_window]:
            del self._probes[k]
            self._probe_ports.pop(k, None)
        for k in [k for k, q in self._flood.items() if not q or now - q[-1][0] > self.flood_window]:
            del self._flood[k]
            self._flood_ports.pop(k, None)
            self._flood_syns.pop(k, None)