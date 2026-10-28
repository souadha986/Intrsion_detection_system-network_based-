from collections import Counter, defaultdict, deque

from scapy.all import IP, TCP

PORT_WINDOW = 5          # seconds used for distinct_ports
FLOW_IDLE = 15           # forget flows that were silent this long
PRUNE_EVERY = 5000       # packets between clean-ups


class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
        })
        # source IP -> deque of (time, destination port), plus a running count per port
        self.port_history = defaultdict(deque)
        self._port_count = defaultdict(Counter)
        self._seen = 0

    def analyze_packet(self, packet):
        if IP not in packet or TCP not in packet:
            return None

        ip_src, ip_dst = packet[IP].src, packet[IP].dst
        port_src, port_dst = packet[TCP].sport, packet[TCP].dport
        now = float(packet.time)

        # Per-conversation tally
        # NOTE: a flood with random source ports makes a new flow per packet, so per-flow
        # rates stay at 0 for it. That is why HostDetector/DDoSDetector exist.
        flow_key = (ip_src, ip_dst, port_src, port_dst)
        stats = self.flow_stats[flow_key]
        stats['packet_count'] += 1
        stats['byte_count'] += len(packet)
        if stats['start_time'] is None:
            stats['start_time'] = now
        stats['last_time'] = now

        # Per-attacker tally: ports touched in the last PORT_WINDOW s (incremental, O(1))
        history, count = self.port_history[ip_src], self._port_count[ip_src]
        history.append((now, port_dst))
        count[port_dst] += 1
        while history and now - history[0][0] > PORT_WINDOW:
            _, old = history.popleft()
            count[old] -= 1
            if count[old] <= 0:
                del count[old]

        features = self.extract_features(packet, stats)
        features['distinct_ports'] = len(count)

        self._seen += 1
        if self._seen % PRUNE_EVERY == 0:
            self._prune(now)
        return features

    def _prune(self, now):
        """Keep memory bounded."""
        for k in [k for k, s in self.flow_stats.items() if now - s['last_time'] > FLOW_IDLE]:
            del self.flow_stats[k]
        for ip in [ip for ip, h in self.port_history.items() if not h or now - h[-1][0] > PORT_WINDOW]:
            del self.port_history[ip]
            self._port_count.pop(ip, None)

    def extract_features(self, packet, stats):
        duration = stats['last_time'] - stats['start_time']

        if duration > 0:
            packet_rate = stats['packet_count'] / duration
            byte_rate = stats['byte_count'] / duration
        else:
            packet_rate = 0
            byte_rate = 0

        return {
            'packet_size': len(packet),
            'flow_duration': duration,
            'packet_rate': packet_rate,
            'byte_rate': byte_rate,
            'tcp_flags': int(packet[TCP].flags),   # plain int, not scapy's FlagValue
            'window_size': packet[TCP].window,
        }