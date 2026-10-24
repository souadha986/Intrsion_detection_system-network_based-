from collections import defaultdict
from scapy.all import IP, TCP


class TrafficAnalyzer:
    def __init__(self):
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None
        })
        # source IP -> list of (time, destination port)
        self.port_history = defaultdict(list)

    def analyze_packet(self, packet):
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport
            now = float(packet.time)

            # Per-conversation tally (same as before)
            flow_key = (ip_src, ip_dst, port_src, port_dst)
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            if stats['start_time'] is None:
                stats['start_time'] = now
            stats['last_time'] = now

            # Per-attacker tally: which ports has this IP touched in the last 5 seconds?
            history = self.port_history[ip_src]
            history.append((now, port_dst))
            history[:] = [(t, p) for t, p in history if now - t <= 5]

            features = self.extract_features(packet, stats)
            features['distinct_ports'] = len({p for _, p in history})
            return features

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
            'tcp_flags': packet[TCP].flags,
            'window_size': packet[TCP].window
        }