import queue
import threading
import time
from collections import Counter, deque

from scapy.all import IP, TCP

from alert_system import AlertSystem
from anomaly_detector import AnomalyDetector
from host_detector import HostDetector
from packet_sources import make_capture
from signatures import DDoSDetector, check_signatures, SEVERITY, SUPPRESSED_BY_DDOS
from traffic_analysis import TrafficAnalyzer

MIN_FLOW_PACKETS = 20      # a flow's rate is meaningless before this many packets
IGNORE_PORTS = {8501}      # the dashboard's own traffic
# per-flow "speed" rules that misfire on normal traffic; HostDetector replaces them
DISABLED_RULES = {'port_scan', 'port_scan_multi', 'dos_flood', 'syn_flood'}

ML_BATCH = 256             # packets scored per model call
ML_QUEUE = 5000            # if the model falls this far behind, new packets skip it
ML_MIN_HITS = 5            # anomalous packets from one source within 10 s before an anomaly alert
ML_PRUNE_EVERY = 1000


def ml_features(analyzer, packet, features):
    """Zero the rates until the flow has enough packets (see MIN_FLOW_PACKETS)."""
    stats = getattr(analyzer, "flow_stats", {}).get(
        (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport))
    if stats and stats['packet_count'] < MIN_FLOW_PACKETS:
        features = dict(features, packet_rate=0, byte_rate=0)
    return features


class DetectionEngine:
    """Signature rules + host scan/flood detector + DDoS detector. (The model runs in its own thread.)"""
    def __init__(self, anomaly):
        self.anomaly = anomaly
        self.ddos = DDoSDetector()
        self.hosts = HostDetector()
        self.use_anomaly = False              # off by default; the UI switch turns it on
        self._ml_hits = {}
        self._ml_calls = 0

    def detect_threats(self, packet, features, ml_feats=None):
        """All threats for one packet, most severe first.

        check_signatures() is NOT first-match: every matching rule fires. Order and
        suppression are decided here, explicitly.
        """
        now = float(packet.time)
        target = packet[IP].dst

        threats = [t for t in check_signatures(ml_feats or features) if t['rule'] not in DISABLED_RULES]
        threats += self.hosts.check(packet)
        threats += self.ddos.check(packet)          # updates the DDoS incident state

        # While a DDoS is active against this target, per-packet odd-flag alerts are just noise
        if self.ddos.is_active(target, now):
            threats = [t for t in threats if t['rule'] not in SUPPRESSED_BY_DDOS]

        threats.sort(key=lambda t: SEVERITY.get(t['rule'], 50), reverse=True)
        return threats

    def confirm_anomaly(self, src):
        """One odd packet is normal noise; an attack makes several in a row from the same source."""
        now = time.time()
        hits = self._ml_hits.setdefault(src, deque())
        hits.append(now)
        while hits and now - hits[0] > 10:
            hits.popleft()
        confirmed = len(hits) >= ML_MIN_HITS

        self._ml_calls += 1
        if self._ml_calls % ML_PRUNE_EVERY == 0:      # keep memory bounded
            for s in [s for s, h in self._ml_hits.items() if not h or now - h[-1] > 10]:
                del self._ml_hits[s]
        return confirmed


class IntrusionDetectionSystem:
    def __init__(self, interface="eth0", source="live", pcap_path=None, anomaly=None,
                 alert_system=None, attack_prob=0.002):
        self.interface, self.source = interface, source
        self.packet_capture = make_capture(source, pcap_path, attack_prob)
        self.traffic_analyzer = TrafficAnalyzer()
        self.anomaly = anomaly or AnomalyDetector()
        self.detection_engine = DetectionEngine(self.anomaly)
        self.alert_system = alert_system or AlertSystem()

        self._stop = threading.Event()
        self._thread = self._ml_thread = None
        self._ml_queue = queue.Queue(maxsize=ML_QUEUE)
        self._lock = threading.Lock()
        self.total_packets = 0
        self.errors, self.last_error = 0, None
        self.ml_skipped = 0
        self.top_sources = Counter()
        self.history = deque(maxlen=300)                       # one entry per second
        self._sec, self._sec_pkts, self._sec_alerts = int(time.time()), 0, 0
        self.running = False

    # ---- status helpers for the UI ----
    @property
    def dropped(self):
        return getattr(self.packet_capture, "dropped", 0)

    @property
    def backlog(self):
        """Packets captured but not analysed yet (should stay near 0)."""
        return self.packet_capture.packet_queue.qsize()

    @property
    def capture_error(self):
        cap = self.packet_capture
        if getattr(cap, "error", None):
            return cap.error
        t = getattr(cap, "capture_thread", None)
        if self.running and t is not None and not t.is_alive() and not self._stop.is_set():
            return "Capture thread stopped - live capture needs root/admin and a valid interface name."
        return None

    # ---- lifecycle ----
    def start(self):
        self._stop.clear()
        self.running = True
        self.packet_capture.start_capture(self.interface)
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._ml_thread = threading.Thread(target=self._ml_loop, daemon=True)
        self._thread.start()
        self._ml_thread.start()

    def stop(self):
        self._stop.set()
        if self.source == "live":
            # PacketCapture.stop() joins a sniff() that only checks the stop flag when a packet
            # arrives, so run it in the background so the UI never freezes
            threading.Thread(target=self.packet_capture.stop, daemon=True).start()
        else:
            self.packet_capture.stop()
        for t in (self._thread, self._ml_thread):
            if t:
                t.join(timeout=3)
        self.running = False

    def _loop(self):
        while not self._stop.is_set():
            try:
                packet = self.packet_capture.packet_queue.get(timeout=0.2)
            except queue.Empty:
                if getattr(self.packet_capture, "finished", False):
                    break                      # pcap replay finished
                continue
            self._process(packet)
        self.running = False

    def _fail(self, e):
        with self._lock:
            self.errors += 1
            self.last_error = f"{type(e).__name__}: {e}"

    def _raise(self, threat, info):
        """Send one threat to the alert system and update the dashboard counters."""
        if self.alert_system.generate_alert(threat, info):
            with self._lock:
                self.top_sources[info['source_ip']] += 1
                self._sec_alerts += 1

    # ---- lane 1: signatures, on every packet ----
    def _process(self, packet):
        try:
            if IP not in packet or TCP not in packet:
                return
            if packet[TCP].sport in IGNORE_PORTS or packet[TCP].dport in IGNORE_PORTS:
                return
            features = self.traffic_analyzer.analyze_packet(packet)
            if not features:
                return
            ml_feats = ml_features(self.traffic_analyzer, packet, features)
            info = {'source_ip': packet[IP].src, 'destination_ip': packet[IP].dst,
                    'source_port': packet[TCP].sport, 'destination_port': packet[TCP].dport}
            for threat in self.detection_engine.detect_threats(packet, features, ml_feats):
                self._raise(threat, info)

            if self.detection_engine.use_anomaly and self.anomaly.ready and self.anomaly.live_compatible:
                try:
                    self._ml_queue.put_nowait((info, self.anomaly.row(ml_feats)))
                except queue.Full:
                    with self._lock:
                        self.ml_skipped += 1   # model is behind: skip it, never slow the signatures
        except Exception as e:                 # never let one bad packet kill the IDS
            self._fail(e)                      # still counted below, so totals match reality

        with self._lock:
            self.total_packets += 1
            sec = int(time.time())
            if sec != self._sec:
                self.history.append({'second': self._sec, 'packets': self._sec_pkts,
                                     'alerts': self._sec_alerts})
                self._sec, self._sec_pkts, self._sec_alerts = sec, 0, 0
            self._sec_pkts += 1

    # ---- lane 2: Isolation Forest, in batches ----
    def _ml_loop(self):
        while not self._stop.is_set():
            try:
                batch = [self._ml_queue.get(timeout=0.2)]
            except queue.Empty:
                continue
            while len(batch) < ML_BATCH:
                try:
                    batch.append(self._ml_queue.get_nowait())
                except queue.Empty:
                    break
            try:
                flags, scores = self.anomaly.score_rows([row for _, row in batch])
                for (info, _), flag, score in zip(batch, flags, scores):
                    if flag and self.detection_engine.confirm_anomaly(info['source_ip']):
                        self._raise({'type': 'anomaly', 'rule': 'isolation_forest',
                                     'confidence': round(float(min(max(score, 0), 1)), 3)}, info)
            except Exception as e:
                self._fail(e)

    def snapshot(self):
        with self._lock:
            return {'total_packets': self.total_packets, 'history': list(self.history),
                    'top_sources': dict(self.top_sources.most_common(10))}


if __name__ == "__main__":
    ids = IntrusionDetectionSystem(source="live")
    ids.start()
    try:
        while ids.running:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Stopping IDS...")
        ids.stop()