"""Turns detected threats into de-duplicated alerts, keeps them in memory and in a JSONL log."""
import json
import logging
import os
import threading
import time
from collections import Counter, deque
from datetime import datetime

import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ids")

SEVERITY = {
    'ddos': 'critical', 'syn_flood': 'critical',
    'dos_flood': 'high', 'port_scan_multi': 'high', 'xmas_scan': 'high',
    'null_scan': 'high', 'syn_fin': 'high',
    'port_scan': 'medium', 'isolation_forest': 'medium',
}

MAX_COOLDOWN_KEYS = 10000     # spoofed floods create a new key per packet; cap the memory


class AlertSystem:
    def __init__(self, log_path=settings.ALERT_LOG, cooldown=3.0, max_alerts=2000):
        self.log_path = log_path
        self.cooldown = cooldown              # seconds before the same rule+source re-alerts
        self.alerts = deque(maxlen=max_alerts)
        self.counts = Counter()
        self._last = {}
        self._lock = threading.Lock()
        self._next_id = 1

    def generate_alert(self, threat, packet_info):
        # a DDoS has hundreds of sources, so de-duplicate it per victim instead
        who = packet_info.get('destination_ip') if threat['rule'] == 'ddos' else packet_info.get('source_ip')
        key = (threat['rule'], who)
        now = time.time()
        with self._lock:
            if now - self._last.get(key, 0) < self.cooldown:
                return None
            self._last[key] = now
            if len(self._last) > MAX_COOLDOWN_KEYS:      # drop expired cooldowns
                cutoff = now - self.cooldown
                self._last = {k: t for k, t in self._last.items() if t > cutoff}
            alert = {
                'id': self._next_id,
                'ts': now,
                'time': datetime.now().strftime("%H:%M:%S"),
                'severity': SEVERITY.get(threat['rule'], 'low'),
                'type': threat['type'],
                'rule': threat['rule'],
                'confidence': threat['confidence'],
                **packet_info,
            }
            self._next_id += 1
            self.alerts.append(alert)
            self.counts[alert['rule']] += 1
        log.warning("[%s] %s from %s -> %s:%s", alert['severity'].upper(), alert['rule'],
                    alert.get('source_ip'), alert.get('destination_ip'), alert.get('destination_port'))
        try:
            os.makedirs(os.path.dirname(self.log_path) or ".", exist_ok=True)
            with open(self.log_path, "a") as fh:
                fh.write(json.dumps(alert) + "\n")
        except OSError:
            pass
        return alert

    def get_alerts(self):
        with self._lock:
            return list(self.alerts)

    def clear(self):
        with self._lock:
            self.alerts.clear()
            self.counts.clear()
            self._last.clear()