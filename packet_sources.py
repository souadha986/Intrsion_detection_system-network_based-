"""Packet sources: live capture (teammate's PacketCapture), simulation, pcap replay.
All expose  .packet_queue  .start_capture(interface)  .stop()"""
import queue
import threading
import time

from scapy.all import IP, TCP, PcapReader

from Packet_Capture import PacketCapture      # teammate's live capture, untouched
from simulator import mixed_stream


class ReplayCapture:
    def __init__(self, source="simulation", pcap_path=None, attack_prob=0.002, maxsize=20000):
        self.source, self.pcap_path, self.attack_prob = source, pcap_path, attack_prob
        self.packet_queue = queue.Queue(maxsize=maxsize)
        self.stop_capture = threading.Event()
        self.finished, self.error, self.dropped = False, None, 0
        self.capture_thread = None

    def _put(self, packet):
        if IP not in packet or TCP not in packet:
            return
        while not self.stop_capture.is_set():
            try:
                self.packet_queue.put(packet, timeout=0.5)
                return
            except queue.Full:
                pass

    def _run(self):
        try:
            if self.source == "pcap":
                with PcapReader(self.pcap_path) as reader:
                    for p in reader:
                        if self.stop_capture.is_set():
                            break
                        self._put(p)
            else:
                for p in mixed_stream(self.attack_prob):
                    if self.stop_capture.is_set():
                        break
                    self._put(p)
                    time.sleep(0.002)
        except Exception as e:
            self.error = f"{type(e).__name__}: {e}"
        finally:
            self.finished = True

    def start_capture(self, interface=None):
        self.stop_capture.clear()
        self.capture_thread = threading.Thread(target=self._run, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.stop_capture.set()
        if self.capture_thread:
            self.capture_thread.join(timeout=3)


def make_capture(source, pcap_path=None, attack_prob=0.002):
    return PacketCapture() if source == "live" else ReplayCapture(source, pcap_path, attack_prob)

def list_interfaces():
    """[(label, scapy_name, ip)] for the interface picker, real network cards first."""
    out = []
    try:
        from scapy.all import conf
        for i in conf.ifaces.values():
            ip = getattr(i, "ip", "") or ""
            out.append((f"{i.name}  ({ip})" if ip else i.name, i.name, ip))
    except Exception:
        pass
    good = lambda r: bool(r[2]) and not r[2].startswith(("127.", "0.", "169.254."))
    out.sort(key=lambda r: not good(r))
    return out or [("eth0", "eth0", "")]
