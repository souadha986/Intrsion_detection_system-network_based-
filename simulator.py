
import random
import time
from scapy.all import IP, TCP, Raw

SERVER = "10.0.0.1"


def _pkt(src, sport, dport, flags, t, payload=0, window=29200):
    p = IP(src=src, dst=SERVER) / TCP(sport=sport, dport=dport, flags=flags, window=window)
    if payload:
        p = p / Raw(b"x" * payload)
    p.time = t
    return p


def normal_stream(rng=None, start=None):
    rng = rng or random.Random()
    t = start or time.time()
    clients = [f"192.168.1.{i}" for i in range(10, 40)]
    sessions = {}
    while True:
        c = rng.choice(clients)
        if c not in sessions or rng.random() < 0.02:
            sessions[c] = (rng.randint(30000, 60000), rng.choice([80, 443, 443, 22, 8080]))
        sport, dport = sessions[c]
        t += rng.expovariate(40)
        yield _pkt(c, sport, dport, rng.choice(["PA", "A", "A", "PA"]), t,
                   payload=rng.choice([0, 0, 100, 300, 600, 1000, 1400]),
                   window=rng.choice([8192, 16384, 29200, 65535]))


def attack_burst(kind, t, rng):
    atk = f"203.0.113.{rng.randint(2, 250)}"
    sport = rng.randint(1024, 65000)
    out = []
    if kind == "syn_flood":
        out = [_pkt(atk, sport, 80, "S", t + i * 0.004) for i in range(250)]
    elif kind == "port_scan":
        out = [_pkt(atk, sport + i, 1000 + i, "S", t + i * 0.02) for i in range(40)]
    elif kind == "null_scan":
        out = [_pkt(atk, sport, 22, "", t)]
    elif kind == "xmas_scan":
        out = [_pkt(atk, sport, 22, "FPU", t)]
    elif kind == "ddos":
        for i in range(700):
            src = f"198.51.{i % 40}.{i % 250 + 1}"
            out.append(_pkt(src, 4000 + i, 80, "S", t + i * 0.002))
    elif kind == "exfiltration":   # NOT covered by any signature -> only the ML model can catch it
        insider = f"192.168.1.{rng.randint(10, 39)}"      # ONE compromised host
        out = [_pkt(insider, sport, 4444, "PA", t + i * 0.02,
                    payload=1400, window=65535) for i in range(60)]
    return out


ATTACKS = ["syn_flood", "port_scan", "null_scan", "xmas_scan", "ddos", "exfiltration"]


def mixed_stream(attack_prob=0.002, seed=None):
    rng = random.Random(seed)
    normal = normal_stream(rng)
    for p in normal:
        yield p
        if rng.random() < attack_prob:
            burst = attack_burst(rng.choice(ATTACKS), float(p.time) + 0.01, rng)
            for b in burst:
                yield b
