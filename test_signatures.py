from signatures import check_signatures

def features(**changes):
    f = {
        'packet_size': 500,
        'packet_rate': 10,
        'byte_rate': 5000,
        'tcp_flags': 24,
        'window_size': 1024,
        'flow_duration': 1,
        'distinct_ports': 1,
    }
    f.update(changes)
    return f

def test(name, f):
    rules = [t['rule'] for t in check_signatures(f)]
    print(f"{name}: {rules}")

test("Normal traffic", features())
test("SYN flood", features(packet_size=60, packet_rate=150, tcp_flags=2))
test("DoS flood", features(packet_rate=300, tcp_flags=16))
test("NULL scan", features(tcp_flags=0))
test("XMAS scan", features(tcp_flags=41))
test("SYN+FIN", features(tcp_flags=3))
test("Port scan (30 ports)", features(distinct_ports=30))
test("Few ports (5 ports)", features(distinct_ports=5))