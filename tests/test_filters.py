import pytest

from sharkai.filters import FilterError, compile_filter, describe

PKT = {"n": 7, "src": "10.1.2.3", "dst": "8.8.8.8", "sport": 40000, "dport": 53, "l4": "UDP", "proto": "DNS", "length": 90,
       "rel": 2.5, "info": "Standard query A Evil.Example.com", "dns_name": "evil.example.com", "dns_type": "A"}
TCP = {"n": 8, "src": "10.1.2.3", "dst": "10.9.9.9", "sport": 50000, "dport": 80, "l4": "TCP", "proto": "HTTP", "length": 120, "stream": 3,
       "flags": "PSH,ACK", "http_method": "POST", "http_host": "Shop.local", "http_uri": "/login", "rel": 3.0, "info": ""}


@pytest.mark.parametrize("expr, pkt, want", [
    ("dns", PKT, True), ("http", PKT, False), ("tcp or udp", PKT, True), ("not tcp", PKT, True),
    ("ip.addr == 10.0.0.0/8", PKT, True), ("ip.addr == 192.168.0.0/16", PKT, False), ("ip.dst != 8.8.8.8", PKT, False),
    ("ip.addr != 1.1.1.1", PKT, True), ("port in {53 80}", PKT, True), ("udp.port == 53 && frame.len > 80", PKT, True),
    ("tcp.stream == 3 and http.method == POST", TCP, True), ("http.host contains SHOP", TCP, True),
    ("tcp.flags contains ACK and not tcp.flags contains SYN", TCP, True), ("tcp.port == 80", PKT, False),
    ("dns.qry.name contains EVIL", PKT, True), ("frame.time_rel >= 2.5", PKT, True),
    ("(tcp and tcp.port == 80) or (udp and udp.port == 53)", PKT, True), ('info contains "query a"', PKT, True),
    ("", PKT, True),
])
def test_accepts(expr, pkt, want):
    assert compile_filter(expr)(pkt) is want


@pytest.mark.parametrize("expr", [
    "__import__('os').system('id')", "ip.addr ~= 1", "unknown.field == 1", "tcp.port == abc", "port == 70000", "frame == 1",
    "dns.qry.name matches 'x'", "ip.src contains 1.1", "tcp.port", "(" * 12 + "dns" + ")" * 12, "a" * 400, "dns and", "dns )", "tcp.port in {80",
    "http.host == " + "x" * 200, " and ".join(["tcp.port == 80"] * 25), "tcp.port == 1; DROP TABLE", "ip.addr == 999.1.1.1", "frame contains ''",
    "dns\x00", "frame.number == 1e5",
])
def test_rejects(expr):
    with pytest.raises(FilterError):
        compile_filter(expr)


def test_frame_contains_uses_reader_only_when_asked():
    reads = []
    def reader(p):
        reads.append(p["n"]); return b"xx FLAG{abc} yy"
    assert compile_filter('frame contains "flag{"', reader)(PKT) is True and reads == [7]
    compile_filter("dns", reader)(PKT)
    assert reads == [7]


def test_help_lists_only_allowlisted_fields():
    names = {f["name"] for f in describe()["fields"]}
    assert "ip.addr" in names and "frame" in names and "eval" not in names
