import base64
import gzip

import pytest

from sharkai import dnsparse, httpparse
from sharkai.analyzer import analyze_capture
from sharkai.capture_io import CaptureFormatError, CaptureReader
from sharkai.decode import decode_frame
from sharkai.samples import DEMO_FLAGS, CaptureBuilder, dns_response
from sharkai.streams import StreamTable


def reassemble(builder: CaptureBuilder):
    table = StreamTable(10**7)
    for raw, frame in CaptureReader(builder.to_pcap()).packets():
        d = decode_frame(frame, raw.linktype)
        if d.l4 == "TCP":
            table.add(raw.number, raw.ts, d)
    return table.finalize()


def test_reassembly_handles_reorder_and_duplicates():
    msg = bytes(range(256)) * 20
    cap = CaptureBuilder()
    cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 80, [("c", msg)], mss=500, shuffle=True, duplicate_first=True)
    (s,) = reassemble(cap)
    assert s.data[0] == msg and s.retransmits >= 1 and s.gaps == 0 and s.state == "closed"


def test_reassembly_reports_gaps_and_sequence_wrap():
    cap = CaptureBuilder()
    cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 80, [("c", b"A" * 3000)], mss=1000, isn_c=0xFFFFFF00)
    (s,) = reassemble(cap)
    assert s.data[0] == b"A" * 3000
    cap.frames = [f for i, f in enumerate(cap.frames) if i != 4]  # drop a middle data segment
    (s,) = reassemble(cap)
    assert s.gaps == 1 and len(s.data[0]) == 2000


def test_port_reuse_creates_new_stream():
    cap = CaptureBuilder()
    for payload in (b"first", b"second"):
        cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 80, [("c", payload)])
    assert [s.data[0] for s in reassemble(cap)] == [b"first", b"second"]


def test_http_chunked_gzip_and_pipelining():
    body = gzip.compress(b"hello world" * 10)
    raw = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n"
           + f"{len(body):x}\r\n".encode() + body + b"\r\n0\r\n\r\n"
           + b"HTTP/1.1 404 Not Found\r\nContent-Length: 3\r\n\r\nnop")
    first, second = httpparse.parse_responses(raw)
    assert first.decoded_body == b"hello world" * 10 and second.status == 404 and second.body == b"nop"


def test_http_multipart_and_gzip_bomb_is_bounded():
    ct = "multipart/form-data; boundary=XX"
    body = b'--XX\r\nContent-Disposition: form-data; name="f"; filename="a.txt"\r\n\r\nDATA\r\n--XX--\r\n'
    assert httpparse.parse_multipart(body, ct)[0]["filename"] == "a.txt"
    out, _ = httpparse.decode_body(gzip.compress(b"\x00" * 1000), "gzip")
    assert out == b"\x00" * 1000
    assert httpparse.decode_body(b"not gzip", "gzip")[1]  # reports instead of raising


def test_dns_parser_compression_loop_and_truncation():
    resp = dnsparse.parse(dns_response("x.example.com", "1.2.3.4"))
    assert resp["answers"][0]["data"] == "1.2.3.4" and resp["response"]
    loop = b"\x00\x01\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xc0\x0c\x00\x01\x00\x01"
    assert dnsparse.parse(loop) is None
    assert dnsparse.parse(dns_response("x.example.com", "1.2.3.4")[:20]) is None


@pytest.fixture(scope="module")
def demo(tmp_path_factory, demo_pcap):
    from sharkai.config import Settings
    d = tmp_path_factory.mktemp("cap")
    (d / "original.bin").write_bytes(demo_pcap)
    return analyze_capture(d / "original.bin", d, Settings())


def test_demo_finds_every_hidden_flag(demo):
    found = {f["flag"] for f in demo["flags"]}
    assert found == set(DEMO_FLAGS.values())
    by = {f["flag"]: f for f in demo["flags"]}
    assert by[DEMO_FLAGS["b64"]]["encoding"] == "base64" and by[DEMO_FLAGS["ftp"]]["encoding"] == "hex"
    assert by[DEMO_FLAGS["split"]]["locations"][0]["source"] == "stream"   # needed reassembly
    assert by[DEMO_FLAGS["icmp"]]["locations"][0]["source"] == "packet"


def test_demo_http_files_creds_and_alerts(demo):
    assert [(h["method"], h["status"]) for h in demo["http"]][:2] == [("GET", 200), ("GET", 200)]
    names = {f["name"]: f for f in demo["files"]}
    assert names["logo.png"]["type"] == "PNG image" and names["notes.txt"]["source"] == "ftp-downloaded"
    assert names["notes.gz"]["size"] == len(b"nothing to see here\n")  # gunzipped
    assert {(c["kind"], c["user"], c["secret"]) for c in demo["credentials"]} == {("ftp", "admin", "hunter2"), ("http-form", "admin", "s3cr3t-pass")}
    titles = {s["title"] for s in demo["suspicious"]}
    assert {"Possible port scan", "Possible DNS tunnelling / exfiltration", "Cleartext credentials observed"} <= titles


def test_demo_iocs_timeline_graph(demo):
    kinds = {(i["type"], i["value"]) for i in demo["iocs"]}
    assert ("domain", "ctf-chall.local") in kinds and ("ip", "203.0.113.9") in kinds
    assert any(i["scope"] == "public" for i in demo["iocs"] if i["type"] == "ip")
    ts = [e["ts"] for e in demo["timeline"]["events"]]
    assert ts == sorted(ts) and demo["timeline"]["buckets"] and sum(demo["timeline"]["buckets"]) == demo["overview"]["packets"]
    assert {n["id"] for n in demo["graph"]["nodes"]} >= {"10.0.0.5", "10.0.0.80"} and demo["graph"]["edges"]


def test_basic_auth_and_empty_capture(tmp_path):
    from sharkai.config import Settings
    cap = CaptureBuilder()
    req = b"GET /admin HTTP/1.1\r\nHost: x\r\nAuthorization: Basic " + base64.b64encode(b"bob:pw123") + b"\r\n\r\n"
    cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 8081, [("c", req), ("s", b"HTTP/1.1 401 No\r\nContent-Length: 0\r\n\r\n")])
    (tmp_path / "original.bin").write_bytes(cap.to_pcap())
    a = analyze_capture(tmp_path / "original.bin", tmp_path, Settings())
    assert a["credentials"][0]["user"] == "bob" and a["credentials"][0]["secret"] == "pw123"
    (tmp_path / "e.bin").write_bytes(CaptureBuilder().to_pcap())
    with pytest.raises(CaptureFormatError):
        analyze_capture(tmp_path / "e.bin", tmp_path, Settings())


def test_follow_stream_view_is_in_stream_order_even_when_packets_arrive_reordered():
    cap = CaptureBuilder()
    cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 80, [("c", b"AAAABBBBCCCC"), ("s", b"1111222233334444")], mss=4, shuffle=True)
    (s,) = reassemble(cap)
    msgs = s.messages()
    from sharkai.streams import message_bytes
    assert [(m["dir"], message_bytes(s.data[m["dir"]], m)) for m in msgs] == [(0, b"AAAABBBBCCCC"), (1, b"1111222233334444")]
