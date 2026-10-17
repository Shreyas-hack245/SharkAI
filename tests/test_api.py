import json

import pytest
from fastapi.testclient import TestClient

from conftest import H, make_settings
from sharkai.app import create_app
from sharkai.samples import CaptureBuilder, DEMO_FLAGS, dns_query


def test_upload_browse_and_every_view(client, capture_id):
    base = f"/api/captures/{capture_id}"
    cap = client.get(base).json()
    assert cap["overview"]["packets"] == 114 and cap["meta"]["name"] == "demo.pcap" and len(cap["meta"]["sha256"]) == 64
    assert client.get("/api/captures").json()[0]["id"] == capture_id
    pk = client.get(f"{base}/packets?limit=10").json()
    assert pk["total"] == 114 and len(pk["packets"]) == 10 and pk["packets"][0]["n"] == 1
    assert client.get(f"{base}/packets?offset=100&limit=50").json()["packets"][-1]["n"] == 114
    d = client.get(f"{base}/packets/14").json()
    assert d["layers"][0]["name"] == "Frame" and d["hex"][0].startswith("0000") and "secret" not in d["summary"]
    assert client.get(f"{base}/packets/9999").status_code == 404
    for view, minimum in [("streams", 4), ("http", 5), ("files", 6), ("iocs", 20), ("flags", 5), ("timeline", 1), ("graph", 1), ("credentials", 2), ("suspicious", 4)]:
        r = client.get(f"{base}/{view}")
        assert r.status_code == 200, view
        body = r.json()
        assert len(body["events"] if view == "timeline" else body["nodes"] if view == "graph" else body) >= minimum, view
    dns = client.get(f"{base}/dns?q=exfil").json()
    assert dns["total"] == 8 and all("exfil" in e["qname"] for e in dns["items"])


def test_filters_through_api(client, capture_id):
    base = f"/api/captures/{capture_id}/packets"
    assert client.get(base, params={"filter": "dns"}).json()["total"] == 12
    assert client.get(base, params={"filter": "tcp.flags contains SYN and not tcp.flags contains ACK and ip.src == 10.0.0.66 and tcp.dstport <= 25"}).json()["total"] == 25
    assert client.get(base, params={"filter": 'frame contains "picoCTF"'}).json()["total"] == 2
    assert client.get(base, params={"filter": "tcp.stream == 0"}).json()["total"] > 10
    bad = client.get(base, params={"filter": "__import__('os')"})
    assert bad.status_code == 400 and bad.json()["kind"] == "filter"
    assert client.get(base, params={"filter": "x" * 500}).status_code == 422 or client.get(base, params={"filter": "x" * 500}).status_code == 400
    assert any(f["name"] == "ip.addr" for f in client.get("/api/filters/help").json()["fields"])


def test_stream_view_and_raw(client, capture_id):
    base = f"/api/captures/{capture_id}/streams"
    s = client.get(f"{base}/0").json()
    assert s["messages"][0]["dir"] == 0 and "GET / HTTP/1.1" in s["messages"][0]["text"]
    assert "47 45 54" in client.get(f"{base}/0?format=hex").json()["messages"][0]["text"]
    raw = client.get(f"{base}/1/raw?dir=1")
    assert raw.content.endswith(b"\n") and DEMO_FLAGS["split"].encode() in raw.content
    assert raw.headers["content-disposition"].startswith("attachment")
    assert client.get(f"{base}/9999").status_code == 404


def test_file_download_is_safe(client, capture_id):
    files = client.get(f"/api/captures/{capture_id}/files").json()
    png = next(f for f in files if f["name"] == "logo.png")
    r = client.get(f"/api/captures/{capture_id}/files/{png['id']}")
    assert r.content.startswith(b"\x89PNG") and r.headers["content-type"] == "application/octet-stream"
    assert r.headers["content-disposition"] == 'attachment; filename="logo.png"' and r.headers["x-content-type-options"] == "nosniff"


def test_reports(client, capture_id):
    base = f"/api/captures/{capture_id}/report"
    md = client.get(base, params={"format": "md"})
    assert md.status_code == 200 and "flag{base64_in_http_body}" in md.text and "hunter2" in md.text
    assert "hunter2" not in client.get(base, params={"format": "md", "redact": "true"}).text
    js = client.get(base, params={"format": "json"}).json()
    assert js["capture"]["name"] == "demo.pcap" and len(js["flags"]) == 5
    assert "hunter2" not in client.get(base, params={"format": "json", "redact": "true"}).text
    pdf = client.get(base, params={"format": "pdf", "redact": "true"})
    assert pdf.content.startswith(b"%PDF-") and pdf.headers["content-type"] == "application/pdf" and len(pdf.content) > 2000
    assert client.get(base, params={"format": "exe"}).status_code == 422


def test_upload_validation(tmp_path, demo_pcap):
    c = TestClient(create_app(make_settings(tmp_path, max_upload_mb=1)))
    assert c.post("/api/captures", content=b"MZ" + b"\x00" * 100, headers=H).status_code == 415
    assert c.post("/api/captures", content=b"", headers=H).status_code == 415
    assert c.post("/api/captures", content=demo_pcap[:30], headers=H).status_code in (415, 422)
    assert c.post("/api/captures", content=demo_pcap[:4] + b"\x00" * (2 * 1024 * 1024), headers=H).status_code == 413
    assert c.post("/api/captures?flag_prefix=bad%7Bprefix", content=demo_pcap, headers=H).status_code == 400
    assert c.get("/api/captures").json() == []                  # nothing half-stored after failures
    assert not any((tmp_path / "data" / "captures").iterdir())


def test_filename_never_touches_the_filesystem(client, demo_pcap, settings):
    r = client.post("/api/captures", params={"filename": "../../../../tmp/evil.pcap"}, content=demo_pcap, headers=H)
    assert r.json()["name"] == "evil.pcap"
    dirs = list((settings.data_dir / "captures").iterdir())
    assert len(dirs) == 1 and (dirs[0] / "original.bin").is_file() and oct(dirs[0].stat().st_mode & 0o777) == "0o700"
    assert not any(p.name == "evil.pcap" for p in settings.data_dir.parent.rglob("evil.pcap"))


@pytest.mark.parametrize("cid", ["../../etc/passwd", "..%2f..%2fetc", "A" * 32, "0" * 31, "zz" * 16, "%00"])
def test_capture_ids_are_validated(client, cid):
    assert client.get(f"/api/captures/{cid}").status_code in (404, 400)
    assert client.get(f"/api/captures/{cid}/packets").status_code in (404, 400)
    assert client.delete(f"/api/captures/{cid}", headers=H).status_code in (404, 400)


def test_csrf_origin_and_host_protection(client, capture_id):
    assert client.delete(f"/api/captures/{capture_id}").status_code == 403           # no custom header
    assert client.post(f"/api/captures/{capture_id}/ask", json={"question": "x"}).status_code == 403
    cross = client.post(f"/api/captures/{capture_id}/ask", json={"question": "hi"}, headers={**H, "Origin": "http://evil.example"})
    assert cross.status_code == 403
    assert client.get("/api/health", headers={"Host": "evil.example"}).status_code == 400  # DNS-rebinding guard
    same = client.post(f"/api/captures/{capture_id}/ask", json={"question": "hi"}, headers={**H, "Origin": "http://testserver"})
    assert same.status_code == 200


def test_security_headers_and_static_ui(client):
    r = client.get("/")
    assert r.status_code == 200 and "SharkAI" in r.text
    csp = r.headers["content-security-policy"]
    assert "script-src 'self'" in csp and "unsafe-inline" not in csp and "frame-ancestors 'none'" in csp
    assert "no-store" in client.get("/api/health").headers["cache-control"]
    html = r.text + client.get("/assets/app.js").text
    assert "innerHTML" not in html and "eval(" not in html and "<script>" not in r.text
    assert client.get("/docs").status_code == 404


def test_delete_removes_everything(client, capture_id, settings):
    assert client.delete(f"/api/captures/{capture_id}", headers=H).status_code == 204
    assert client.get(f"/api/captures/{capture_id}").status_code == 404
    assert not (settings.data_dir / "captures" / capture_id).exists()


def test_reanalyze_with_custom_prefix_promotes_flag(client):
    cap = CaptureBuilder()
    cap.tcp_session("10.0.0.1", 40000, "10.0.0.2", 7000, [("s", b"hello ACME{leet_12345} bye")])
    cid = client.post("/api/captures", content=cap.to_pcap(), headers=H).json()["id"]
    assert client.get(f"/api/captures/{cid}/flags").json()[0]["confidence"] == "low"
    r = client.post(f"/api/captures/{cid}/reanalyze", json={"flag_prefixes": ["acme"]}, headers=H)
    assert r.status_code == 200
    assert client.get(f"/api/captures/{cid}/flags").json()[0]["confidence"] == "high"
    assert client.post(f"/api/captures/{cid}/reanalyze", json={"flag_prefixes": ["a b"]}, headers=H).status_code == 400


def test_concurrent_captures_are_isolated(client, demo_pcap):
    cap = CaptureBuilder()
    cap.udp_pkt("10.0.0.1", "10.0.0.2", 1, 53, dns_query("only.example.com"))
    a = client.post("/api/captures?filename=a.pcap", content=demo_pcap, headers=H).json()["id"]
    b = client.post("/api/captures?filename=b.pcap", content=cap.to_pcap(), headers=H).json()["id"]
    assert client.get(f"/api/captures/{a}").json()["overview"]["packets"] == 114
    assert client.get(f"/api/captures/{b}").json()["overview"]["packets"] == 1
    assert client.get(f"/api/captures/{b}/flags").json() == []
