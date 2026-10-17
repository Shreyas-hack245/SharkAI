import struct

import pytest

from sharkai.capture_io import CaptureFormatError, CaptureReader, sniff_format
from sharkai.decode import decode_frame
from sharkai.samples import CaptureBuilder, dns_query, eth, ipv4, udp


def build() -> CaptureBuilder:
    cap = CaptureBuilder(t0=1_700_000_000.0)
    cap.udp_pkt("10.0.0.1", "10.0.0.2", 1111, 53, dns_query("a.example.com"), ts=1_700_000_000.123456)
    cap.udp_pkt("10.0.0.2", "10.0.0.1", 53, 1111, b"x" * 20, ts=1_700_000_001.5)
    return cap


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("nano", [False, True])
def test_pcap_variants(big, nano):
    r = CaptureReader(build().to_pcap(big_endian=big, nano=nano))
    pkts = list(r.packets())
    assert r.format == "pcap" and len(pkts) == 2
    assert abs(pkts[0][0].ts - 1_700_000_000.123456) < 1e-5
    assert pkts[1][0].ts == pytest.approx(1_700_000_001.5)


@pytest.mark.parametrize("big", [False, True])
@pytest.mark.parametrize("res", [6, 9, 3])
def test_pcapng_variants(big, res):
    r = CaptureReader(build().to_pcapng(big_endian=big, tsresol=res))
    pkts = list(r.packets())
    assert r.format == "pcapng" and len(pkts) == 2
    assert pkts[1][0].ts == pytest.approx(1_700_000_001.5, abs=1e-3)
    assert pkts[0][0].offset > 0 and pkts[0][1] == build().frames[0][1]


def test_truncated_capture_warns_but_keeps_good_packets():
    data = build().to_pcap()[:-10]
    r = CaptureReader(data)
    assert len(list(r.packets())) == 1 and any("truncated" in w for w in r.warnings)


def test_rejects_garbage():
    with pytest.raises(CaptureFormatError):
        CaptureReader(b"GIF89a....not a capture")
    assert sniff_format(b"\xd4\xc3\xb2\xa1") == "pcap" and sniff_format(b"\x0a\x0d\x0d\x0a") == "pcapng"


def test_raw_ip_linktype():
    cap = build()
    cap.frames = [(t, f[14:]) for t, f in cap.frames]
    r = CaptureReader(cap.to_pcap(linktype=101))
    raw, frame = next(r.packets())
    d = decode_frame(frame, raw.linktype)
    assert d.src == "10.0.0.1" and d.dns["questions"][0]["name"] == "a.example.com"


def test_ipv6_udp_dns_and_ethernet_padding():
    dns = dns_query("v6.example.org")
    u = udp(5000, 53, dns)
    ip6 = struct.pack(">IHBB", 6 << 28, len(u), 17, 64) + bytes(15) + b"\x01" + bytes(15) + b"\x02" + u
    d = decode_frame(eth(ip6, 0x86DD) + b"\x00" * 6, 1)
    assert d.l3 == "IPv6" and d.src.endswith("::1") and d.dns["questions"][0]["name"] == "v6.example.org"


def test_malformed_frames_do_not_raise():
    for frame in (b"", b"\x00" * 5, eth(b"\x45\x00"), eth(ipv4("1.1.1.1", "2.2.2.2", 6, b"\x00" * 5))):
        assert decode_frame(frame, 1) is not None
    assert decode_frame(b"\x01\x02", 999).app == "Unsupported"
