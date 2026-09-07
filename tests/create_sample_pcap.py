"""Generate a sample PCAP for testing SharkAI."""

import sys
from pathlib import Path

try:
    from scapy.all import IP, TCP, UDP, DNS, DNSQR, Raw, Ether, wrpcap
except ImportError:
    print("Install scapy: pip install scapy")
    sys.exit(1)


def create_sample_pcap(output_path: str):
    packets = []

    # HTTP GET request with a flag in response
    http_req = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: ctf.example.com\r\n"
        b"User-Agent: SharkAI-Test/1.0\r\n\r\n"
    )
    http_resp = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html\r\n\r\n"
        b"<html><body>The flag is: flag{sh4rk_ai_t3st_p4ck3t}</body></html>"
    )

    pkt1 = Ether() / IP(src="10.10.10.5", dst="192.168.1.100") / TCP(sport=45678, dport=80, flags="PA") / Raw(load=http_req)
    pkt2 = Ether() / IP(src="192.168.1.100", dst="10.10.10.5") / TCP(sport=80, dport=45678, flags="PA") / Raw(load=http_resp)
    packets.extend([pkt1, pkt2])

    # HTTP POST with credentials
    http_post = (
        b"POST /login HTTP/1.1\r\n"
        b"Host: app.example.com\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Content-Length: 35\r\n\r\n"
        b"username=admin&password=s3cr3tP@ss"
    )
    pkt3 = Ether() / IP(src="10.10.10.5", dst="192.168.1.200") / TCP(sport=45679, dport=80, flags="PA") / Raw(load=http_post)
    packets.append(pkt3)

    # DNS query
    pkt4 = Ether() / IP(src="10.10.10.5", dst="8.8.8.8") / UDP(sport=12345, dport=53) / DNS(rd=1, qd=DNSQR(qname="suspicious.example.com"))
    packets.append(pkt4)

    # Fragmented flag across packets
    frag1 = Ether() / IP(src="10.10.10.5", dst="10.10.10.10") / TCP(sport=9999, dport=4444, flags="PA") / Raw(load=b"flag{frag_")
    frag2 = Ether() / IP(src="10.10.10.5", dst="10.10.10.10") / TCP(sport=9999, dport=4444, flags="PA") / Raw(load=b"mented_")
    frag3 = Ether() / IP(src="10.10.10.5", dst="10.10.10.10") / TCP(sport=9999, dport=4444, flags="PA") / Raw(load=b"fl4g}")
    packets.extend([frag1, frag2, frag3])

    wrpcap(output_path, packets)
    print(f"Created sample PCAP: {output_path} ({len(packets)} packets)")


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else str(Path(__file__).parent / "samples" / "test_capture.pcap")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    create_sample_pcap(out)
