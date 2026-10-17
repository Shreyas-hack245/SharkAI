#!/usr/bin/env python3
"""Write a demo CTF capture (HTTP, FTP, DNS exfil, ICMP tunnel, split flag, port scan)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sharkai.samples import DEMO_FLAGS, sample_ctf_capture  # noqa: E402

out = Path(sys.argv[1] if len(sys.argv) > 1 else "samples/demo-ctf.pcap")
out.parent.mkdir(parents=True, exist_ok=True)
out.write_bytes(sample_ctf_capture())
print(f"wrote {out} ({out.stat().st_size} bytes)")
print("hidden flags:", ", ".join(DEMO_FLAGS.values()))
