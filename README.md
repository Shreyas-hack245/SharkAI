# SharkAI

An AI-assisted Wireshark companion for network forensics and CTF work. Upload a capture, browse packets, TCP
streams, HTTP, DNS, extracted files, IOCs, a timeline and a host graph, let SharkAI hunt for flags, then ask
questions about the capture, **without the raw PCAP ever being sent to an AI provider**.

- Reads `.pcap`, `.pcapng` and `.cap` (when the `.cap` contains libpcap/pcapng data, which is what Wireshark,
  tcpdump and airodump write). Format is detected by magic bytes, not by file name.
- Works fully offline. An AI provider is optional; without one (or when it fails) you get deterministic results.

## Quick start

Requires Python 3.11+.

```bash
make setup            # virtualenv + dependencies
make sample           # writes samples/demo-ctf.pcap (5 hidden flags)
make run              # http://127.0.0.1:8000
make test             # 123 tests
```

Without `make`:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
python scripts/make_sample.py && python -m sharkai
```

Open <http://127.0.0.1:8000>, drop `samples/demo-ctf.pcap` on the page, and try the **Flags**, **Streams** and
**Ask** tabs. The demo hides flags in a split TCP stream, a base64 HTTP body, a hex FTP file, DNS exfiltration
labels and an ICMP tunnel, plus a port scan, cleartext logins and a PNG download.

## What it does

| Tab | What you get |
|---|---|
| Overview | counts, protocol mix, top talkers, flag candidates, heuristic alerts |
| Packets | Wireshark-style list, allowlisted display filters, layer tree, hex dump |
| Streams | reassembled TCP conversations (reorder/retransmit/overlap aware), text or hex, flag highlighting, raw download |
| HTTP | requests/responses incl. chunked + gzip/deflate, headers, body previews, uploads |
| DNS | UDP and TCP DNS, search, tunnelling/exfiltration detection with label reconstruction |
| Files | HTTP bodies and uploads, FTP transfers, carved PNG/JPEG/PDF/ZIP/ELF…, SHA-256/MD5 |
| IOCs | IPs (internal/external), domains, URLs, user agents, emails, file hashes, cleartext credentials |
| Flags | CTF flags in plain text, URL, base64, hex, base32, rot13, reversed and nested encodings, with where they were found |
| Timeline / Graph | chronological events with a packets-over-time sparkline; host communication graph |
| Ask | questions answered from structured evidence (AI) or deterministic summaries (fallback) |
| Report | Markdown, JSON or PDF, generated from the stored analysis |

Flags are matched for `flag{}`, `ctf{}`, `picoCTF{}`, `HTB{}`, `THM{}` and others, plus a lower-confidence
generic `NAME{…}` shape. Add your event's prefix (`mycorp`, …) at upload time, in `config.toml`, or in the Flags
tab (it re-analyses). Only prefixes are configurable; no user regex is ever compiled.

## AI providers

Set `[ai]` in `config.toml` (copy `config.example.toml`) or use `SHARKAI_AI_*` environment variables.

```toml
# Ollama
[ai]
provider = "ollama"
model    = "llama3.1"            # base_url defaults to http://127.0.0.1:11434

# Any OpenAI-compatible server: OpenAI, LM Studio, llama.cpp, vLLM, LiteLLM, OpenRouter, ...
[ai]
provider = "openai"
base_url = "http://127.0.0.1:1234/v1"
model    = "qwen2.5-14b-instruct"
# key via:  export SHARKAI_AI_API_KEY=...
```

The chip in the top bar shows the active provider; click it to test connectivity. Ollama is called on
`POST /api/chat` with `stream:false`; OpenAI-compatible servers on `POST {base_url}/chat/completions`.

### What the AI is allowed to see

Only the JSON built by `sharkai/evidence.py`, and you can inspect it: **Ask → "Show evidence the AI would see"**.

- Derived summaries with stable IDs (`F1` flag, `S3` stream, `H12` HTTP, `D4` DNS, `X2` file, `A1` alert, `I7` IOC).
- Printable-ASCII snippets, each length-capped. No packet bytes, no full payloads, no file contents.
- A hard size cap (`max_evidence_chars`); sections are trimmed by relevance to the question.
- Cleartext passwords/tokens are masked (`redact_secrets = true`) and scrubbed from every other field too.
- The system prompt tells the model to treat evidence as untrusted data. Traffic is only ever placed in the
  user turn, and answers citing IDs that were not in the evidence are flagged in the UI.

The AI base URL and key come only from configuration, never from a request. Provider errors are scrubbed of the key.

### Fallback

If no provider is configured, it times out, refuses, returns bad JSON or an empty answer, or you untick
**Use AI provider**, you get a deterministic answer rendered from the *same* evidence, labelled
"Deterministic result" with the reason. The app never needs an AI to be useful.

## Display filters

A safe subset of Wireshark's syntax, parsed by a hand-written parser (no `eval`, no regex from users):

```
dns
ip.addr == 10.0.0.0/8 and tcp.port in {80 8080}
tcp.flags contains SYN and not tcp.flags contains ACK
http.method == POST or dns.qry.name contains example
frame contains "flag{"          # case-insensitive search of raw frame bytes
```

Fields and operators are allowlisted; filters are capped at 300 characters, 20 comparisons and 8 levels of nesting.
The full field list is in the Packets tab and at `GET /api/filters/help`. `frame contains` searches raw frames, so
a flag split across two TCP segments is found by the Flags tab (reassembled) but not by that filter.

## Storage and security

- Each upload lives in `data/captures/<random 32-hex id>/` (mode 0700). The original is saved as `original.bin`;
  your file name is only display metadata, so it can never form a path. IDs are validated on every request.
- Uploads are streamed with a size cap and rejected unless the first bytes are a pcap/pcapng magic number;
  failed uploads leave nothing behind. Delete a capture in the UI to remove everything derived from it.
- Extracted files are only ever served as `application/octet-stream` attachments with `nosniff`.
- Strict CSP (no inline script/style), DOM built with `textContent` only, `Host` allowlist against DNS rebinding,
  and a required `X-SharkAI` header plus same-origin check on every state-changing request (CSRF).
- **There is no login.** It binds to `127.0.0.1` by default and warns if you change that. If you expose it,
  put an authenticating reverse proxy in front and set `allowed_hosts`. Captures are evidence: treat
  `data/` accordingly.
- Reports contain credentials unless you tick *Mask credential secrets* (or pass `?redact=true`).

## API

All under `/api`; mutating calls need the header `X-SharkAI: 1`.

```
GET  /config  /health  /filters/help         POST /ai/test
GET  /captures                               POST /captures?filename=x.pcap[&flag_prefix=acme]   (raw body)
GET  /captures/{id}                          DELETE /captures/{id}        POST /captures/{id}/reanalyze
GET  /captures/{id}/packets?filter=&offset=&limit=      /packets/{n}
GET  /captures/{id}/streams  /streams/{sid}?format=text|hex   /streams/{sid}/raw?dir=0|1
GET  /captures/{id}/http  /dns?q=  /files  /files/{fid}  /iocs  /flags  /credentials  /suspicious  /timeline  /graph
GET  /captures/{id}/evidence?question=       POST /captures/{id}/ask  {question, use_ai, history}
GET  /captures/{id}/report?format=md|json|pdf&redact=true
```

## Limits (what it does not do)

- IP fragments are flagged but not reassembled. No TLS decryption: TLS shows SNI only. HTTP/2 and QUIC are not parsed.
- Analysis runs while the upload request is open. Rough speed is 3-4k packets/s on the worst case (large random
  binary bodies) and faster on typical traffic; defaults cap uploads at 100 MB / 500k packets and say so when hit.
- Heuristics (scan, tunnelling, beaconing, ICMP) are hints, not verdicts. Verify in Packets/Streams.
- Link types: Ethernet (+VLAN), Linux cooked v1/v2, BSD loopback and raw IP. Wi-Fi (802.11) is not decoded.
- Tested against the bundled synthetic captures and the 123-test suite, not a corpus of real-world pcaps.

## Layout

```
sharkai/
  capture_io.py   pcap/pcapng readers          decode.py    Ethernet/IP/TCP/UDP/ICMP decoding
  streams.py      TCP reassembly               httpparse.py HTTP/1.x      dnsparse.py DNS
  flags.py        flag + encoding scanner      analyzer.py  the pipeline  insights.py IOCs/timeline/graph
  filters.py      safe display filters         store.py     on-disk storage
  evidence.py     what the AI may see          ai.py        providers     fallback.py deterministic answers
  reports.py      md/json/pdf                  app.py       FastAPI       web/        the UI (no build step)
tests/            parsers, reassembly, flags, filters, AI boundary + fallbacks, API security
```
