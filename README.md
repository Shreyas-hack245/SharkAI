<div align="center">

# SharkAI

**An AI-assisted Wireshark companion for network forensics and CTF analysis.**

Upload a capture. Browse packets, streams, HTTP, DNS and files. Find the flags.
Ask questions about it, without the raw PCAP ever leaving your machine.

![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue) ![Tests](https://img.shields.io/badge/tests-123%20passing-brightgreen) ![Runs offline](https://img.shields.io/badge/runs-offline-informational) ![No build step](https://img.shields.io/badge/frontend-no%20build%20step-lightgrey)

![SharkAI overview](docs/screenshots/overview.png)

</div>

---

## Contents

[Features](#features) · [Quick start](#quick-start) · [Using SharkAI](#using-sharkai) · [AI providers](#ai-providers) ·
[Privacy model](#privacy-model) · [Display filters](#display-filters) · [Reports](#reports) · [Security](#security) ·
[API](#api-reference) · [Architecture](#architecture) · [Limitations](#limitations) · [Troubleshooting](#troubleshooting) ·
[Development](#development)

## Features

| | |
|---|---|
| **Formats** | `.pcap`, `.pcapng`, `.cap` (libpcap/pcapng content). Detected by magic bytes. Both byte orders, micro/nanosecond timestamps. |
| **Packet browser** | Wireshark-style list with protocol colouring, layer tree, hex dump, and allowlisted display filters. |
| **TCP streams** | Reassembly that handles reordering, retransmission, overlap and sequence wrap. Text/hex views, raw download. |
| **Protocols** | HTTP/1.x (chunked, gzip, deflate, pipelining, multipart), DNS over UDP and TCP, FTP, TLS SNI, ICMP, ARP, IPv4/IPv6, VLAN. |
| **Files** | Extracted from HTTP bodies/uploads and FTP transfers, plus carved PNG/JPEG/GIF/PDF/ZIP/ELF. SHA-256 and MD5. |
| **Flag hunting** | Plain, URL, base64, hex, base32, rot13, reversed and nested encodings, across packets, reassembled streams, HTTP bodies, DNS and files. |
| **Detections** | Cleartext credentials, port scans, DNS tunnelling/exfiltration (with decoded labels), ICMP payload abuse, beaconing, executable transfers. |
| **IOCs, timeline, graph** | Internal/external IPs, domains, URLs, emails, user agents, hashes; chronological events; host communication graph. |
| **Ask** | Questions answered by an AI provider from structured evidence, with a deterministic fallback when no provider is available. |
| **Reports** | Markdown, JSON and PDF generated from the stored analysis. |

<table>
<tr>
<td width="50%"><img src="docs/screenshots/streams.png" alt="Following a TCP stream"><br><sub><b>Streams</b>: reassembled in stream order, flags highlighted in place.</sub></td>
<td width="50%"><img src="docs/screenshots/packets.png" alt="Packet list and layers"><br><sub><b>Packets</b>: filters, layer tree and hex dump.</sub></td>
</tr>
<tr>
<td><img src="docs/screenshots/flags.png" alt="Flag candidates"><br><sub><b>Flags</b>: where each one was found and how it was encoded.</sub></td>
<td><img src="docs/screenshots/ask.png" alt="Ask panel"><br><sub><b>Ask</b>: AI answers, or deterministic results with the reason shown.</sub></td>
</tr>
</table>

## Quick start

**Requirements:** Python **3.11 or newer** (3.9/3.10 will fail with `No module named 'tomllib'`). No Node, no database, no build step.

### Windows (PowerShell)

```powershell
# one-time: install Python 3.12 if you don't have 3.11+, then reopen PowerShell
winget install Python.Python.3.12

cd SharkAI
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements-dev.txt
.venv\Scripts\python scripts\make_sample.py        # optional demo capture
.venv\Scripts\python -m sharkai
```

### macOS / Linux

```bash
cd sharkai
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
.venv/bin/python scripts/make_sample.py            # optional demo capture
.venv/bin/python -m sharkai
```

`make setup`, `make sample`, `make run` and `make test` do the same on systems that have `make`.

Then open **http://127.0.0.1:8000** and drop a capture on the page. Try `samples/demo-ctf.pcap`. It hides five flags in a
split TCP stream, a base64 HTTP body, a hex-encoded FTP file, DNS exfiltration labels and an ICMP tunnel, plus a port
scan, cleartext logins and a PNG download.

> Calling the venv's Python directly (as above) means you never need to "activate" it, which avoids PowerShell's
> script-execution policy.

## Using SharkAI

| Tab | Use it to |
|---|---|
| **Overview** | See counts, protocol mix, top talkers, flag candidates and heuristic alerts at a glance. |
| **Packets** | Filter and inspect individual packets. Click a row for layers and a hex dump. |
| **Streams** | Follow a TCP conversation. Flags are highlighted. Download either direction's raw bytes. |
| **HTTP** | Review requests and responses, headers, body previews. Jump to the stream or download the body. |
| **DNS** | Search queries and answers. Tunnelling shows up in Overview and IOCs. |
| **Files** | Download extracted files (served only as attachments), compare hashes. |
| **IOCs** | Cleartext credentials and indicators. Click an IP or domain to filter packets. |
| **Flags** | Every flag candidate with confidence, encoding and location. Add custom prefixes and re-analyse. |
| **Timeline / Graph** | Order events in time; see who talked to whom. |
| **Ask** | Ask in plain English, e.g. *"Is there a flag?"*, *"What was downloaded over HTTP?"*, *"Any suspicious DNS?"* |
| **Report** | Download Markdown, JSON or PDF. Optionally mask credential secrets. |

**Custom flag formats.** Built-in prefixes include `flag`, `ctf`, `picoCTF`, `HTB`, `THM` and others, plus a
lower-confidence generic `NAME{...}` shape. Add your event's prefix in the sidebar when uploading, in `config.toml`, or
in the **Flags** tab (which re-analyses). Only *prefixes* are configurable; no user-supplied regex is ever compiled.

## Configuration

Settings come from (lowest to highest priority) built-in defaults → `config.toml` → `.env` → real environment variables.
Copy the examples to get started:

```powershell
copy config.example.toml config.toml        # Windows
```
```bash
cp config.example.toml config.toml          # macOS / Linux
```

| Setting (`config.toml`) | Environment variable | Default | Purpose |
|---|---|---|---|
| `server.host` / `port` | `SHARKAI_HOST` / `SHARKAI_PORT` | `127.0.0.1` / `8000` | Where to listen. Keep on loopback. |
| `server.data_dir` | `SHARKAI_DATA_DIR` | `data` | Capture storage. |
| `server.allowed_hosts` | `SHARKAI_ALLOWED_HOSTS` | localhost, 127.0.0.1 | Accepted `Host` headers. |
| `limits.max_upload_mb` | `SHARKAI_MAX_UPLOAD_MB` | `100` | Upload size cap. |
| `limits.max_packets` | `SHARKAI_MAX_PACKETS` | `500000` | Analysis stops here and says so. |
| `limits.max_stream_mb` | `SHARKAI_MAX_STREAM_MB` | `32` | Per TCP direction. |
| `analysis.flag_prefixes` | `SHARKAI_FLAG_PREFIXES` | none | Extra CTF prefixes. |
| `ai.provider` | `SHARKAI_AI_PROVIDER` | `none` | `none`, `openai` or `ollama`. |
| `ai.base_url` | `SHARKAI_AI_BASE_URL` | per provider | Provider endpoint. |
| `ai.model` | `SHARKAI_AI_MODEL` | none | Model name. |
| `ai.api_key` | `SHARKAI_AI_API_KEY` | none | Prefer the environment variable. |
| `ai.max_evidence_chars` | `SHARKAI_AI_MAX_EVIDENCE_CHARS` | `16000` | Hard cap on data sent per question. |
| `ai.redact_secrets` | `SHARKAI_AI_REDACT_SECRETS` | `true` | Mask cleartext passwords/tokens in evidence. |

## AI providers

AI is **optional**. With `provider = "none"` (the default) SharkAI is fully functional and answers questions
deterministically.

```toml
# Ollama (local)
[ai]
provider = "ollama"
model    = "llama3.1"                       # base_url defaults to http://127.0.0.1:11434

# Any OpenAI-compatible server: OpenAI, LM Studio, llama.cpp, vLLM, LiteLLM, OpenRouter...
[ai]
provider = "openai"
base_url = "http://127.0.0.1:1234/v1"       # default: https://api.openai.com/v1
model    = "your-model-name"
```

Set the key in your environment, not in the file:

```powershell
$env:SHARKAI_AI_API_KEY = "sk-..."          # PowerShell
```
```bash
export SHARKAI_AI_API_KEY=sk-...            # macOS / Linux
```

The chip in the top bar shows the active provider; **click it to test connectivity**. Ollama is called on
`POST /api/chat` with `stream: false`; OpenAI-compatible servers on `POST {base_url}/chat/completions`.

### Fallback behaviour

If no provider is configured, or it times out, refuses the connection, returns an HTTP error, invalid JSON or an empty
answer, or you untick **Use AI provider**, SharkAI returns a deterministic answer rendered from the *same evidence*.
It is clearly labelled *"Deterministic result"* with the reason. The app never depends on an AI being available.

## Privacy model

The AI provider never receives the capture. It receives only the JSON produced by `sharkai/evidence.py`, and you can
inspect it before trusting it: **Ask → "Show evidence the AI would see"**.

- **Derived, not raw.** Summaries with stable IDs (`F1` flag, `S3` stream, `H12` HTTP, `D4` DNS, `X2` file, `A1` alert,
  `I7` IOC). No packet bytes, no full payloads, no file contents.
- **Bounded.** Snippets are printable ASCII and length-capped; the whole bundle obeys `max_evidence_chars`.
- **Relevant.** Sections are selected and trimmed based on the question.
- **Masked.** Cleartext passwords and tokens are replaced with `[redacted]` and scrubbed from every other field too.
- **Injection-aware.** The system prompt marks evidence as untrusted data. Traffic only ever appears in the user turn.
  Answers that cite IDs not present in the evidence are flagged in the UI.
- **Config-only endpoints.** The provider URL and key come from configuration, never from a request, and provider
  errors are scrubbed of the key.

## Display filters

A safe subset of Wireshark's syntax, parsed by a hand-written parser: no `eval`, no regex from users, allowlisted
fields and operators only, limited to 300 characters, 20 comparisons and 8 levels of nesting.

```text
dns
ip.addr == 10.0.0.0/8 and tcp.port in {80 8080}
tcp.flags contains SYN and not tcp.flags contains ACK
http.method == POST or dns.qry.name contains example
frame contains "flag{"                 # case-insensitive search of raw frame bytes
```

The full field list is in the Packets tab and at `GET /api/filters/help`. `frame contains` searches individual frames,
so a flag split across TCP segments is found by the **Flags** tab (which searches reassembled streams) but not by that
filter.

## Reports

| Format | Contents |
|---|---|
| **Markdown** | Summary, flags, alerts, credentials, IOCs, HTTP, DNS, files, streams, timeline. HTML-escaped. |
| **JSON** | Everything above in machine-readable form, for scripting. |
| **PDF** | Paginated A4 report with tables and page numbers. |

Reports are generated from the stored analysis, not by the AI, so they are identical every time. They **contain
credentials unless you tick "Mask credential secrets"** (or pass `?redact=true`), in which case secrets are scrubbed
from every field.

## Security

- **Storage.** Each upload lives in `data/captures/<random 32-hex id>/` (directory mode `0700`). The original is saved as
  `original.bin`; the uploaded filename is display metadata only and can never become part of a path. IDs are validated
  on every request.
- **Uploads.** Streamed with a size cap; rejected unless the first bytes are a pcap/pcapng magic number. Failed uploads
  leave nothing behind. Deleting a capture removes everything derived from it.
- **Downloads.** Extracted files are served only as `application/octet-stream` attachments with `nosniff`.
- **Browser.** Strict CSP (no inline script or style), all DOM built with `textContent`, no `innerHTML` or `eval`.
- **Network.** `Host` allowlist (DNS-rebinding guard); every state-changing request requires an `X-SharkAI` header and
  a same-origin check (CSRF).
- **There is no login.** SharkAI binds to `127.0.0.1` by default and warns if you change that. If you expose it, put an
  authenticating reverse proxy in front and set `allowed_hosts`. Captures are evidence; protect `data/` accordingly.

## API reference

All endpoints are under `/api`. Mutating calls need the header `X-SharkAI: 1`.

| Method & path | Description |
|---|---|
| `GET /health`, `/config`, `/filters/help` | Status, safe configuration view, filter reference |
| `POST /ai/test` | Check provider connectivity |
| `GET /captures` · `POST /captures?filename=x.pcap[&flag_prefix=acme]` | List; upload (raw request body) |
| `GET/DELETE /captures/{id}` · `POST /captures/{id}/reanalyze` | Overview; delete; re-run with custom prefixes |
| `GET /captures/{id}/packets?filter=&offset=&limit=` · `/packets/{n}` | Filtered packet list; packet detail with hex |
| `GET /captures/{id}/streams` · `/streams/{sid}?format=text\|hex` · `/streams/{sid}/raw?dir=0\|1` | Streams |
| `GET /captures/{id}/http` · `/dns?q=` · `/files` · `/files/{fid}` | Protocol views and extracted files |
| `GET /captures/{id}/iocs` · `/flags` · `/credentials` · `/suspicious` · `/timeline` · `/graph` | Findings |
| `GET /captures/{id}/evidence?question=` | Exactly what the AI would receive |
| `POST /captures/{id}/ask` `{question, use_ai, history}` | Ask a question |
| `GET /captures/{id}/report?format=md\|json\|pdf&redact=true` | Report |

## Architecture

```text
 Browser (vanilla JS, strict CSP)
      │  JSON over HTTP, X-SharkAI header
      ▼
 app.py (FastAPI) ───────────────────────────────┐
      │ upload                                    │ browse / filter / report
      ▼                                           ▼
 store.py ──► data/captures/<id>/          filters.py   reports.py
      │            original.bin                   ▲
      ▼            analysis.json, packets.json    │
 analyzer.py  ◄──  streams/, files/ ──────────────┘
   ├─ capture_io.py   pcap / pcapng readers
   ├─ decode.py       Ethernet · IP · TCP · UDP · ICMP · DNS · SNI
   ├─ streams.py      TCP reassembly
   ├─ httpparse.py    HTTP/1.x          dnsparse.py   DNS
   ├─ flags.py        flag + encoding scanner
   └─ insights.py     IOCs · alerts · timeline · graph

 Ask:  analysis ──► evidence.py ──► ai.py ──► provider (OpenAI-compatible / Ollama)
                         │                        │ unavailable / error
                         └────────────────────────┴──► fallback.py (deterministic)
```

## Limitations

- IP fragments are flagged but not reassembled. TLS is not decrypted (SNI only). HTTP/2, QUIC and 802.11 are not decoded.
- Link types supported: Ethernet (with VLAN), Linux cooked v1/v2, BSD loopback, raw IP.
- Analysis runs while the upload request is open. Worst-case speed (large random binary bodies) is roughly 3-4k
  packets/s; typical traffic is faster. Defaults cap uploads at 100 MB and 500k packets and tell you when they are hit.
- Detections (scan, tunnelling, beaconing, ICMP) are heuristics. Verify them in Packets and Streams.
- Validated against the bundled synthetic captures and the test suite, not a corpus of real-world captures.

## Troubleshooting

| Symptom | Fix |
|---|---|
| `No module named 'tomllib'` | Your Python is older than 3.11. Install 3.12 (`winget install Python.Python.3.12`), reopen the terminal, recreate the venv. |
| `python3` / `pip` / `source` not recognised (Windows) | Use `py -3.12` and `.venv\Scripts\python` as shown above. |
| Port already in use | Set `SHARKAI_PORT` to another port. |
| `configuration error: ...` at start | The message names the bad setting (usually `provider` or `base_url`). |
| Uploads fail with 403 | You opened it by a hostname other than `localhost`/`127.0.0.1`; add it to `allowed_hosts`. |
| 415 on upload | Not a pcap/pcapng file (e.g. a Sniffer-format `.cap`). Convert with Wireshark or `editcap`. |
| AI chip says unreachable | Check `base_url` (OpenAI-style needs the `/v1` suffix) and that the server is running; answers still work via fallback. |

## Development

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q          # 123 tests
```

The suite covers the parsers (both formats, byte orders, truncation), TCP reassembly edge cases, every flag encoding
and false-positive guard, the filter allowlist against injection attempts, the AI boundary (request shapes, redaction,
size limits, prompt-injection handling, seven failure modes falling back), and API security (path traversal, CSRF,
host checks, upload validation, safe downloads).

`sharkai/samples.py` contains a packet builder used by the tests and by `scripts/make_sample.py`, handy for writing your
own fixtures. No license file is included; add one before redistributing.
