# SharkAI — Local-first network forensics assistant

SharkAI is a runnable MVP for PCAP/PCAPNG/CAP triage. It has a browser UI, FastAPI backend, packet metadata/payload inspection, heuristic CTF flag detection, DNS/HTTP views, simple TCP payload concatenation, IOC candidates, traffic timeline, safe query-parameter filters, evidence-only AI prompting, deterministic fallback, and Markdown/JSON/PDF reports.

## Requirements
- Python 3.10+ recommended (Scapy and current dependencies may not support older runtimes).
- Optional: an OpenAI-compatible API key or local Ollama installation/model.

## Local setup

### Windows PowerShell
```powershell
cd sharkai
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
Copy-Item .env.example .env
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

### Linux / macOS
```bash
cd sharkai
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r backend/requirements.txt
cp .env.example .env
uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open http://127.0.0.1:8000. The `.env` file is an example only; export variables in your shell or load them with your preferred environment manager. Do not commit API keys.

### Optional AI providers
- **No AI / fallback:** leave `SHARKAI_AI_PROVIDER=none`. Deterministic results work without a provider.
- **OpenAI-compatible:** set `SHARKAI_AI_PROVIDER=openai`, `SHARKAI_AI_BASE_URL=https://api.openai.com/v1`, `SHARKAI_AI_API_KEY`, and `SHARKAI_AI_MODEL`. Any compatible `/chat/completions` endpoint can be used.
- **Ollama:** set `SHARKAI_AI_PROVIDER=ollama`, `SHARKAI_AI_BASE_URL=http://localhost:11434`, `SHARKAI_AI_MODEL=llama3.2` (or a model installed locally). SharkAI posts to `/api/chat` with `stream:false`.

The AI receives a deliberately bounded structured evidence summary, not the raw PCAP file. Some extracted strings (e.g. DNS names, HTTP excerpts) can still be attacker-controlled; the prompt instructs the model to treat them as untrusted evidence.

## Tests
```bash
python -m pytest -q
```

## API overview
- `GET /api/health`
- `POST /api/captures` multipart upload (`file`)
- `GET /api/captures`
- `GET /api/captures/{id}`
- `GET /api/captures/{id}/packets?protocol=TCP&src_ip=...&dst_ip=...&src_port=80&dst_port=...&contains=...&flag=...&limit=500&offset=0`
- `GET /api/captures/{id}/streams`
- `POST /api/captures/{id}/ask` JSON: `{"question":"..."}`
- `GET /api/captures/{id}/report?format=md|json|pdf`
- `DELETE /api/captures/{id}`

## Safety and known MVP limits
- Designed for local, authorized forensic and CTF use. Bind to `127.0.0.1` for a single-user workstation. Do not expose it to an untrusted network without authentication, CSRF controls, rate limiting, and a deployment review.
- Upload size defaults to 50 MB; analysis is capped at 250,000 packets. Files are stored under generated capture IDs with restrictive permissions, and the supplied filename is not used as a storage path.
- Current capture metadata lives in process memory; restarting the server clears the in-memory index. The saved `analysis.json` is groundwork for persistent indexing, not yet reloaded automatically.
- TCP payload concatenation is a simple per-direction concatenation, not full TCP sequence-number reassembly. Retransmissions/out-of-order segments may distort results. TLS payloads remain encrypted unless separately decrypted.
- “Files” are heuristic embedded-content indicators, not complete file carving. IOC/flag detection is heuristic and can have false positives/negatives.
- Safe filters are fixed API fields; this does not execute arbitrary Wireshark display-filter syntax.
- Production hardening still needed: background jobs for large captures, full TCP reassembly, protocol-aware file carving, auth, persistent database, quotas/cleanup, and sandboxing of parser workers.
