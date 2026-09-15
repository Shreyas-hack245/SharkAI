# SharkAI

**SharkAI — Your AI-Powered Network Traffic Analyst**

SharkAI combines deterministic PCAP analysis with an evidence-first AI investigation layer. Upload a PCAP, inspect packets and streams, hunt CTF flags, and ask focused questions without sending the raw capture to an LLM.

## What it does

- Validated `.pcap`, `.pcapng`, and `.cap` upload with isolated processing.
- tshark-powered packet indexing, packet details, hex view, TCP streams, HTTP, DNS, files, IOCs, timeline, and graph data.
- CTF flag searching across packet payloads and reconstructed TCP streams.
- Safe, allowlisted display filters and AI tool calls.
- Configurable OpenAI-compatible or Ollama-compatible AI provider.
- Evidence-first findings with packet and stream references.
- Markdown, JSON, and PDF investigation reports.

## Architecture

```text
React UI → FastAPI → Analysis service → tshark / analyzers → SQLite
                       ↓
               AI tool gateway → configured AI provider
```

The AI receives only structured tool results. It cannot run shell commands or directly process the uploaded PCAP.

## Requirements

- Python 3.11+
- Node.js 20+
- Wireshark/tshark on `PATH` (or set `TSHARK_PATH`)

## Run locally

```powershell
Copy-Item .env.example .env
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r backend\requirements.txt
cd frontend
npm install
npm run build
```

Start the API from `backend`:

```powershell
uvicorn app.main:app --reload --port 8000
```

Start the frontend from `frontend`:

```powershell
npm run dev
```

Vite proxies `/api` requests to the FastAPI service during development.

## AI configuration

Set `AI_PROVIDER`, `AI_BASE_URL`, `AI_MODEL`, and, when needed, `AI_API_KEY` in `.env`.

- OpenAI-compatible: `AI_BASE_URL=https://api.openai.com/v1`
- Ollama OpenAI compatibility: `AI_BASE_URL=http://localhost:11434/v1`

If the provider is unreachable, SharkAI uses deterministic fallback investigation paths for flag, credential, and summary requests.

## API highlights

- `POST /api/captures/upload`
- `GET /api/captures/{id}/packets`
- `GET /api/captures/{id}/streams/{stream_id}`
- `GET /api/captures/{id}/report?format=markdown|json|pdf`
- `POST /api/ai/investigate`
- `POST /api/ai/search`

Interactive OpenAPI documentation is available at `/docs`.

## Security model

Captures are size-limited and header-validated. Uploads are stored in a per-capture directory. Display filters and AI tools are allowlisted; no model output is passed into a shell. Extracted files are never executed.

## Testing

```powershell
py -3.11 -m pytest -q
```

Use only captures you are authorized to inspect.
