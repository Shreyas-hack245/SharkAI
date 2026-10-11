# SharkAI — Your AI-Powered Network Traffic Analyst

SharkAI is a local-first network forensics and CTF analysis assistant. It combines deterministic packet analysis with an evidence-first AI investigation layer, so you can explore a capture, search for flags and indicators of compromise (IOCs), and ask focused questions without sending the raw PCAP file to an AI provider.

## Features

- **Capture upload:** Accepts `.pcap`, `.pcapng`, and `.cap` files with size limits and validation.
- **Packet inspection:** Browse packet metadata and payload excerpts, with packet details and hex-oriented inspection where supported by the configured analyzer.
- **Protocol views:** Explore TCP streams, HTTP, DNS, and file-related indicators.
- **CTF flag hunting:** Search packet payloads and reconstructed TCP payload streams for common flag patterns.
- **IOC candidates:** Surface potentially interesting domains, URLs, IP addresses, and other strings for investigation.
- **Timeline and traffic graph:** Review activity over time and inspect basic traffic relationships.
- **Safe filters:** Use predefined, allowlisted filter fields instead of passing arbitrary display-filter expressions to a shell.
- **Evidence-first AI:** The AI layer receives bounded, structured analysis results—not the original PCAP file. Extracted network content is still untrusted and may contain attacker-controlled strings.
- **Provider flexibility:** Configure an OpenAI-compatible endpoint or Ollama-compatible provider. Deterministic fallback paths keep core investigations useful when the provider is unavailable.
- **Reports:** Export investigation results as Markdown, JSON, or PDF.
- **Local-first workflow:** Intended for authorized analysis on your own workstation.

## Architecture

```text
React UI
   │
   ▼
FastAPI backend
   │
   ▼
Analysis service ──► tshark / protocol analyzers
   │                         │
   │                         ▼
   │                    Packet evidence
   ▼
SQLite / capture metadata
   │
   ▼
AI tool gateway ──► Configured AI provider
   │
   └──► Deterministic fallback when AI is unavailable
```

The AI tool gateway exposes only approved investigation operations. Model output is not passed to a shell, and the model does not receive the raw capture file directly.

> **Implementation note:** The repository may contain an earlier MVP implementation with in-memory capture metadata, Scapy-based analysis, and simplified TCP payload concatenation. Treat architecture elements such as SQLite persistence, full TCP reassembly, complete file carving, and tshark-backed indexing as implemented only if the current source code confirms them.

## Requirements

- Python 3.11 or newer recommended.
- Node.js 20 or newer for the React/Vite frontend.
- Wireshark `tshark` on `PATH` if using the tshark-based analyzer. Set `TSHARK_PATH` if it is installed in a non-standard location.
- Optional: an OpenAI-compatible API key or a local Ollama installation with a model downloaded.

## Project structure

The exact structure depends on the checked-out version. A full-stack version may look like this:

```text
sharkai/
├── backend/
│   ├── app/
│   ├── requirements.txt
│   └── tests/
├── frontend/
│   ├── src/
│   ├── package.json
│   └── vite.config.*
├── .env.example
└── README.md
```

If your checkout uses the earlier single-app MVP, the API entry point may instead be `backend.app:app`; see the relevant setup section below.

## Local setup

### Option A: Full-stack React + FastAPI version

Run these commands from the project root in Windows PowerShell:

```powershell
Copy-Item .env.example .env

py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install -r backend\requirements.txt

cd frontend
npm install
npm run build
```

Start the API in a **first terminal**, from the `backend` directory:

```powershell
cd ..\backend
python -m uvicorn app.main:app --reload --port 8000
```

Start the frontend in a **second terminal**, from the project root:

```powershell
cd ..\frontend
npm run dev
```

Open the local URL printed by Vite in the terminal. During development, Vite should proxy `/api` requests to the FastAPI server on port `8000`.

If your backend package uses a different entry point, check the files in `backend` and use the matching import path.

### Option B: Earlier single-app MVP

If the project contains `backend/app.py` rather than `backend/app/main.py`, run this from the project root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1

python -m pip install -r backend\requirements.txt
Copy-Item .env.example .env

python -m uvicorn backend.app:app --host 127.0.0.1 --port 8000
```

Open <http://127.0.0.1:8000>.

**Important:** Do not run both API entry points. Use the setup that matches the files in your checkout. If dependency installation is interrupted, rerun the install command and wait for it to finish before starting the server.

## Configuration

Copy `.env.example` to `.env`, then configure the variables supported by your version. Do not commit secrets.

### Upload and analysis limits

The earlier MVP defaults to a 50 MB upload limit and a maximum of 250,000 packets. If the code supports the `SHARKAI_MAX_UPLOAD_MB` setting, you can change the value in `.env`, for example:

```dotenv
SHARKAI_MAX_UPLOAD_MB=200
```

Restart the backend after changing configuration. Confirm the exact variable name in the upload endpoint or settings module; changing `.env` has no effect unless the application reads that setting. Larger captures may require more memory and processing time.

### AI provider

Variable names differ between versions. The earlier MVP uses `SHARKAI_AI_*` variables; the full-stack configuration may use `AI_*` variables. Follow the names in your `.env.example`.

Example OpenAI-compatible configuration:

```dotenv
AI_PROVIDER=openai
AI_BASE_URL=https://api.openai.com/v1
AI_MODEL=gpt-4o-mini
AI_API_KEY=replace-with-your-key
```

Example Ollama configuration (OpenAI-compatible endpoint):

```dotenv
AI_PROVIDER=openai
AI_BASE_URL=http://localhost:11434/v1
AI_MODEL=llama3.2
AI_API_KEY=
```

Some versions support a native Ollama mode instead. For that mode, use the provider name and base URL format documented in the matching configuration or source code. Ensure Ollama is running and the selected model is available locally.

For deterministic-only operation, select the `none` provider if supported by your version. Flag searches and other deterministic analyses should remain available without an AI service.

## API overview

Endpoints depend on the selected implementation. The earlier MVP exposes routes similar to:

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/captures` | Upload a capture |
| `GET` | `/api/captures` | List captures |
| `GET` | `/api/captures/{id}` | Retrieve capture summary |
| `GET` | `/api/captures/{id}/packets` | Browse and filter packets |
| `GET` | `/api/captures/{id}/streams` | List TCP streams |
| `GET` | `/api/captures/{id}/streams/{stream_id}` | Inspect a stream, if supported |
| `POST` | `/api/captures/{id}/ask` | Ask a question about structured evidence |
| `GET` | `/api/captures/{id}/report?format=md` | Download a report |
| `DELETE` | `/api/captures/{id}` | Delete a capture, if supported |

The alternate full-stack design may use routes such as `POST /api/captures/upload` and `POST /api/ai/investigate`. Check the interactive API documentation at <http://127.0.0.1:8000/docs> after starting the backend.

## Testing

Activate the virtual environment and run tests from the project root:

```powershell
python -m pytest -q
```

For the frontend, run:

```powershell
cd frontend
npm test
```

The frontend test command is available only if a test script is defined in `frontend/package.json`.

## Security and privacy

- Analyze only captures you are authorized to inspect.
- Keep the service bound to `127.0.0.1` for single-user local use.
- Do not expose the app to an untrusted network without authentication, authorization, CSRF protections where applicable, rate limiting, request-size limits, and a deployment security review.
- Store API keys in local environment configuration and never commit `.env`.
- Captures may contain credentials, session cookies, personal data, and other sensitive information. Protect stored captures and reports accordingly.
- The AI receives structured evidence rather than the raw capture, but evidence can include attacker-controlled DNS names, URLs, HTTP strings, or payload excerpts. Treat those values as untrusted input.
- Never execute extracted files. Use an isolated, disposable analysis environment for suspicious samples.
- Upload limits alone do not prevent resource exhaustion. Large captures can use significant CPU, memory, and disk space.
- Validate parser and report-generation behavior before using SharkAI for incident-response decisions.

## Known limitations

Depending on the version and enabled analyzer, limitations may include:

- TCP payload concatenation without full TCP sequence-number reassembly; out-of-order segments and retransmissions can affect results.
- TLS payloads remain encrypted unless decryption material is separately available and configured.
- File indicators may be heuristic rather than complete protocol-aware file carving.
- IOC and flag detection may produce false positives and false negatives.
- Capture indexing may be in memory and lost when the backend restarts.
- Large-file analysis may run synchronously rather than in a background job.
- Authentication, multi-user isolation, retention policies, and production hardening may not be implemented.

## Responsible use

SharkAI is intended for local network forensics, defensive investigation, education, and authorized CTF work. You are responsible for having permission to inspect each capture and for protecting any sensitive data it contains.
