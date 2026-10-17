"""`python -m sharkai` starts the local server."""
import sys

import uvicorn

from .app import create_app
from .config import ConfigError, load_settings


def main() -> None:
    try:
        settings = load_settings()
    except ConfigError as exc:
        sys.exit(f"configuration error: {exc}")
    if settings.host not in ("127.0.0.1", "localhost", "::1"):
        print(f"WARNING: listening on {settings.host}. SharkAI has no authentication; "
              "put it behind a trusted reverse proxy and set SHARKAI_ALLOWED_HOSTS.", file=sys.stderr)
    ai = settings.ai
    print(f"SharkAI on http://{settings.host}:{settings.port}  |  AI: "
          + (f"{ai.provider} / {ai.model}" if ai.enabled else "off (deterministic results only)"))
    uvicorn.run(create_app(settings), host=settings.host, port=settings.port, log_level="info")


if __name__ == "__main__":
    main()
