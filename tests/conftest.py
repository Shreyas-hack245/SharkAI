import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from sharkai.app import create_app  # noqa: E402
from sharkai.config import AISettings, Settings  # noqa: E402
from sharkai.samples import sample_ctf_capture  # noqa: E402

H = {"X-SharkAI": "1"}


@pytest.fixture(scope="session")
def demo_pcap() -> bytes:
    return sample_ctf_capture()


def make_settings(tmp_path, **kw) -> Settings:
    kw.setdefault("allowed_hosts", ("testserver",))
    return Settings(data_dir=tmp_path / "data", **kw)


@pytest.fixture
def settings(tmp_path):
    return make_settings(tmp_path)


@pytest.fixture
def client(settings):
    return TestClient(create_app(settings))


@pytest.fixture
def capture_id(client, demo_pcap):
    r = client.post("/api/captures?filename=demo.pcap", content=demo_pcap, headers=H)
    assert r.status_code == 201, r.text
    return r.json()["id"]


def ai_client(tmp_path, handler, provider="openai", **kw):
    """TestClient whose AI provider is an in-process mock transport."""
    base = "http://llm.test/v1" if provider == "openai" else "http://llm.test"
    ai = AISettings(provider=provider, base_url=base, model="test-model", api_key=kw.pop("api_key", "sk-secret-key"), **kw)
    app = create_app(make_settings(tmp_path, ai=ai), ai_transport=httpx.MockTransport(handler))
    return TestClient(app)
