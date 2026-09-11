from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from keynonce_guard.app import create_app
from keynonce_guard.config import Settings


def test_api_scan_and_explain_fallback(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "db.sqlite", False, "", "", "", 1)
    client = TestClient(create_app(settings))
    source = b"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    return AESGCM(b'0123456789abcdef').encrypt(os.urandom(12), data, None)
"""
    response = client.post("/api/v1/scans", files={"file": ("sample.py", source, "text/x-python")})
    assert response.status_code == 201
    body = response.json()
    finding_id = body["findings"][0]["finding_id"]
    explanation = client.post(f"/api/v1/findings/{finding_id}/explain")
    assert explanation.status_code == 200
    assert explanation.json()["provider"] == "deterministic-fallback"
