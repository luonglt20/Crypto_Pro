from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from keynonce_guard.storage import EvidenceStore
from keynonce_guard.telemetry import TelemetryRejected, TelemetryScanService


def event(event_id: str, nonce: str) -> dict[str, str]:
    return {
        "event_id": event_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "operation": "encrypt",
        "algorithm": "AES-256-GCM",
        "key_fingerprint": "hmac-sha256:" + "a" * 64,
        "nonce_fingerprint": "hmac-sha256:" + nonce * 64,
        "source_id": "service-a",
    }


def encode(*items: dict[str, str]) -> bytes:
    return ("\n".join(json.dumps(item) for item in items) + "\n").encode()


def test_duplicate_pair_is_dynamically_confirmed(tmp_path: Path) -> None:
    store = EvidenceStore(tmp_path / "db.sqlite")
    result = TelemetryScanService(store).scan_jsonl(encode(event("e1", "b"), event("e2", "b")))
    assert result.event_count == 2
    assert result.findings[0].rule_id == "KN004"
    assert result.findings[0].status == "dynamic_confirmed"
    assert store.verify_evidence_integrity()["valid"] is True


def test_raw_nonce_field_is_rejected(tmp_path: Path) -> None:
    item = event("e1", "b")
    item["nonce"] = "raw-value"
    with pytest.raises(TelemetryRejected, match="raw secret"):
        TelemetryScanService(EvidenceStore(tmp_path / "db.sqlite")).scan_jsonl(encode(item))
