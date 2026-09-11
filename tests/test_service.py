from __future__ import annotations

from pathlib import Path

from keynonce_guard.config import Settings
from keynonce_guard.ingest import SourceFile
from keynonce_guard.service import ScanService
from keynonce_guard.storage import EvidenceStore


def test_scan_persists_finding_and_evidence(tmp_path: Path) -> None:
    config = Settings(tmp_path / "db.sqlite", False, "", "", "", 1)
    store = EvidenceStore(config.db_path)
    service = ScanService(config, store)
    source = """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    return AESGCM(b'0123456789abcdef').encrypt(b'0123456789ab', data, None)
"""
    result = service.scan_sources([SourceFile("sample.py", source)])
    assert result.summary.finding_count >= 2
    finding = result.findings[0]
    assert store.get_finding(finding.finding_id) is not None
    evidence = store.evidence_for_finding(finding.finding_id)
    assert len(evidence) == 1
    assert evidence[0].record_digest.startswith("sha256:")
