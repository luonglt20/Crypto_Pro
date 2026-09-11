from __future__ import annotations

from pathlib import Path

import pytest

from keynonce_guard.config import Settings
from keynonce_guard.harness import FixtureHarness
from keynonce_guard.ingest import SourceFile
from keynonce_guard.models import FindingStatus
from keynonce_guard.service import ScanService
from keynonce_guard.storage import EvidenceStore
from keynonce_guard.verification import VerificationRejected, VerificationService

FIXTURES = Path(__file__).parents[1] / "corpus" / "fixtures" / "manifest.json"


def test_negative_control_cannot_confirm_a_finding(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "db.sqlite", False, "", "", "", 1)
    store = EvidenceStore(settings.db_path)
    scan = ScanService(settings, store).scan_sources(
        [
            SourceFile(
                "bad.py",
                """\
from Crypto.Cipher import AES
def decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(ciphertext)
""",
            )
        ]
    )
    finding = next(item for item in scan.findings if item.rule_id == "KN005")
    result = VerificationService(store, FixtureHarness(FIXTURES)).verify_finding(
        finding.finding_id, "aead_tag_tamper", repeats=1
    )
    assert result["finding"]["status"] == FindingStatus.NEEDS_REVIEW.value
    assert store.verify_evidence_integrity()["valid"] is True


def test_mismatched_fixture_is_rejected(tmp_path: Path) -> None:
    settings = Settings(tmp_path / "db.sqlite", False, "", "", "", 1)
    store = EvidenceStore(settings.db_path)
    scan = ScanService(settings, store).scan_sources(
        [
            SourceFile(
                "bad.py",
                "from cryptography.hazmat.primitives.ciphers.aead import AESGCM\nAESGCM(b'0'*16)",
            )
        ]
    )
    service = VerificationService(store, FixtureHarness(FIXTURES))
    with pytest.raises(VerificationRejected):
        service.verify_finding(scan.findings[0].finding_id, "counter_reset")
