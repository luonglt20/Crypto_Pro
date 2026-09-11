from pathlib import Path

from keynonce_guard.config import Settings
from keynonce_guard.ingest import SourceFile
from keynonce_guard.retest import RetestService
from keynonce_guard.service import ScanService
from keynonce_guard.storage import EvidenceStore

BAD = b"""\
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    return AESGCM(b'0123456789abcdef').encrypt(os.urandom(12), data, None)
"""

FIXED = b"""\
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    return AESGCM(key).encrypt(os.urandom(12), data, None)
"""


def setup(tmp_path: Path):
    settings = Settings(tmp_path / "db.sqlite", False, "", "", "", 1)
    store = EvidenceStore(settings.db_path)
    scanner = ScanService(settings, store)
    original = scanner.scan_sources([SourceFile("sample.py", BAD.decode())]).findings[0]
    return store, scanner, original


def test_retest_marks_fixed_only_when_rule_disappears(tmp_path: Path) -> None:
    store, scanner, original = setup(tmp_path)
    result = RetestService(store, scanner).retest_upload(original.finding_id, "sample.py", FIXED)
    assert result["finding"]["status"] == "fixed"
    assert store.verify_evidence_integrity()["valid"] is True


def test_retest_marks_not_fixed_when_rule_remains(tmp_path: Path) -> None:
    store, scanner, original = setup(tmp_path)
    result = RetestService(store, scanner).retest_upload(original.finding_id, "sample.py", BAD)
    assert result["finding"]["status"] == "not_fixed"


def test_retest_does_not_claim_fixed_for_wrong_filename(tmp_path: Path) -> None:
    store, scanner, original = setup(tmp_path)
    result = RetestService(store, scanner).retest_upload(original.finding_id, "renamed.py", FIXED)
    assert result["finding"]["status"] == "needs_review"
