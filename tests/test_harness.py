from __future__ import annotations

from pathlib import Path

import pytest

from keynonce_guard.harness import FixtureHarness, FixtureRejected

MANIFEST = Path(__file__).parents[1] / "corpus" / "fixtures" / "manifest.json"


def test_nonce_reuse_is_confirmed_reproducibly() -> None:
    result = FixtureHarness(MANIFEST).run("nonce_reuse_aesgcm", repeats=3)
    assert result["status"] == "passed"
    assert result["reproducible"] is True


def test_tampered_tag_is_rejected() -> None:
    result = FixtureHarness(MANIFEST).run("aead_tag_tamper", repeats=1)
    assert result["runs"][0]["oracle"]["tamper_rejected"] is True


def test_unknown_fixture_is_rejected() -> None:
    with pytest.raises(FixtureRejected):
        FixtureHarness(MANIFEST).run("../../arbitrary")
