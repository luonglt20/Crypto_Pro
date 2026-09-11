import json
from pathlib import Path


def test_packaged_fixture_manifest_matches_corpus_manifest() -> None:
    root = Path(__file__).parents[1]
    canonical = json.loads((root / "corpus/fixtures/manifest.json").read_text(encoding="utf-8"))
    packaged = json.loads(
        (root / "src/keynonce_guard/resources/fixture_manifest.json").read_text(encoding="utf-8")
    )
    assert packaged == canonical
