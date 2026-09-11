from __future__ import annotations

import io
import zipfile
from pathlib import Path

import pytest

from keynonce_guard.config import Settings
from keynonce_guard.ingest import UploadRejected, load_upload


def settings(tmp_path: Path) -> Settings:
    return Settings(tmp_path / "db.sqlite", False, "", "", "", 1)


def make_zip(entries: dict[str, bytes]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for path, value in entries.items():
            archive.writestr(path, value)
    return buffer.getvalue()


def test_safe_zip_is_loaded(tmp_path: Path) -> None:
    files = load_upload("code.zip", make_zip({"src/a.py": b"value = 1"}), settings(tmp_path))
    assert [(item.path, item.text) for item in files] == [("src/a.py", "value = 1")]


@pytest.mark.parametrize("path", ["../escape.py", "/absolute.py", "C:/drive.py"])
def test_unsafe_paths_are_rejected(tmp_path: Path, path: str) -> None:
    with pytest.raises(UploadRejected):
        load_upload("code.zip", make_zip({path: b"pass"}), settings(tmp_path))


def test_nested_archive_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(UploadRejected):
        load_upload("code.zip", make_zip({"inner.zip": b"not-a-zip"}), settings(tmp_path))
