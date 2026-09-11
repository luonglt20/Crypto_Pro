from __future__ import annotations

import io
import stat
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath

from .config import Settings


class UploadRejected(ValueError):
    pass


@dataclass(frozen=True)
class SourceFile:
    path: str
    text: str


def load_upload(filename: str, content: bytes, settings: Settings) -> list[SourceFile]:
    if len(content) > settings.max_upload_bytes:
        raise UploadRejected("Tệp vượt quá giới hạn 5 MB")
    lowered = filename.lower()
    if lowered.endswith(".py"):
        return [SourceFile(_safe_path(filename), _decode(content))]
    if lowered.endswith(".zip"):
        return _load_zip(content, settings)
    raise UploadRejected("Chỉ chấp nhận tệp .py hoặc .zip")


def _load_zip(content: bytes, settings: Settings) -> list[SourceFile]:
    result: list[SourceFile] = []
    total = 0
    try:
        archive = zipfile.ZipFile(io.BytesIO(content))
    except zipfile.BadZipFile as exc:
        raise UploadRejected("ZIP không hợp lệ") from exc
    with archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            path = _safe_path(info.filename)
            mode = info.external_attr >> 16
            if mode and stat.S_ISLNK(mode):
                raise UploadRejected("ZIP chứa symlink")
            if path.lower().endswith(".zip"):
                raise UploadRejected("Không cho phép archive lồng")
            if not path.lower().endswith(".py"):
                continue
            total += info.file_size
            if total > settings.max_unpacked_bytes:
                raise UploadRejected("Dung lượng sau giải nén vượt giới hạn")
            if info.compress_size and info.file_size / info.compress_size > 200:
                raise UploadRejected("Tỷ lệ nén bất thường")
            if len(result) >= settings.max_python_files:
                raise UploadRejected("Số tệp Python vượt giới hạn")
            result.append(SourceFile(path, _decode(archive.read(info))))
    if not result:
        raise UploadRejected("ZIP không chứa tệp Python hợp lệ")
    return result


def _safe_path(raw: str) -> str:
    normalized = raw.replace("\\", "/")
    path = PurePosixPath(normalized)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise UploadRejected("Đường dẫn không an toàn")
    if ":" in path.parts[0] or normalized.startswith("//"):
        raise UploadRejected("Đường dẫn tuyệt đối không được phép")
    return path.as_posix()


def _decode(content: bytes) -> str:
    if b"\x00" in content:
        raise UploadRejected("Tệp Python chứa byte NUL")
    try:
        return content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise UploadRejected("Tệp Python phải dùng UTF-8") from exc
