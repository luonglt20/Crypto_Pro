from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    db_path: Path
    ai_enabled: bool
    ai_base_url: str
    ai_api_key: str
    ai_model: str
    ai_timeout_seconds: float
    max_upload_bytes: int = 5 * 1024 * 1024
    max_unpacked_bytes: int = 20 * 1024 * 1024
    max_python_files: int = 200
    max_ast_nodes: int = 250_000

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            db_path=Path(os.getenv("KEYNONCE_DB_PATH", "data/keynonce_guard.db")),
            ai_enabled=os.getenv("AI_ENABLED", "false").lower() == "true",
            ai_base_url=os.getenv("AI_BASE_URL", "https://api.openai.com/v1").rstrip("/"),
            ai_api_key=os.getenv("AI_API_KEY", ""),
            ai_model=os.getenv("AI_MODEL", ""),
            ai_timeout_seconds=float(os.getenv("AI_TIMEOUT_SECONDS", "20")),
        )
