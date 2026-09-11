from __future__ import annotations

import hashlib
import json
import os
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path
from uuid import uuid4


class FixtureRejected(ValueError):
    pass


class FixtureHarness:
    def __init__(self, manifest_path: Path) -> None:
        self.manifest_path = manifest_path
        document = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.fixtures = {item["fixture_id"]: item for item in document["fixtures"]}

    def run(self, fixture_id: str, repeats: int = 3) -> dict:
        fixture = self.fixtures.get(fixture_id)
        if not fixture:
            raise FixtureRejected("fixture is not allowlisted")
        if not 1 <= repeats <= 3:
            raise FixtureRejected("repeats must be between 1 and 3")
        results = [self._run_once(fixture["handler"]) for _ in range(repeats)]
        stable = all(item["oracle"] == results[0]["oracle"] for item in results[1:])
        passed = stable and all(item.get("passed") is True for item in results)
        return {
            "test_run_id": f"TR-{uuid4().hex[:12]}",
            "fixture_id": fixture_id,
            "rule_id": fixture["rule_id"],
            "status": "passed" if passed else "failed",
            "reproducible": stable,
            "runs": results,
        }

    @staticmethod
    def _run_once(handler: str) -> dict:
        monitor_key = secrets.token_bytes(32).hex()
        env = {
            "PATH": os.environ.get("PATH", ""),
            "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
            "PYTHONPATH": str(Path(__file__).resolve().parents[1]),
            "PYTHONIOENCODING": "utf-8",
            "KEYNONCE_MONITOR_KEY": monitor_key,
        }
        with tempfile.TemporaryDirectory(prefix="keynonce-fixture-") as workdir:
            process = subprocess.run(
                [sys.executable, "-m", "keynonce_guard.harness_worker", handler],
                cwd=workdir,
                env=env,
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        if process.returncode != 0:
            raise FixtureRejected(f"fixture worker failed with code {process.returncode}")
        if len(process.stdout) > 100_000:
            raise FixtureRejected("fixture output exceeded limit")
        try:
            return json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            raise FixtureRejected("fixture returned invalid JSON") from exc

    def manifest_digest(self) -> str:
        raw = self.manifest_path.read_bytes()
        return "sha256:" + hashlib.sha256(raw).hexdigest()
