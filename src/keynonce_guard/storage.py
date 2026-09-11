from __future__ import annotations

import hashlib
import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from pydantic import ValidationError

from .models import EvidenceRecord, Finding, FindingStatus, ScanSummary

SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    file_count INTEGER NOT NULL,
    finding_count INTEGER NOT NULL,
    elapsed_ms INTEGER NOT NULL,
    analyzer_version TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id),
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    finding_id TEXT REFERENCES findings(finding_id),
    payload_json TEXT NOT NULL,
    record_digest TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS test_runs (
    test_run_id TEXT PRIMARY KEY,
    fixture_id TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS ai_explanations (
    finding_id TEXT PRIMARY KEY REFERENCES findings(finding_id),
    payload_json TEXT NOT NULL,
    validated INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
"""


class EvidenceStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def save_scan(self, summary: ScanSummary, findings: list[Finding]) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO scans(scan_id,status,file_count,finding_count,elapsed_ms,analyzer_version) "
                "VALUES(?,?,?,?,?,?)",
                (
                    summary.scan_id,
                    summary.status,
                    summary.file_count,
                    summary.finding_count,
                    summary.elapsed_ms,
                    summary.analyzer_version,
                ),
            )
            for finding in findings:
                conn.execute(
                    "INSERT INTO findings(finding_id,scan_id,payload_json) VALUES(?,?,?)",
                    (finding.finding_id, finding.scan_id, finding.model_dump_json()),
                )

    def add_evidence(self, finding_id: str | None, record: EvidenceRecord) -> EvidenceRecord:
        if record.parent_digest is None:
            with self.connect() as conn:
                previous = conn.execute(
                    "SELECT record_digest FROM evidence WHERE run_id=? "
                    "ORDER BY created_at DESC, rowid DESC LIMIT 1",
                    (record.run_id,),
                ).fetchone()
            if previous:
                record.parent_digest = previous["record_digest"]
        record.record_digest = self.compute_record_digest(record)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO evidence(evidence_id,run_id,finding_id,payload_json,record_digest) "
                "VALUES(?,?,?,?,?)",
                (
                    record.evidence_id,
                    record.run_id,
                    finding_id,
                    record.model_dump_json(),
                    record.record_digest,
                ),
            )
        return record

    @staticmethod
    def compute_record_digest(record: EvidenceRecord) -> str:
        payload = record.model_dump(mode="json", exclude={"record_digest"})
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return "sha256:" + hashlib.sha256(encoded).hexdigest()

    def verify_evidence_integrity(self) -> dict[str, object]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT rowid,evidence_id,run_id,payload_json,record_digest FROM evidence "
                "ORDER BY run_id,created_at,rowid"
            ).fetchall()
        broken: list[dict[str, str]] = []
        previous_by_run: dict[str, str] = {}
        for row in rows:
            try:
                record = EvidenceRecord.model_validate_json(row["payload_json"])
                computed = self.compute_record_digest(record)
            except ValidationError as exc:
                broken.append({"evidence_id": row["evidence_id"], "reason": type(exc).__name__})
                continue
            if computed != row["record_digest"] or record.record_digest != row["record_digest"]:
                broken.append({"evidence_id": record.evidence_id, "reason": "digest_mismatch"})
            expected_parent = previous_by_run.get(record.run_id)
            if record.parent_digest != expected_parent:
                broken.append({"evidence_id": record.evidence_id, "reason": "chain_mismatch"})
            previous_by_run[record.run_id] = row["record_digest"]
        return {"valid": not broken, "checked_records": len(rows), "broken": broken}

    def get_scan(self, scan_id: str) -> tuple[ScanSummary, list[Finding]] | None:
        with self.connect() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if not scan:
                return None
            rows = conn.execute(
                "SELECT payload_json FROM findings WHERE scan_id=? ORDER BY created_at,finding_id",
                (scan_id,),
            ).fetchall()
        summary = ScanSummary(
            scan_id=scan["scan_id"],
            status=scan["status"],
            file_count=scan["file_count"],
            finding_count=scan["finding_count"],
            elapsed_ms=scan["elapsed_ms"],
            analyzer_version=scan["analyzer_version"],
        )
        return summary, [Finding.model_validate_json(row["payload_json"]) for row in rows]

    def get_finding(self, finding_id: str) -> Finding | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT payload_json FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
        return Finding.model_validate_json(row["payload_json"]) if row else None

    def update_finding_status(self, finding_id: str, status: FindingStatus) -> Finding:
        finding = self.get_finding(finding_id)
        if finding is None:
            raise KeyError(finding_id)
        finding.status = status
        with self.connect() as conn:
            conn.execute(
                "UPDATE findings SET payload_json=? WHERE finding_id=?",
                (finding.model_dump_json(), finding_id),
            )
        return finding

    def evidence_for_finding(self, finding_id: str) -> list[EvidenceRecord]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload_json FROM evidence WHERE finding_id=? ORDER BY created_at,evidence_id",
                (finding_id,),
            ).fetchall()
        return [EvidenceRecord.model_validate_json(row["payload_json"]) for row in rows]

    def save_ai_explanation(self, finding_id: str, payload_json: str, validated: bool) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_explanations(finding_id,payload_json,validated) VALUES(?,?,?)",
                (finding_id, payload_json, 1 if validated else 0),
            )

    def save_test_run(self, test_run_id: str, fixture_id: str, status: str, payload: dict) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO test_runs(test_run_id,fixture_id,status,payload_json) VALUES(?,?,?,?)",
                (test_run_id, fixture_id, status, json.dumps(payload, sort_keys=True)),
            )
