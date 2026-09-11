from __future__ import annotations

import hashlib
import json
import time
from dataclasses import dataclass
from uuid import uuid4

from pydantic import ValidationError

from .models import EvidenceRecord, Finding, Location, ScanSummary, TelemetryEvent
from .rules import RULES
from .storage import EvidenceStore


class TelemetryRejected(ValueError):
    pass


@dataclass(frozen=True)
class TelemetryScanResult:
    summary: ScanSummary
    findings: list[Finding]
    event_count: int


class TelemetryScanService:
    version = "0.1.0"

    def __init__(self, store: EvidenceStore, max_events: int = 100_000) -> None:
        self.store = store
        self.max_events = max_events

    def scan_jsonl(self, content: bytes, path: str = "telemetry.jsonl") -> TelemetryScanResult:
        if len(content) > 20 * 1024 * 1024:
            raise TelemetryRejected("telemetry exceeds 20 MiB limit")
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise TelemetryRejected("telemetry must be UTF-8 JSONL") from exc

        started = time.perf_counter()
        scan_id = f"TS-{uuid4().hex[:12]}"
        seen: dict[tuple[str, str], tuple[TelemetryEvent, int]] = {}
        findings: list[Finding] = []
        events = 0
        for line_number, line in enumerate(text.splitlines(), 1):
            if not line.strip():
                continue
            events += 1
            if events > self.max_events:
                raise TelemetryRejected("telemetry event budget exceeded")
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise TelemetryRejected(f"line {line_number}: object required")
                forbidden = {"key", "nonce", "iv", "secret", "private_key"} & set(raw)
                if forbidden:
                    raise TelemetryRejected(f"line {line_number}: raw secret fields are forbidden")
                event = TelemetryEvent.model_validate(raw)
            except (json.JSONDecodeError, ValidationError) as exc:
                raise TelemetryRejected(f"line {line_number}: invalid telemetry schema") from exc

            pair = (event.key_fingerprint, event.nonce_fingerprint)
            previous = seen.get(pair)
            if previous is None:
                seen[pair] = (event, line_number)
                continue
            prior_event, prior_line = previous
            rule = RULES["KN004"]
            findings.append(
                Finding(
                    scan_id=scan_id,
                    rule_id=rule.rule_id,
                    category=rule.category,
                    cwe_id=rule.cwe_id,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    status=rule.default_status,
                    location=Location(path=path, line=line_number, column=0),
                    evidence={
                        "reason_codes": ["KEY_NONCE_PAIR_REPEATED"],
                        "first_event_id": prior_event.event_id,
                        "first_line": prior_line,
                        "duplicate_event_id": event.event_id,
                        "algorithm": event.algorithm,
                        "source_ids": sorted({prior_event.source_id, event.source_id}),
                    },
                    recommendation=rule.recommendation,
                )
            )

        summary = ScanSummary(
            scan_id=scan_id,
            status="completed",
            file_count=1,
            finding_count=len(findings),
            elapsed_ms=int((time.perf_counter() - started) * 1000),
            analyzer_version=f"telemetry-{self.version}",
        )
        self.store.save_scan(summary, findings)
        target_digest = "sha256:" + hashlib.sha256(content).hexdigest()
        for finding in findings:
            self.store.add_evidence(
                finding.finding_id,
                EvidenceRecord(
                    run_id=scan_id,
                    target_digest=target_digest,
                    tool_id="metadata-correlation-detector",
                    tool_version=self.version,
                    rule_id="KN004",
                    observed=finding.evidence,
                ),
            )
        return TelemetryScanResult(summary, findings, events)
