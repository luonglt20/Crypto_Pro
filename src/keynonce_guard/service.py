from __future__ import annotations

import ast
import time
from dataclasses import dataclass
from uuid import uuid4

from .analyzer import CryptoAnalyzer, digest_source
from .config import Settings
from .ingest import SourceFile, load_upload
from .models import EvidenceRecord, Finding, ScanSummary
from .storage import EvidenceStore


@dataclass(frozen=True)
class ScanResult:
    summary: ScanSummary
    findings: list[Finding]
    parse_errors: list[dict[str, str | int]]


class ScanService:
    def __init__(self, settings: Settings, store: EvidenceStore) -> None:
        self.settings = settings
        self.store = store
        self.analyzer = CryptoAnalyzer()

    def scan_upload(self, filename: str, content: bytes) -> ScanResult:
        sources = load_upload(filename, content, self.settings)
        return self.scan_sources(sources)

    def scan_sources(self, sources: list[SourceFile]) -> ScanResult:
        started = time.perf_counter()
        scan_id = f"S-{uuid4().hex[:12]}"
        findings: list[Finding] = []
        parse_errors: list[dict[str, str | int]] = []
        total_nodes = 0
        source_digests: dict[str, str] = {}
        for source in sources:
            source_digests[source.path] = digest_source(source.text)
            try:
                tree = ast.parse(source.text, filename=source.path)
                total_nodes += sum(1 for _ in ast.walk(tree))
                if total_nodes > self.settings.max_ast_nodes:
                    raise ValueError("AST node budget exceeded")
                findings.extend(self.analyzer.analyze(source.text, source.path, scan_id))
            except SyntaxError as exc:
                parse_errors.append(
                    {
                        "path": source.path,
                        "line": exc.lineno or 1,
                        "message": "Không thể parse cú pháp Python",
                    }
                )
        elapsed_ms = int((time.perf_counter() - started) * 1000)
        summary = ScanSummary(
            scan_id=scan_id,
            status="completed_with_parse_errors" if parse_errors else "completed",
            file_count=len(sources),
            finding_count=len(findings),
            elapsed_ms=elapsed_ms,
            analyzer_version=self.analyzer.version,
        )
        self.store.save_scan(summary, findings)
        for finding in findings:
            observed = {
                "path": finding.location.path,
                "line": finding.location.line,
                "rule_id": finding.rule_id,
                **finding.evidence,
            }
            record = EvidenceRecord(
                run_id=scan_id,
                target_digest=source_digests[finding.location.path],
                tool_id="python-ast-analyzer",
                tool_version=self.analyzer.version,
                rule_id=finding.rule_id,
                observed=observed,
            )
            self.store.add_evidence(finding.finding_id, record)
        return ScanResult(summary, findings, parse_errors)
