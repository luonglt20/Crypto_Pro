from __future__ import annotations

from dataclasses import dataclass

from .analyzer import digest_source
from .ingest import load_upload
from .models import EvidenceRecord, FindingStatus
from .service import ScanService
from .storage import EvidenceStore


class RetestRejected(ValueError):
    pass


@dataclass
class RetestService:
    store: EvidenceStore
    scanner: ScanService

    def retest_upload(self, finding_id: str, filename: str, content: bytes) -> dict:
        original = self.store.get_finding(finding_id)
        if original is None:
            raise RetestRejected("finding does not exist")
        sources = load_upload(filename, content, self.scanner.settings)
        matching_source = next(
            (item for item in sources if item.path == original.location.path), None
        )
        result = self.scanner.scan_sources(sources)
        still_present = any(
            item.rule_id == original.rule_id and item.location.path == original.location.path
            for item in result.findings
        )
        if matching_source is None or result.parse_errors:
            status = FindingStatus.NEEDS_REVIEW
            reason = "target_missing_or_parse_error"
            target_digest = "sha256:unavailable"
        elif still_present:
            status = FindingStatus.NOT_FIXED
            reason = "rule_still_present"
            target_digest = digest_source(matching_source.text)
        else:
            status = FindingStatus.FIXED
            reason = "rule_absent_after_successful_retest"
            target_digest = digest_source(matching_source.text)

        evidence = EvidenceRecord(
            run_id=result.summary.scan_id,
            target_digest=target_digest,
            tool_id="remediation-retest",
            tool_version=self.scanner.analyzer.version,
            rule_id=original.rule_id,
            observed={
                "original_finding_id": finding_id,
                "target_path": original.location.path,
                "rule_still_present": still_present,
                "parse_error_count": len(result.parse_errors),
                "decision": status.value,
                "reason": reason,
            },
        )
        self.store.add_evidence(finding_id, evidence)
        updated = self.store.update_finding_status(finding_id, status)
        return {
            "finding": updated.model_dump(mode="json"),
            "retest_scan": result.summary.model_dump(mode="json"),
            "evidence": evidence.model_dump(mode="json"),
        }
