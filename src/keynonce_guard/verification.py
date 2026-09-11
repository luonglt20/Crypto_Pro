from __future__ import annotations

from dataclasses import dataclass

from .harness import FixtureHarness, FixtureRejected
from .models import EvidenceRecord, FindingStatus
from .storage import EvidenceStore


class VerificationRejected(ValueError):
    pass


@dataclass
class VerificationService:
    store: EvidenceStore
    harness: FixtureHarness

    def verify_finding(self, finding_id: str, fixture_id: str, repeats: int = 3) -> dict:
        finding = self.store.get_finding(finding_id)
        if finding is None:
            raise VerificationRejected("finding does not exist")
        fixture = self.harness.fixtures.get(fixture_id)
        if fixture is None:
            raise VerificationRejected("fixture is not allowlisted")
        if fixture["rule_id"] != finding.rule_id:
            raise VerificationRejected("fixture rule does not match finding rule")

        try:
            result = self.harness.run(fixture_id, repeats=repeats)
        except FixtureRejected as exc:
            raise VerificationRejected(str(exc)) from exc
        self.store.save_test_run(result["test_run_id"], fixture_id, result["status"], result)

        confirms = fixture.get("confirmation_effect") == "confirms_finding"
        if result["status"] == "passed" and result["reproducible"] and confirms:
            status = FindingStatus.DYNAMIC_CONFIRMED
        else:
            status = FindingStatus.NEEDS_REVIEW

        evidence = EvidenceRecord(
            run_id=result["test_run_id"],
            target_digest=self.harness.manifest_digest(),
            tool_id="allowlisted-fixture-harness",
            tool_version="0.1.0",
            rule_id=finding.rule_id,
            observed={
                "fixture_id": fixture_id,
                "test_run_id": result["test_run_id"],
                "status": result["status"],
                "reproducible": result["reproducible"],
                "confirmation_effect": fixture.get("confirmation_effect", "review_only"),
            },
        )
        self.store.add_evidence(finding_id, evidence)
        updated = self.store.update_finding_status(finding_id, status)
        return {
            "finding": updated.model_dump(mode="json"),
            "test_run": result,
            "evidence": evidence.model_dump(mode="json"),
        }
