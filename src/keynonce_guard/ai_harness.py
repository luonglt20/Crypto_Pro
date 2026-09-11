from __future__ import annotations

from dataclasses import dataclass

from pydantic import ValidationError

from .ai import AIAdapter, AIValidationError
from .models import (
    AIExplanation,
    Confidence,
    EvidenceRecord,
    Finding,
    FindingStatus,
    Location,
    Severity,
)


@dataclass(frozen=True)
class ContractCase:
    case_id: str
    payload: dict[str, object]
    should_accept: bool


def run_ai_contract_harness() -> dict[str, object]:
    """Exercise the post-LLM security boundary without requiring an external API."""
    finding = Finding(
        finding_id="F-HARNESS",
        scan_id="S-HARNESS",
        rule_id="KN003",
        category="fixed_nonce",
        cwe_id="CWE-323",
        severity=Severity.CRITICAL,
        confidence=Confidence.HIGH,
        status=FindingStatus.STATIC_SUSPICION,
        location=Location(path="fixture.py", line=4, column=0),
        evidence={"reason_codes": ["NONCE_CONSTANT"]},
        recommendation="Use a unique nonce.",
    )
    evidence = EvidenceRecord(
        evidence_id="EV-HARNESS",
        run_id="S-HARNESS",
        target_digest="sha256:" + "0" * 64,
        tool_id="python-ast-analyzer",
        tool_version="0.1.0",
        rule_id="KN003",
        observed={"reason_codes": ["NONCE_CONSTANT"]},
    )
    base: dict[str, object] = {
        "finding_id": finding.finding_id,
        "summary": "Rule KN003 observed a constant nonce.",
        "observed_evidence": ["EV-HARNESS: NONCE_CONSTANT"],
        "evidence_ids": ["EV-HARNESS"],
        "risk_context": "Status remains static_suspicion.",
        "recommendation": "Use a unique nonce.",
        "limitations": "No production execution was observed.",
    }
    cases = [
        ContractCase("valid_grounded", dict(base), True),
        ContractCase("unknown_evidence", {**base, "evidence_ids": ["EV-INVENTED"]}, False),
        ContractCase("wrong_finding", {**base, "finding_id": "F-INVENTED"}, False),
        ContractCase("invented_cve", {**base, "risk_context": "Confirmed CVE-2099-0001."}, False),
        ContractCase("schema_smuggling", {**base, "severity": "low"}, False),
        ContractCase("missing_citation", {**base, "evidence_ids": []}, False),
    ]
    outcomes: list[dict[str, object]] = []
    unsafe_accepted = 0
    false_rejected = 0
    for case in cases:
        accepted = False
        reason = "accepted"
        try:
            parsed = AIExplanation.model_validate(case.payload)
            AIAdapter.verify_candidate(parsed, finding, [evidence])
            accepted = True
        except (ValidationError, AIValidationError) as exc:
            reason = type(exc).__name__
        passed = accepted == case.should_accept
        if accepted and not case.should_accept:
            unsafe_accepted += 1
        if not accepted and case.should_accept:
            false_rejected += 1
        outcomes.append(
            {"case_id": case.case_id, "accepted": accepted, "passed": passed, "reason": reason}
        )
    return {
        "cases": outcomes,
        "metrics": {
            "case_count": len(cases),
            "pass_count": sum(bool(item["passed"]) for item in outcomes),
            "unsafe_acceptance_rate": unsafe_accepted / max(1, len(cases) - 1),
            "false_rejection_rate": false_rejected,
        },
    }
