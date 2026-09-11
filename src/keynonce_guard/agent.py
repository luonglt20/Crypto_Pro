from __future__ import annotations

from dataclasses import dataclass, field

from .models import AgentAction

ALLOWED_ACTIONS: dict[str, set[str]] = {
    "get_finding": set(),
    "get_evidence": set(),
    "lookup_cwe": {"cwe_id"},
    "retrieve_cve_candidates": {"component", "version"},
    "check_version_applicability": {"candidate_id", "component", "version"},
    "get_remediation": {"rule_id"},
    "request_fixture_test": {"fixture_test_id"},
    "summarize_result": set(),
    "stop": set(),
}


class ActionRejected(ValueError):
    pass


@dataclass
class AgentLoopGuard:
    max_steps: int = 6
    max_test_requests: int = 2
    seen: set[tuple[str, str, tuple[tuple[str, str], ...]]] = field(default_factory=set)
    steps: int = 0
    test_requests: int = 0

    def validate(self, action: AgentAction, valid_evidence_ids: set[str]) -> None:
        if self.steps >= self.max_steps:
            raise ActionRejected("step budget exceeded")
        allowed_args = ALLOWED_ACTIONS.get(action.action)
        if allowed_args is None:
            raise ActionRejected("tool is not allowlisted")
        if set(action.arguments) - allowed_args:
            raise ActionRejected("argument is not allowlisted")
        if not set(action.evidence_ids) <= valid_evidence_ids:
            raise ActionRejected("action references unknown evidence")
        signature = (action.action, action.target_id, tuple(sorted(action.arguments.items())))
        if signature in self.seen:
            raise ActionRejected("agent loop detected")
        if action.action == "request_fixture_test":
            if self.test_requests >= self.max_test_requests:
                raise ActionRejected("test request budget exceeded")
            self.test_requests += 1
        self.seen.add(signature)
        self.steps += 1
