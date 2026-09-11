from __future__ import annotations

from keynonce_guard.agent import ActionRejected, AgentLoopGuard
from keynonce_guard.models import AgentAction


def test_agent_rejects_non_allowlisted_tool() -> None:
    guard = AgentLoopGuard()
    action = AgentAction(
        action="shell",
        target_id="F-1",
        evidence_ids=["EV-1"],
        arguments={"command": "whoami"},
        reason="test",
    )
    try:
        guard.validate(action, {"EV-1"})
    except ActionRejected as exc:
        assert "allowlisted" in str(exc)
    else:
        raise AssertionError("unsafe action was accepted")


def test_agent_detects_loop() -> None:
    guard = AgentLoopGuard()
    action = AgentAction(
        action="get_evidence", target_id="F-1", evidence_ids=["EV-1"], reason="inspect"
    )
    guard.validate(action, {"EV-1"})
    try:
        guard.validate(action, {"EV-1"})
    except ActionRejected as exc:
        assert "loop" in str(exc)
    else:
        raise AssertionError("loop was accepted")
