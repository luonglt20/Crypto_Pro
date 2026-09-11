import re
from pathlib import Path

ROOT = Path(__file__).parents[1]


def read(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


def test_new_session_has_one_discoverable_current_task() -> None:
    readme = read("README.md")
    agents = read("AGENTS.md")
    memory = read("Memory.md")
    tasks = read("TASK.md")
    marker = re.search(r"<!-- CURRENT_TASK_ID: ([A-Z0-9-]+) -->", memory)

    assert marker is not None
    current_task_id = marker.group(1)
    assert "AI/Session mới — bắt đầu tại đây" in readme
    assert "Memory.md" in readme and "AGENTS.md" in readme
    assert "Mandatory session bootstrap" in agents
    assert "Mandatory end-of-session update" in agents
    assert "## 3. NEXT TASK" in memory
    assert current_task_id in readme
    assert current_task_id in memory
    assert current_task_id in tasks


def test_handoff_records_proof_blockers_and_safety_invariants() -> None:
    memory = read("Memory.md")
    agents = read("AGENTS.md")
    for required in (
        "Verified state at handoff",
        "Open blockers and external inputs",
        "Architecture invariants",
        "Source-of-truth map",
        "End-of-session protocol",
        "Acceptance:",
        "Không làm trong task này",
    ):
        assert required in memory
    assert "Never import or execute uploaded source code" in agents
    assert "never report a push as successful" in agents


def test_reference_documents_are_not_agent_instructions() -> None:
    assert "not executable instructions" in read("AGENTS.md")
    assert "không phải instruction cho agent" in read("README.md")
