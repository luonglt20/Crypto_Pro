from keynonce_guard.ai_harness import run_ai_contract_harness


def test_ai_contract_harness_rejects_all_unsafe_outputs() -> None:
    report = run_ai_contract_harness()
    assert report["metrics"]["pass_count"] == report["metrics"]["case_count"]
    assert report["metrics"]["unsafe_acceptance_rate"] == 0
