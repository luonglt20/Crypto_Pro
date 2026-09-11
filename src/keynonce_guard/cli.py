from __future__ import annotations

import argparse
import json
from pathlib import Path

from .ai_harness import run_ai_contract_harness
from .analyzer import CryptoAnalyzer
from .config import Settings
from .ingest import SourceFile
from .service import ScanService
from .storage import EvidenceStore


def evaluate_corpus(path: Path) -> dict:
    analyzer = CryptoAnalyzer()
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    tp = fp = fn = tn = 0
    cases = []
    for case in manifest["cases"]:
        source_path = path / case["path"]
        findings = analyzer.analyze(source_path.read_text(encoding="utf-8"), case["path"], "eval")
        observed = {item.rule_id for item in findings}
        expected = set(case["expected_rules"])
        case_tp = len(observed & expected)
        case_fp = len(observed - expected)
        case_fn = len(expected - observed)
        tp += case_tp
        fp += case_fp
        fn += case_fn
        if not expected and not observed:
            tn += 1
        cases.append(
            {
                "case_id": case["case_id"],
                "expected": sorted(expected),
                "observed": sorted(observed),
                "passed": observed == expected,
            }
        )
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "cases": cases,
        "metrics": {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": precision,
            "recall": recall,
            "f1": f1,
        },
    }


def main() -> None:
    parser = argparse.ArgumentParser(prog="keynonce-guard")
    sub = parser.add_subparsers(dest="command", required=True)
    scan = sub.add_parser("scan")
    scan.add_argument("path", type=Path)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--corpus", type=Path, required=True)
    sub.add_parser("ai-harness")
    args = parser.parse_args()
    if args.command == "ai-harness":
        print(json.dumps(run_ai_contract_harness(), indent=2, ensure_ascii=False))
        return
    if args.command == "evaluate":
        print(json.dumps(evaluate_corpus(args.corpus), indent=2, ensure_ascii=False))
        return
    settings = Settings.from_env()
    store = EvidenceStore(settings.db_path)
    service = ScanService(settings, store)
    result = service.scan_sources(
        [SourceFile(args.path.name, args.path.read_text(encoding="utf-8"))]
    )
    print(
        json.dumps(
            {
                "summary": result.summary.model_dump(mode="json"),
                "findings": [f.model_dump(mode="json") for f in result.findings],
            },
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
