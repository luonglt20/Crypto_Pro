from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, File, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from .ai import AIAdapter
from .config import Settings
from .harness import FixtureHarness, FixtureRejected
from .ingest import UploadRejected
from .retest import RetestRejected, RetestService
from .rules import public_rule_catalog
from .service import ScanService
from .storage import EvidenceStore
from .telemetry import TelemetryRejected, TelemetryScanService
from .verification import VerificationRejected, VerificationService


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    package_dir = Path(__file__).resolve().parent
    project_root = package_dir.parents[1]
    manifest_candidates = [
        Path.cwd() / "corpus" / "fixtures" / "manifest.json",
        project_root / "corpus" / "fixtures" / "manifest.json",
        package_dir / "resources" / "fixture_manifest.json",
    ]
    manifest_path = next((path for path in manifest_candidates if path.is_file()), None)
    if manifest_path is None:
        raise RuntimeError("fixture manifest not found")
    templates = Jinja2Templates(directory=package_dir / "templates")
    store = EvidenceStore(settings.db_path)
    service = ScanService(settings, store)
    harness = FixtureHarness(manifest_path)
    ai = AIAdapter(settings)
    verifier = VerificationService(store, harness)
    telemetry = TelemetryScanService(store)
    retest = RetestService(store, service)

    app = FastAPI(title="KeyNonce Guard", version="0.1.0")
    app.state.settings = settings
    app.state.store = store
    app.state.scan_service = service
    app.state.harness = harness
    app.state.ai = ai
    app.state.verifier = verifier
    app.state.telemetry = telemetry
    app.state.retest = retest

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "version": app.version}

    @app.get("/", response_class=HTMLResponse)
    def home(request: Request):
        return templates.TemplateResponse(
            request,
            "index.html",
            {"rules": public_rule_catalog(), "ai_enabled": settings.ai_enabled},
        )

    @app.post("/api/v1/scans", status_code=201)
    async def create_scan(file: UploadFile = File(...)) -> dict:  # noqa: B008
        content = await file.read(settings.max_upload_bytes + 1)
        try:
            result = service.scan_upload(file.filename or "upload", content)
        except UploadRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "summary": result.summary.model_dump(mode="json"),
            "findings": [item.model_dump(mode="json") for item in result.findings],
            "parse_errors": result.parse_errors,
        }

    @app.post("/api/v1/telemetry/scans", status_code=201)
    async def create_telemetry_scan(file: UploadFile = File(...)) -> dict:  # noqa: B008
        content = await file.read(20 * 1024 * 1024 + 1)
        try:
            result = telemetry.scan_jsonl(content, file.filename or "telemetry.jsonl")
        except TelemetryRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "summary": result.summary.model_dump(mode="json"),
            "event_count": result.event_count,
            "findings": [item.model_dump(mode="json") for item in result.findings],
        }

    @app.get("/api/v1/scans/{scan_id}")
    def get_scan(scan_id: str) -> dict:
        result = store.get_scan(scan_id)
        if not result:
            raise HTTPException(status_code=404, detail="Không tìm thấy scan")
        summary, findings = result
        return {"summary": summary, "findings": findings}

    @app.get("/api/v1/findings/{finding_id}")
    def get_finding(finding_id: str) -> dict:
        finding = store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Không tìm thấy finding")
        return {"finding": finding, "evidence": store.evidence_for_finding(finding_id)}

    @app.get("/api/v1/rules")
    def get_rules() -> list[dict[str, str | None]]:
        return public_rule_catalog()

    @app.post("/api/v1/fixtures/runs")
    def run_fixture(payload: dict[str, object]) -> dict:
        fixture_id = str(payload.get("fixture_id", ""))
        repeats = int(payload.get("repeats", 3))
        try:
            result = harness.run(fixture_id, repeats=repeats)
        except (FixtureRejected, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        store.save_test_run(result["test_run_id"], fixture_id, result["status"], result)
        return result

    @app.post("/api/v1/findings/{finding_id}/verify")
    def verify_finding(finding_id: str, payload: dict[str, object]) -> dict:
        try:
            return verifier.verify_finding(
                finding_id,
                str(payload.get("fixture_id", "")),
                int(payload.get("repeats", 3)),
            )
        except (VerificationRejected, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post("/api/v1/findings/{finding_id}/retest")
    async def retest_finding(
        finding_id: str,
        file: UploadFile = File(...),  # noqa: B008
    ) -> dict:
        content = await file.read(settings.max_upload_bytes + 1)
        try:
            return retest.retest_upload(finding_id, file.filename or "upload", content)
        except (RetestRejected, UploadRejected, ValueError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.get("/api/v1/evidence/integrity")
    def evidence_integrity() -> dict[str, object]:
        return store.verify_evidence_integrity()

    @app.post("/api/v1/findings/{finding_id}/explain")
    async def explain_finding(finding_id: str) -> dict:
        finding = store.get_finding(finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Không tìm thấy finding")
        evidence = store.evidence_for_finding(finding_id)
        result = await ai.explain(finding, evidence)
        store.save_ai_explanation(
            finding_id, result.explanation.model_dump_json(), result.validated
        )
        return {
            "provider": result.provider,
            "validated": result.validated,
            "fallback_reason": result.fallback_reason,
            "explanation": result.explanation,
        }

    return app


app = create_app()


def main() -> None:
    import uvicorn

    uvicorn.run("keynonce_guard.app:app", host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()
