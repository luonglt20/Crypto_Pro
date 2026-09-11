# Architecture — KeyNonce Guard

> Tên file giữ theo yêu cầu dự án. Nội dung mô tả kiến trúc version 0.1.0.

## Nguyên tắc

- Deterministic-first: rule/test/oracle là nguồn kết luận bảo mật.
- Evidence-grounded: finding phải có rule ID, vị trí, reason code, tool version và digest.
- Least authority: AI không có shell, URL tùy ý, filesystem hoặc quyền thay đổi finding.
- Safe pre-production: source upload không được thực thi; fixture runtime là mã dự án allowlisted.
- Fail closed: schema sai, evidence ID lạ, output AI không hợp lệ hoặc budget vượt giới hạn đều bị
  từ chối/fallback.

## Component view

```text
Browser / API client
        │
        v
 FastAPI + upload/schema guard
        │
        ├── .py/.zip ──> AST analyzer ───────────────┐
        │                                            │
        ├── JSONL ──> HMAC metadata correlator ─────┤
        │                                            v
        ├── fixture request ─> allowlist ─> subprocess oracle
        │                                            │
        └── remediation source ─> deterministic re-scan
                                                     │
                                                     v
                                      SQLite finding/evidence store
                                                     │
                            ┌────────────────────────┴──────────────┐
                            v                                       v
                  digest-chain verifier                    redacted AI adapter
                                                                    │
                                                          strict output validator
                                                                    │
                                                     explanation or fallback
```

## Trust boundaries

| Boundary | Untrusted input | Control |
|---|---|---|
| Upload | Filename, Python, ZIP | size/count/path/symlink/nested archive checks; UTF-8; AST only |
| Telemetry | JSONL metadata | Pydantic extra-forbid; raw secret field denylist; HMAC format |
| Fixture | API fixture ID/repeat | manifest allowlist; 1–3 repeats; timeout; minimal env |
| AI | Provider output | strict schema; finding/evidence ID binding; CVE assertion reject; fallback |
| Storage | DB content | per-record SHA-256 and parent link verification |

## Technical workflow

```text
ingest → normalize path → parse AST → resolve aliases → propagate abstract provenance
→ fire rule → persist finding → create evidence digest → optional verify/retest → final status
```

Abstract provenance lattice hiện dùng: `unknown`, `literal`, `constant`, `secure_random`,
`weak_random`, `time_derived`, `counter`, `external`, `derived`.

## AI workflow

```text
finding + redacted evidence IDs
        → prompt boundary: content is data
        → one LLM call, temperature 0, JSON-only
        → schema validator
        → finding ID/evidence ID/CVE checks
        ├── pass: store explanation separately
        └── fail: retry once, then deterministic fallback
```

AI không tạo finding, không xác nhận vulnerability, không sửa code và không quyết định release.
Agent loop guard giới hạn tool allowlist, arguments, evidence reference, số bước, test budget và
phát hiện action lặp.

## Verification state machine

```text
static_suspicion ──positive deterministic oracle──> dynamic_confirmed
        │
        ├── insufficient/mismatched evidence ─────> needs_review
        └── remediation upload ────────────────────> retest_pending
                                                       ├── same rule remains → not_fixed
                                                       ├── rule absent + valid target → fixed
                                                       └── missing target/parse error → needs_review
```

## Data model tối thiểu

- `ScanSummary`: scan ID, analyzer version, file/finding count, elapsed time.
- `Finding`: rule/version, CWE, severity, confidence, status, location, structured evidence.
- `EvidenceRecord`: run/tool/rule, target digest, observed facts, parent/record digest.
- `TestRun`: fixture ID, repeat outputs, reproducibility, oracle status.
- `AIExplanation`: finding ID, evidence IDs, summary, risk, recommendation, limitations.

## Giới hạn kiến trúc

- AST nội hàm chưa giải quyết reflection và interprocedural flow sâu.
- SQLite chain không chống attacker có toàn quyền sửa DB và tính lại toàn bộ chain.
- KN004 xác nhận duplicate trên dữ liệu đã cung cấp, không chứng minh production exploit.
- Không có ML trong 0.1.0; đây là chủ đích cho MVP crypto-first.

