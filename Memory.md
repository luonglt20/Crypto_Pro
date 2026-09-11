# Memory — Live Session Handoff

Đây là bộ nhớ vận hành của dự án dành cho session/người/AI tiếp theo. File phải trả lời được ngay:
đang làm gì, vừa làm gì, bằng chứng nào đã có, bước kế tiếp là gì và đang bị chặn ở đâu.

Không lưu token, credential, API key, raw key/nonce, `.env`, dữ liệu production hoặc source riêng
tư trong file này.

## 1. Bootstrap cho session mới

Làm đúng thứ tự sau trước khi sửa code:

1. Đọc file này để lấy trạng thái và `NEXT TASK`.
2. Đọc `TASK.md` để biết backlog/acceptance; không tự chọn P2 khi P0 còn mở.
3. Đọc `Context.md`, `Target.md`, `Architech.md` để giữ scope và trust boundary.
4. Chạy `git status --short --branch` và `git log -3 --oneline`.
5. Nếu worktree có thay đổi không phải do session hiện tại tạo ra, giữ nguyên và đánh giá trước khi
   chạm vào.
6. Chạy baseline test/lint. Nếu baseline khác phần “Verified state”, ghi rõ regression trước khi
   triển khai task mới.
7. Thực hiện đúng một task có thể kiểm chứng; cập nhật `TASK.md` và file này trước khi kết thúc.

## 2. Current session state

- Repository: `https://github.com/luonglt20/Crypto_Pro.git`.
- Default branch: `main`.
- Baseline implementation commit: `9bfe6bea0e780384f8ea3508369dad00db22ff99`.
- Prototype version: `0.1.0`; Python `>=3.12`.
- Phase: vertical slice đã chạy được; đang chuyển sang P0 release evidence.
- Current focus: tạo report artifact xác định, sau đó tăng test coverage/data-flow coverage.
- Không có migration/database production cần giữ; runtime SQLite nằm ngoài Git.

## 3. NEXT TASK — task mặc định cho session kế tiếp

<!-- CURRENT_TASK_ID: P0-RPT-01 -->

### P0-RPT-01: Deterministic report export

Mục tiêu: xuất một report tái lập từ scan/evidence, không dùng LLM làm nguồn dữ liệu.

Phạm vi triển khai:

- Thêm report service đọc `ScanSummary`, findings và evidence từ `EvidenceStore`.
- Xuất JSON machine-readable và HTML self-contained; PDF chỉ thêm nếu render tool có sẵn và được
  kiểm chứng layout.
- Report bắt buộc có: report/run ID, UTC timestamp, tool/analyzer version, config fingerprint,
  corpus/target digest, finding status, evidence IDs, integrity verdict và residual limitations.
- Thêm CLI `keynonce-guard report --scan-id ... --format json|html --output ...`.
- Thêm API tải report nhưng không để path traversal hoặc cho client chọn filesystem path.
- Thêm tests chứng minh report không chứa source, raw key/nonce hoặc AI-only unsupported claim.
- Chạy test, Ruff, corpus evaluator và AI contract harness sau thay đổi.

Acceptance:

- Cùng một snapshot scan/evidence cho cùng canonical payload và config fingerprint; timestamp/report
  ID được tách khỏi phần dùng để so reproducibility.
- Evidence integrity fail phải hiển thị `not_verified`, không được xuất kết luận confirmed im lặng.
- JSON và HTML chứa tất cả finding/evidence references; không chứa secret canary.
- `TASK.md` đánh dấu task hoàn tất và phần “Last completed work” bên dưới được cập nhật.

Không làm trong task này: gọi AI provider thật, ML, CVE lookup, chạy code upload hoặc redesign UI.

## 4. Last completed work

### Session handoff/docs — 2026-09-11

- Đưa prototype, corpus, tests và tài liệu lên GitHub `main`.
- Thêm `TASK.md`, `Memory.md`, `Architech.md`, `Target.md`, `Context.md`.
- Audit đường vào cho session mới: README trỏ thẳng tới handoff, `AGENTS.md` áp dụng contract cho
  toàn repo và regression test khóa sự đồng bộ của task ID.
- Upload proposal DOCX/PDF, course guideline, revised topic requirements và evidence JSON vào
  `docs/`.
- Secret scan trước commit không phát hiện GitHub/OpenAI token, private key hoặc API key thật.
- Remote `main` đã được đọc lại và khớp baseline commit `9bfe6bea...`.

### Prototype implementation — 2026-09-11

- FastAPI/Jinja2 app, upload guard, AST analyzer KN001–KN008.
- Metadata JSONL detector cho reuse key/nonce fingerprint.
- Allowlisted fixture harness, evidence chain verifier và deterministic state machine.
- Remediation re-test loop và optional AI explanation với deterministic fallback.
- 60-case public-adapted + synthetic corpus, family-aware split.

## 5. Verified state at handoff

| Gate | Observed result | Status |
|---|---|---|
| Unit/integration + handoff contract tests | 30 passed | verified |
| Ruff | `src`, `tests`, `scripts` passed | verified |
| Corpus evaluator | 60 cases; TP=46, FP=0, FN=0, TN=19 | verified on controlled corpus only |
| AI contract harness | 6/6; unsafe acceptance rate 0 | verified on defined cases only |
| API smoke | health 200; sample KN004 confirmed; integrity valid | verified in-process |
| Python wheel | built; template + fixture manifest included | verified |
| Line coverage | 77% | below target 85% |
| Docker Compose runtime | Docker daemon unavailable | not verified |
| Real repository benchmark | not run | not verified |
| Live AI provider eval | not configured/run | not verified |
| Blind held-out review | requires independent reviewer | not verified |

Không được diễn giải F1=1.0 trên corpus kiểm soát thành production accuracy hoặc generalization.

## 6. Open blockers and external inputs

- Docker verification cần Docker daemon hoạt động.
- Live AI evaluation cần provider/base URL/model/API credential được cấu hình ngoài Git.
- Blind label review cần một reviewer độc lập; AI không tự đóng vai reviewer để chứng minh nhãn.
- Repository benchmark chỉ dùng project có license/phạm vi cho phép; không tự scrape code tùy ý.

Nếu blocker chưa được giải quyết, chuyển sang task P0 khác không phụ thuộc blocker; không đánh dấu
blocked toàn dự án.

## 7. Architecture invariants — không được phá

1. Rule/test/oracle xác định là security authority; AI chỉ triage/explain.
2. Không import/exec source upload.
3. Dynamic code chỉ là fixture project-owned được allowlist, có timeout/repeat budget.
4. LLM không nhận raw source/secret và không đổi severity/confidence/status.
5. `dynamic_confirmed` chỉ từ deterministic positive evidence; negative control không confirm.
6. Remediation chỉ `fixed` khi đúng target path, parse thành công và rule gốc biến mất.
7. Expected corpus label không được sửa chỉ để làm metric đẹp; cần oracle/reviewer rationale.
8. Phải phân biệt `verified`, `partially verified`, `not verified`; file cấu hình không phải runtime
   proof.

## 8. Source-of-truth map

- `TASK.md`: backlog, priority và Definition of Done theo task.
- `Memory.md`: trạng thái live, next task, last completed work và blocker.
- `Architech.md`: component, data flow, trust boundary, AI workflow, state machine.
- `Target.md`: target metrics và release gate.
- `Context.md`: đề tài, threat model, scope và dataset strategy.
- `docs/`: proposal/reference inputs và point-in-time evidence.
- `src/keynonce_guard/`: implementation.
- `tests/`: executable regression proof.
- `corpus/source/manifest.json`: label/provenance/split source of truth.

Khi tài liệu xung đột: safety invariant trong `Architech.md`/`Context.md` thắng; trạng thái test mới
đo được thắng con số cũ; cập nhật lại `Memory.md` và `TASK.md` trong cùng commit.

## 9. Standard verification commands

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\ruff check src tests scripts
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m keynonce_guard.cli evaluate --corpus corpus/source
.\.venv\Scripts\python -m keynonce_guard.cli ai-harness
```

Sau thay đổi dependency/build, build wheel và kiểm tra package resource. Sau thay đổi rule/corpus,
chạy lại generator/evaluator và không overwrite evidence baseline nếu chưa ghi version/run metadata.

## 10. End-of-session protocol

Trước khi bàn giao session:

1. Cập nhật checkbox và evidence của task trong `TASK.md`.
2. Đổi `NEXT TASK` thành task cụ thể tiếp theo, có scope và acceptance rõ.
   Đồng thời cập nhật marker `CURRENT_TASK_ID` và entry tương ứng trong README/TASK.
3. Ghi công việc vừa hoàn tất vào `Last completed work`, kèm ngày/commit nếu đã push.
4. Cập nhật bảng `Verified state` bằng kết quả thực chạy; không copy số cũ nếu chưa chạy lại.
5. Ghi blocker mới và external input cần thiết.
6. Secret scan staged files, kiểm tra `git diff --check`, test/lint, rồi mới commit/push.
