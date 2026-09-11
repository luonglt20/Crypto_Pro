# KeyNonce Guard — Implementation Handoff

## Kết quả hiện tại

Prototype đã triển khai một vertical slice chạy được cho đề tài **Agentic AI for Key/Nonce
Security Assurance, Vulnerability Classification and Threat Hunting**. Nguồn kết luận bảo mật
là AST rule, telemetry correlation, fixture oracle và evidence verifier; AI không được quyền đổi
severity, confidence hoặc trạng thái finding.

## Kiến trúc đã triển khai

```text
.py/.zip ──> upload guard ──> Python AST + provenance ──> finding + evidence
                                                        │
JSONL HMAC metadata ──> schema guard ──> correlation ───┤
                                                        v
                                              SQLite evidence chain
                                                        │
                         allowlisted fixture <── verifier/agent guard
                                                        │
                                                        v
                                        deterministic state transition
                                                        │
                                      optional AI explanation + validator
```

- FastAPI + Jinja2, không dùng SPA.
- Không import hoặc thực thi source do người dùng tải lên.
- Dynamic harness chỉ gọi ba fixture được allowlist, trong subprocess có timeout, môi trường tối
  thiểu và giới hạn ba lần lặp.
- Evidence không lưu source hoặc raw key/nonce; chỉ lưu SHA-256/HMAC fingerprint, vị trí, rule,
  reason code và kết quả test.
- AI adapter tương thích OpenAI API, temperature 0, JSON schema nghiêm ngặt, retry một lần và
  deterministic fallback.
- AI contract harness kiểm tra wrong finding ID, evidence giả, CVE bịa, schema smuggling và thiếu
  citation.

## Rule và cơ chế xác minh

| Rule | Nội dung | Nguồn evidence | Trạng thái ban đầu |
|---|---|---|---|
| KN001 | Hard-coded key | AST + provenance | static_suspicion |
| KN002 | Weak RNG cho key/nonce | AST + call resolution | static_suspicion |
| KN003 | Nonce/IV cố định hoặc loop-invariant | AST + loop context | static_suspicion |
| KN004 | Lặp cặp key-fingerprint/nonce-fingerprint | JSONL correlation | dynamically_confirmed |
| KN005 | Decrypt không verify hoặc auth failure tiếp tục | AST state tracking | static_suspicion |
| KN006 | Key module-level hoặc multi-purpose | scope/purpose tracking | needs_review |
| KN007 | Signature nonce/randfunc không an toàn | AST call inspection | needs_review |
| KN008 | Nonce lệch profile 96-bit | abstract byte length | static_suspicion |

State transition được kiểm soát bằng code. Negative control không thể nâng finding lên
`dynamic_confirmed`. Remediation loop chỉ gắn `fixed` nếu đúng target path, parse thành công và
rule gốc biến mất; nếu rule còn thì `not_fixed`, còn target thiếu/parse lỗi thì `needs_review`.

## Dataset và đánh giá

- 60 source cases: 4 public-adapted có URL/license và 56 mẫu synthetic/khởi tạo do dự án sở hữu.
- Các biến thể generated có `family_id` và cùng family chỉ nằm trong một split để giảm leakage.
- Một JSONL threat-hunting scenario mô phỏng service restart làm reuse nonce; chỉ dùng HMAC
  fingerprint.
- Kết quả hiện tại trên corpus kiểm soát: TP=46, FP=0, FN=0, TN=19; precision=recall=F1=1.0.
  Đây là test nội bộ của corpus nhỏ, không phải tuyên bố accuracy ngoài thực tế.
- AI contract harness: 6/6 case đạt, unsafe acceptance rate bằng 0 trên các case đã định nghĩa.
- Test suite: 26 test đạt; line coverage hiện tại 77%.

## Chạy demo

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\python -m keynonce_guard.cli evaluate --corpus corpus/source
.\.venv\Scripts\python -m keynonce_guard.cli ai-harness
.\.venv\Scripts\python -m keynonce_guard.app
```

Mở `http://127.0.0.1:8000`. OpenAPI ở `http://127.0.0.1:8000/docs`.

## API chính

- `POST /api/v1/scans`: scan `.py` hoặc `.zip`.
- `POST /api/v1/telemetry/scans`: scan metadata JSONL đã fingerprint.
- `GET /api/v1/findings/{id}`: finding và evidence.
- `POST /api/v1/findings/{id}/verify`: chạy fixture allowlisted phù hợp rule.
- `POST /api/v1/findings/{id}/retest`: re-scan bản remediation.
- `POST /api/v1/findings/{id}/explain`: AI explanation hoặc fallback.
- `GET /api/v1/evidence/integrity`: kiểm tra digest và chain linkage.

## Gate chưa hoàn tất

- Dockerfile và Compose đã có nhưng Docker Desktop không chạy tại lúc kiểm chứng, vì vậy container
  runtime là **not verified**.
- Chưa benchmark trên repository thực tế quy mô lớn hoặc corpus độc lập do người khác gán nhãn.
- Chưa fine-tune hay dùng ML. Đây là chủ đích: thời lượng 6–8 tuần nên ưu tiên crypto correctness,
  evidence và false-positive control; ML chỉ nên thêm sau khi có đủ telemetry được gán nhãn.
- SQLite hash chain phát hiện sửa đổi ngẫu nhiên nhưng không chống local administrator có toàn quyền.
- Static analysis chưa hỗ trợ reflection, wrapper phức tạp hoặc interprocedural data flow sâu.

## Hướng triển khai tiếp theo

1. Tuần 1–2: reviewer gán nhãn blind cho held-out/public cases; mở rộng wrapper và alias cases.
2. Tuần 3: thêm property-based tests cho nonce generation và concurrency/restart.
3. Tuần 4: thêm signed evidence root hoặc append-only export; tăng coverage các nhánh upload lỗi.
4. Tuần 5: chạy benchmark trên 3–5 repository Python được cấp phép và ghi hardware/runtime.
5. Tuần 6: chạy AI harness với provider thật, chấm groundedness bằng reviewer và cost/latency.
6. Tuần 7: triển khai một optional anomaly model trên feature metadata, so sánh rule-only với hybrid.
7. Tuần 8: freeze corpus, chạy held-out một lần, hoàn thiện traceability và demo.

Không nên làm multi-agent swarm hoặc fine-tuning trong MVP. Kiến trúc phù hợp nhất là hybrid có
thứ bậc: deterministic rules/oracles là security authority; optional statistical model chỉ tạo
candidate; một LLM duy nhất chỉ triage/explain; deterministic verifier và human gate quyết định
release.
