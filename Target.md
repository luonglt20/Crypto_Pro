# Target — Definition of Done

## Mục tiêu sản phẩm

Xây một Python web prototype giúp phát hiện, xác minh có giới hạn và giải thích lỗi quản lý
key/nonce trong môi trường pre-production. Hệ thống phải tạo evidence tái lập; AI chỉ là trợ lý
phân tích, không phải security oracle.

## Đối tượng và phạm vi

- Người dùng: sinh viên/người review AppSec và giảng viên đánh giá đề tài.
- Ngôn ngữ MVP: Python.
- Thư viện ưu tiên: `cryptography`, PyCryptodome, `secrets`, `os.urandom`, `random`.
- Input: `.py`, `.zip`, metadata-only JSONL và fixture ID allowlisted.
- Deployment mục tiêu: local/Docker, pre-production, nhóm nhỏ trong 6–8 tuần.

## Success criteria

| ID | Tiêu chí | Target | Evidence |
|---|---|---:|---|
| T01 | Corpus có public + synthetic provenance | >=60 cases | manifest + source/license |
| T02 | Precision held-out | >=0.85 | frozen evaluator output |
| T03 | Recall held-out | >=0.80 | frozen evaluator output |
| T04 | False-positive rate trên safe/ambiguous | <=0.15 | confusion matrix |
| T05 | Reproducible fixture result | 100% qua 3 runs | test-run JSON |
| T06 | AI evidence-ID coverage | 100% | AI harness report |
| T07 | Unsupported AI security claims | 0 accepted | validator/adversarial tests |
| T08 | Secret canary xuất hiện trong DB/prompt/log | 0 | privacy test |
| T09 | Test line coverage | >=85% | coverage report |
| T10 | Analyze 200 Python files/5 MiB | <=10 s trên máy công bố | benchmark report |
| T11 | Critical requirement có test/evidence | 100% | traceability matrix |

T02–T04 chỉ được báo cáo chính thức trên held-out frozen set sau blind labeling; metric development
không được dùng làm final claim.

## Functional acceptance

- Finding trả `rule_id`, category, severity, confidence, status, location, evidence và remediation.
- Phân biệt rõ suspicion/confirmed/review và không cho AI thay đổi các trường này.
- Dynamic runtime không chạy source upload.
- Khi AI/API lỗi, scanner và report rule-based vẫn đầy đủ.
- Có remediation re-test và evidence integrity endpoint.
- Có threat-hunting scenario nonce reuse từ metadata không giải mã payload.

## Non-goals

- Không chứng nhận hệ thống production an toàn.
- Không thu thập/sinh key thật cho người dùng.
- Không exploit, active response hoặc tự động sửa/rotate secret.
- Không hỗ trợ mọi ngôn ngữ/thư viện crypto trong MVP.
- Không dùng entropy test thống kê để “chứng nhận CSPRNG”.

## Release gate

Release demo chỉ được gọi là ready khi toàn bộ P0 trong `TASK.md` hoàn tất hoặc được ghi rõ waiver,
test/lint/build pass, evidence integrity valid, không có secret trong artifact và residual risks xuất
hiện trong report. Human reviewer là người duyệt cuối.

