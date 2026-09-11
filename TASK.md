# TASK — KeyNonce Guard

Quy ước trạng thái: `[x]` đã hoàn tất và có kiểm chứng; `[~]` đã có khung nhưng chưa đủ bằng
chứng; `[ ]` chưa thực hiện. Mọi tuyên bố “đạt” phải trỏ được tới test/evidence, không dựa vào
đánh giá của LLM.

## Đã hoàn tất

- [x] FastAPI + Jinja2 web app và OpenAPI.
- [x] Upload guard cho `.py`/`.zip`: size, file count, traversal, symlink và nested archive.
- [x] AST analyzer với abstract provenance và 8 rule KN001–KN008.
- [x] Hỗ trợ API phổ biến của `cryptography`, PyCryptodome và Python standard library.
- [x] SQLite evidence store không lưu source/raw key/raw nonce.
- [x] SHA-256 evidence digest và parent-linked chain verifier.
- [x] Metadata JSONL detector xác nhận reuse cặp key/nonce đã HMAC fingerprint.
- [x] Dynamic harness chỉ chạy fixture allowlisted trong subprocess timeout/repeat budget.
- [x] Finding state machine phân biệt `static_suspicion`, `dynamic_confirmed`, `needs_review`,
  `fixed` và `not_fixed`.
- [x] Remediation loop: re-upload, re-scan và quyết định fixed theo rule xác định.
- [x] AI adapter tùy chọn, strict schema, evidence-ID validation, retry và deterministic fallback.
- [x] AI contract harness chống evidence giả, finding ID sai, CVE bịa, schema smuggling và thiếu
  citation.
- [x] Corpus 60 source cases: public-adapted có provenance/license và synthetic có family split.
- [x] Test suite 27 test; lint đạt; wheel build được và có packaged template/fixture resource.

## P0 — bắt buộc trước demo/hội đồng

- [ ] Chạy Docker Compose khi Docker daemon hoạt động; lưu log health/API và resource limits.
- [ ] Bổ sung blind review cho nhãn held-out; reviewer không xem output rule trước khi gán nhãn.
- [ ] Thêm repository-level benchmark trên 3–5 dự án Python được phép dùng.
- [ ] Thêm test matrix đầy đủ cho KN004/KN006 và cross-file/interprocedural edge cases.
- [ ] Xuất report JSON + HTML/PDF gồm config hash, corpus hash, tool version và run ID.
- [ ] Chạy AI harness với provider thật trên golden set; đo groundedness, latency, token/cost và
  fallback rate. Không gửi secret/source thô.
- [ ] Hoàn thiện traceability matrix Threat → SR → CR → Tool/Test → Evidence → Result → Residual
  Risk trong báo cáo cuối.

## P1 — tăng chất lượng kỹ thuật

- [ ] Dùng property-based testing cho nonce generation, restart và concurrency.
- [ ] Thêm interprocedural summaries cho wrapper tự viết quanh AEAD/RNG.
- [ ] Thêm SARIF export để tích hợp CI pre-production.
- [ ] Thêm key-lifecycle metadata schema: owner, purpose, activation, expiry, rotation, revocation.
- [ ] Ký evidence root hoặc export append-only để tăng khả năng phát hiện DB tampering.
- [ ] Thêm CVE enrichment offline snapshot; chỉ xác nhận khi component/version khớp affected range.
- [ ] Tăng branch coverage upload/AI failure paths; mục tiêu line coverage tối thiểu 85%.

## P2 — nghiên cứu tùy chọn, chỉ làm khi P0 đã đạt

- [ ] Xây feature set metadata: reuse distance, restart window, per-key nonce cardinality, source
  fan-out và burst rate.
- [ ] So sánh rule-only với hybrid rule + Isolation Forest/One-Class model trên split theo service.
- [ ] Chỉ cho ML tạo candidate `needs_review`; không được tự nâng thành confirmed.
- [ ] Ablation study: deterministic-only, deterministic+ML, deterministic+AI explanation.

## Không làm trong MVP

- Không thực thi source do người dùng tải lên.
- Không tự khai thác, rotate/revoke key hay thay đổi production.
- Không multi-agent swarm và không fine-tune LLM khi chưa có dataset gán nhãn đủ lớn.
- Không tuyên bố “secure” chỉ vì scanner không tìm thấy finding.

