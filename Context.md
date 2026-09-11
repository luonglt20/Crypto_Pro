# Context — Course, Threat Model and Constraints

## Đề tài

**Agentic AI for Key/Nonce Security Assurance, Vulnerability Classification and Threat Hunting**.

Đây là đề tài môn Cryptography and Applications, không phải luận văn hoặc sản phẩm production.
Prototype phải kết hợp cryptanalysis reasoning, coding và automated validation, nhưng mọi kết luận
phải evidence-grounded.

## Vấn đề

Các lỗi hard-coded key, weak RNG, nonce reuse, AEAD tag bypass, signature ephemeral nonce và key
lifecycle thường nằm ở nhiều lớp: code, config, runtime behavior và operational metadata. Scanner
tĩnh đơn thuần dễ bỏ sót context; LLM đơn thuần lại có thể hallucinate. Dự án dùng kiến trúc hybrid
có verifier để tận dụng khả năng giải thích của AI mà không giao quyền kết luận cho AI.

## Attacker model

- Có thể đưa file/ZIP, filename, comment/string và telemetry độc hại vào hệ thống.
- Có thể chèn prompt injection trong nội dung được phân tích.
- Có thể gây archive traversal, decompression bomb hoặc resource exhaustion.
- Có thể tạo code wrapper/alias nhằm né rule.
- Không giả định attacker có quyền administrator trên host; nếu có, SQLite chain không đủ bảo vệ.

## Assets

- Source và metadata người dùng cung cấp.
- Key/nonce confidentiality và correlation metadata.
- Tính đúng của finding/status/severity/confidence.
- Evidence integrity, reproducibility và dataset labels.
- AI/API credential nếu người vận hành cấu hình ngoài repo.

## Ràng buộc an toàn

- Không commit `.env`, API key, database runtime, source riêng tư hoặc raw secret.
- Không thực thi code upload; chỉ fixture do dự án quản lý mới chạy.
- AI payload đã loại path/source/raw secret; output bị schema/evidence verifier kiểm soát.
- Public data chỉ dùng khi license/provenance rõ; synthetic data phải được đánh dấu.
- `No finding` không đồng nghĩa `secure`; `dynamic_confirmed` chỉ đúng trong evidence scope.

## Dataset strategy

1. Public-adapted: ví dụ/documentation chính thức của pyca/cryptography và PyCryptodome, lưu URL và
   license.
2. Synthetic: positive, negative và ambiguous variants do generator cố định tạo ra.
3. Split theo `family_id`, không random từng file, để giảm leakage từ biến thể gần trùng.
4. Held-out phải freeze trước final run; thay label cần reviewer rationale.
5. Sau MVP, thêm repository thực tế được cấp phép và metadata lab có restart/concurrency.

## Định hướng AI hay crypto

Ưu tiên crypto correctness, static/dynamic testing, corpus và evidence. Không fine-tune hoặc xây
multi-agent swarm trong giai đoạn đầu. AI chỉ nên được đầu tư ở structured triage, grounded
explanation và remediation summary; accuracy security được tăng chủ yếu bằng data-flow analysis,
oracles, better labels và independent validation.

## Tài liệu định hướng

- NIST SP 800-38D: GCM/GMAC.
- NIST SP 800-57 Part 1: key management.
- NIST SP 800-90 series và SP 800-133: RNG/entropy/key generation.
- RFC 5116: AEAD interface/nonce requirements.
- RFC 6979: deterministic DSA/ECDSA nonce.
- API documentation của Python, `cryptography` và PyCryptodome.

