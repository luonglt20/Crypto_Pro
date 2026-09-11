# KeyNonce Guard

Prototype phục vụ đề tài **Agentic AI for Key/Nonce Security Assurance, Vulnerability
Classification and Threat Hunting**. Kết luận bảo mật đến từ rule, oracle và test xác định;
AI chỉ giải thích evidence đã được làm sạch.

## Tài liệu dự án

- [Proposal, guideline, revised requirements và evidence](docs/README.md)
- [Danh sách công việc và phần chưa làm](TASK.md)
- [Kiến trúc và trust boundaries](Architech.md)
- [Definition of Done](Target.md)
- [Bối cảnh, threat model và dataset strategy](Context.md)
- [Project handoff memory](Memory.md)

## Chạy local

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m keynonce_guard.app
```

Mở `http://127.0.0.1:8000`.

## Chạy Docker

```powershell
docker compose up --build
```

## Kiểm thử

```powershell
pytest -q
python -m keynonce_guard.cli evaluate --corpus corpus/source
python -m keynonce_guard.cli ai-harness
```

Corpus hiện gồm 60 ca: mẫu public-adapted từ tài liệu chính thức của `cryptography` và
PyCryptodome (có URL/license trong manifest), cùng mẫu synthetic do dự án sở hữu. Các biến
thể synthetic được tạo tái lập bằng `scripts/generate_synthetic_corpus.py`; mọi biến thể cùng
`family_id` nằm trong một split để giảm leakage.

Threat-hunting metadata-only dùng JSONL chỉ chứa HMAC fingerprint, không nhận raw key/nonce:

```powershell
curl.exe -F "file=@corpus/telemetry/synthetic_nonce_reuse.jsonl" `
  http://127.0.0.1:8000/api/v1/telemetry/scans
```

## Ranh giới an toàn

- Chỉ parse mã Python; không import hoặc thực thi file người dùng tải lên.
- Dynamic harness chỉ chạy fixture được liệt kê trong `corpus/fixtures/manifest.json`.
- Source, key, nonce và secret không được lưu trong SQLite hoặc gửi tới AI.
- AI không có shell, URL hoặc file tool tùy ý và không thể thay đổi trạng thái finding.
- Remediation loop chỉ gắn `fixed` khi cùng target path parse thành công và rule gốc biến mất;
  sai tên file hoặc parse error luôn chuyển sang `needs_review`.
- CVE chỉ được xác nhận khi component và version khớp affected range; MVP hiện chỉ cung cấp
  CWE mapping xác định và để CVE enrichment ở trạng thái chưa kích hoạt.
