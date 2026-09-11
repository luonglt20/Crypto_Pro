# Memory — Project Handoff

File này lưu quyết định bền vững để người/agent tiếp theo tiếp tục đúng hướng. Không ghi secret,
token, credential, raw key, raw nonce hoặc nội dung source riêng tư.

## Trạng thái được kiểm chứng gần nhất

- Prototype version: `0.1.0`.
- Python mục tiêu: `>=3.12`.
- Test: 27 passed.
- Ruff: passed cho `src`, `tests`, `scripts`.
- Line coverage quan sát: 77%; chưa đạt target 85%.
- Corpus: 60 cases; TP=46, FP=0, FN=0, TN=19 trên corpus kiểm soát.
- AI contract harness: 6/6 cases passed; unsafe acceptance rate 0 trên case đã định nghĩa.
- API smoke: `/health` trả 200; telemetry sample tạo 1 KN004 `dynamic_confirmed`; evidence
  integrity trả `valid=true`.
- Wheel build thành công và chứa `templates/index.html` cùng packaged fixture manifest.
- Docker runtime: **not verified** vì Docker daemon không hoạt động tại lần kiểm chứng.

Các metric corpus ở trên chỉ chứng minh regression nội bộ, không đại diện accuracy ngoài thực tế.

## Quyết định kiến trúc đã chốt

1. Crypto/evidence-first, AI-second.
2. Hybrid có thứ bậc: deterministic rule/oracle là security authority; ML tùy chọn chỉ tạo
   candidate; một LLM chỉ giải thích/triage; deterministic verifier + human gate quyết định release.
3. Source upload chỉ parse AST, tuyệt đối không import/exec.
4. Dynamic validation chỉ chạy fixture do dự án sở hữu và được allowlist.
5. LLM không nhận raw source/secret và không được đổi severity/confidence/status.
6. `dynamically_confirmed` chỉ đến từ telemetry duplicate có schema hoặc positive fixture oracle;
   negative control không được xác nhận lỗ hổng.
7. Remediation chỉ `fixed` khi đúng path, parse thành công và rule gốc biến mất.
8. Public-derived dataset phải có URL và license; synthetic variants phải có family split để giảm
   leakage.

## Lệnh chuẩn

```powershell
python -m venv .venv
.\.venv\Scripts\python -m pip install -e ".[dev]"
.\.venv\Scripts\python -m pytest -q
.\.venv\Scripts\ruff check src tests scripts
.\.venv\Scripts\python -m keynonce_guard.cli evaluate --corpus corpus/source
.\.venv\Scripts\python -m keynonce_guard.cli ai-harness
.\.venv\Scripts\python -m keynonce_guard.app
```

## Khi tiếp tục

- Đọc `Context.md`, `Target.md`, `Architech.md`, rồi lấy P0 đầu tiên trong `TASK.md`.
- Sau mọi thay đổi rule, chạy generator, corpus evaluation, test và lint.
- Không chỉnh expected labels chỉ để làm metric đẹp; thay đổi nhãn phải có oracle/reviewer rationale.
- Báo rõ `verified`, `partially verified`, `not verified`; code/config không phải runtime proof.

