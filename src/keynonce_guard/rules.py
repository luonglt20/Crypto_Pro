from __future__ import annotations

from dataclasses import dataclass

from .models import Confidence, FindingStatus, Severity


@dataclass(frozen=True)
class RuleDefinition:
    rule_id: str
    category: str
    title_vi: str
    cwe_id: str | None
    severity: Severity
    confidence: Confidence
    default_status: FindingStatus
    recommendation: str


RULES: dict[str, RuleDefinition] = {
    "KN001": RuleDefinition(
        "KN001",
        "hardcoded_key",
        "Khóa mật mã được hard-code",
        "CWE-321",
        Severity.HIGH,
        Confidence.HIGH,
        FindingStatus.STATIC_SUSPICION,
        "Sinh khóa bằng API mật mã phù hợp hoặc lấy từ secret/KMS có kiểm soát.",
    ),
    "KN002": RuleDefinition(
        "KN002",
        "weak_rng",
        "Nguồn ngẫu nhiên không phù hợp",
        "CWE-338",
        Severity.HIGH,
        Confidence.HIGH,
        FindingStatus.STATIC_SUSPICION,
        "Dùng secrets, os.urandom hoặc API generate_key của thư viện mật mã.",
    ),
    "KN003": RuleDefinition(
        "KN003",
        "fixed_nonce",
        "Nonce hoặc IV cố định",
        "CWE-323",
        Severity.CRITICAL,
        Confidence.HIGH,
        FindingStatus.STATIC_SUSPICION,
        "Tạo nonce duy nhất cho mỗi lần mã hóa dưới cùng khóa.",
    ),
    "KN004": RuleDefinition(
        "KN004",
        "nonce_reuse",
        "Tái sử dụng cặp key và nonce",
        "CWE-323",
        Severity.CRITICAL,
        Confidence.HIGH,
        FindingStatus.DYNAMIC_CONFIRMED,
        "Duy trì trạng thái nonce theo khóa và kiểm tra restart/concurrency.",
    ),
    "KN005": RuleDefinition(
        "KN005",
        "aead_tag_bypass",
        "Bỏ qua xác minh AEAD tag",
        "CWE-325",
        Severity.CRITICAL,
        Confidence.HIGH,
        FindingStatus.STATIC_SUSPICION,
        "Dùng decrypt_and_verify hoặc kết thúc xử lý khi InvalidTag/ValueError xảy ra.",
    ),
    "KN006": RuleDefinition(
        "KN006",
        "unsafe_lifecycle",
        "Vòng đời hoặc mục đích khóa chưa rõ",
        "CWE-324",
        Severity.MEDIUM,
        Confidence.LOW,
        FindingStatus.NEEDS_REVIEW,
        "Khai báo owner, purpose, activation, expiration, rotation và revocation cho khóa.",
    ),
    "KN007": RuleDefinition(
        "KN007",
        "signature_nonce",
        "Ephemeral signature nonce không an toàn",
        "CWE-338",
        Severity.CRITICAL,
        Confidence.MEDIUM,
        FindingStatus.NEEDS_REVIEW,
        "Không truyền k cố định hoặc weak randfunc; ưu tiên API chữ ký được thư viện quản lý nonce.",
    ),
    "KN008": RuleDefinition(
        "KN008",
        "nonce_policy",
        "Nonce lệch algorithm profile",
        "CWE-323",
        Severity.MEDIUM,
        Confidence.MEDIUM,
        FindingStatus.STATIC_SUSPICION,
        "Tuân thủ độ dài và construction nonce của algorithm profile được chọn.",
    ),
}


def public_rule_catalog() -> list[dict[str, str | None]]:
    return [
        {
            "rule_id": r.rule_id,
            "category": r.category,
            "title": r.title_vi,
            "cwe_id": r.cwe_id,
            "severity": r.severity.value,
            "default_status": r.default_status.value,
        }
        for r in RULES.values()
    ]
