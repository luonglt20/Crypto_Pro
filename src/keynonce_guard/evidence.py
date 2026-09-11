from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field


@dataclass
class Fingerprinter:
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32), repr=False)

    def fingerprint(self, domain: str, value: bytes) -> str:
        if domain not in {"key", "nonce", "source"}:
            raise ValueError("invalid fingerprint domain")
        digest = hmac.new(self.key, domain.encode() + b"\x00" + value, hashlib.sha256).hexdigest()
        return f"hmac-sha256:{digest}"
