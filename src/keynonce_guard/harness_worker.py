from __future__ import annotations

import hashlib
import hmac
import json
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def _fp(domain: str, value: bytes) -> str:
    key = bytes.fromhex(os.environ["KEYNONCE_MONITOR_KEY"])
    return hmac.new(key, domain.encode() + b"\x00" + value, hashlib.sha256).hexdigest()


def nonce_reuse_aesgcm() -> dict:
    key = AESGCM.generate_key(bit_length=128)
    nonce = b"\x01" * 12
    cipher = AESGCM(key)
    events = []
    for sequence, plaintext in enumerate((b"one", b"two"), start=1):
        cipher.encrypt(nonce, plaintext, b"fixture")
        events.append(
            {
                "sequence": sequence,
                "operation": "encrypt",
                "algorithm_profile": "AES-GCM-128",
                "key_fingerprint": _fp("key", key),
                "nonce_fingerprint": _fp("nonce", nonce),
                "result": "success",
            }
        )
    duplicate = len({(e["key_fingerprint"], e["nonce_fingerprint"]) for e in events}) < len(events)
    return {
        "fixture_id": "nonce_reuse_aesgcm",
        "events": events,
        "oracle": {"duplicate_pair": duplicate},
        "passed": duplicate,
    }


def aead_tag_tamper() -> dict:
    key = AESGCM.generate_key(bit_length=128)
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ciphertext = bytearray(cipher.encrypt(nonce, b"secret", b"aad"))
    ciphertext[-1] ^= 1
    rejected = False
    try:
        cipher.decrypt(nonce, bytes(ciphertext), b"aad")
    except InvalidTag:
        rejected = True
    return {
        "fixture_id": "aead_tag_tamper",
        "events": [
            {
                "operation": "decrypt",
                "algorithm_profile": "AES-GCM-128",
                "result": "invalid_tag" if rejected else "accepted",
            }
        ],
        "oracle": {"tamper_rejected": rejected},
        "passed": rejected,
    }


def counter_reset() -> dict:
    key = AESGCM.generate_key(bit_length=128)
    nonces = [(0).to_bytes(12, "big"), (1).to_bytes(12, "big"), (0).to_bytes(12, "big")]
    events = [
        {
            "sequence": i + 1,
            "boot_id": "boot-1" if i < 2 else "boot-2",
            "algorithm_profile": "AES-GCM-128",
            "key_fingerprint": _fp("key", key),
            "nonce_fingerprint": _fp("nonce", nonce),
            "operation": "encrypt",
        }
        for i, nonce in enumerate(nonces)
    ]
    reset = events[0]["nonce_fingerprint"] == events[2]["nonce_fingerprint"]
    return {
        "fixture_id": "counter_reset",
        "events": events,
        "oracle": {"restart_duplicate": reset},
        "passed": reset,
    }


HANDLERS = {
    "nonce_reuse_aesgcm": nonce_reuse_aesgcm,
    "aead_tag_tamper": aead_tag_tamper,
    "counter_reset": counter_reset,
}


def main() -> int:
    if len(sys.argv) != 2 or sys.argv[1] not in HANDLERS:
        return 2
    print(json.dumps(HANDLERS[sys.argv[1]](), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
