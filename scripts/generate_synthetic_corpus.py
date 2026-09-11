from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).parents[1]
CORPUS = ROOT / "corpus" / "source"
GENERATED = CORPUS / "generated"


def add_case(
    cases: list[dict[str, object]],
    index: int,
    family: str,
    source: str,
    expected: list[str],
    split: str,
) -> None:
    case_id = f"GEN-{family}-{index:02d}"
    relative = f"generated/{case_id.lower()}.py"
    (CORPUS / relative).write_text(source.strip() + "\n", encoding="utf-8")
    cases.append(
        {
            "case_id": case_id,
            "path": relative,
            "origin_type": "synthetic_generated",
            "license": "project-owned",
            "family_id": family,
            "split": split,
            "label_quality": "deterministic_oracle",
            "expected_rules": expected,
        }
    )


def main() -> None:
    GENERATED.mkdir(parents=True, exist_ok=True)
    manifest_path = CORPUS / "manifest.json"
    document = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases = [item for item in document["cases"] if not item["case_id"].startswith("GEN-")]

    for index in range(1, 6):
        add_case(
            cases,
            index,
            "KN001-LITERAL",
            f"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = b'{index:016d}'
def encrypt(data, nonce):
    return AESGCM(key).encrypt(nonce, data, None)
""",
            ["KN001", "KN006"],
            "development",
        )
        add_case(
            cases,
            index,
            "KN002-WEAK-RNG",
            """
import random
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data, nonce):
    key = random.randbytes(16)
    return AESGCM(key).encrypt(nonce, data, None)
""",
            ["KN002"],
            "heldout",
        )
        add_case(
            cases,
            index,
            "KN003-FIXED-NONCE",
            f"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    nonce = b'{index:012d}'
    return AESGCM(key).encrypt(nonce, data, None)
""",
            ["KN003"],
            "development",
        )
        add_case(
            cases,
            index,
            "KN005-NO-TAG",
            """
from Crypto.Cipher import AES
def decrypt(key, nonce, ciphertext):
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt(ciphertext)
""",
            ["KN005"],
            "heldout",
        )
        add_case(
            cases,
            index,
            "KN007-FIXED-K",
            f"""
def sign(signer, digest):
    return signer.sign(digest, k={index})
""",
            ["KN007"],
            "development",
        )
        add_case(
            cases,
            index,
            "KN008-SHORT-NONCE",
            f"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    return AESGCM(key).encrypt(os.urandom({6 + index}), data, None)
""",
            ["KN008"],
            "heldout",
        )
        add_case(
            cases,
            index,
            "SAFE-AESGCM",
            """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    return AESGCM(key).encrypt(os.urandom(12), data, None)
""",
            [],
            "heldout",
        )

    for index in range(6, 11):
        add_case(
            cases,
            index,
            "SAFE-PYCRYPTODOME",
            """
from Crypto.Cipher import AES
def encrypt(key, data):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag
""",
            [],
            "development",
        )
        add_case(
            cases,
            index,
            "SAFE-GENERATED-KEY",
            """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    key = AESGCM.generate_key(bit_length=128)
    return AESGCM(key).encrypt(os.urandom(12), data, None)
""",
            [],
            "development",
        )

    document["cases"] = cases
    document["generated_by"] = "scripts/generate_synthetic_corpus.py"
    document["case_count"] = len(cases)
    manifest_path.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
