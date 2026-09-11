from __future__ import annotations

from keynonce_guard.analyzer import CryptoAnalyzer


def rule_ids(source: str) -> set[str]:
    return {item.rule_id for item in CryptoAnalyzer().analyze(source, "sample.py", "scan")}


def test_hardcoded_key_is_detected() -> None:
    source = """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    material = b'0123456789abcdef'
    return AESGCM(material).encrypt(os.urandom(12), data, None)
"""
    assert "KN001" in rule_ids(source)


def test_alias_and_weak_random_are_traced() -> None:
    source = """
import os
import random as rng
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as AG
def encrypt(data):
    material = rng.randbytes(16)
    return AG(material).encrypt(os.urandom(12), data, None)
"""
    assert "KN002" in rule_ids(source)


def test_loop_invariant_nonce_is_detected() -> None:
    source = """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt_all(key, messages):
    cipher = AESGCM(key)
    nonce = os.urandom(12)
    for message in messages:
        cipher.encrypt(nonce, message, None)
"""
    assert "KN003" in rule_ids(source)


def test_secure_aesgcm_has_no_findings() -> None:
    source = """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(data):
    material = AESGCM.generate_key(bit_length=128)
    return AESGCM(material).encrypt(os.urandom(12), data, None)
"""
    assert rule_ids(source) == set()


def test_invalid_tag_handler_must_fail_closed() -> None:
    source = """
from cryptography.exceptions import InvalidTag
def decrypt(cipher, nonce, data):
    try:
        return cipher.decrypt(nonce, data, None)
    except InvalidTag:
        print('ignored')
    return b''
"""
    assert "KN005" in rule_ids(source)


def test_short_nonce_policy() -> None:
    source = """
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
def encrypt(key, data):
    return AESGCM(key).encrypt(os.urandom(8), data, None)
"""
    assert "KN008" in rule_ids(source)
