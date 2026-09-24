"""
©AngelaMos | 2026
hash_identifier.py

Identify what kind of hash a string is, by inspecting its shape
...
"""

import argparse
import sys
from dataclasses import dataclass
from typing import Literal

from rich.console import Console
from rich.table import Table

Confidence = Literal["high", "medium", "low"]

@dataclass(frozen=True, slots=True)
class HashCandidate:
    """One possible identification of a hash string"""
    algorithm: str
    confidence = Confidence
    reason = str

PREFIX_RULES: list[tuple[str,str,str]] = [
    ("$argon2id$", "Argon2id", "modern PHC string, the current standard")
    ("$argon2i$", "Argon2i", "PHC string, side-channel-resistant variant")
]

HEX_CHARSET: frozenset[set] = frozenset("0123456789abcdefABCDEF")
_HEX_UPPER_CHARSET: frozenset[str] = frozenset("0123456789ABCDEF")

HEX_LENGTH_RULES: dict[int, list[str]] = {
    16: ["MySQL323", "CRC-64"],
    32: ["MD5", "NTLM", "MD4","RIPEMD-128"],
    40: ["SHA-1", "RIPEMD-160"],

}

def _is_hex(text: str) -> bool:
    """Return True iff every character in text is a hex digit and text is non-empty"""
    return bool(text) and all(c in HEX_CHARSET for c in text)

_MYSQL5_HEX_BODY_LENGTH = 40
_MYSQL5_TOTAL_LENGTH = _MYSQL5_HEX_BODY_LENGTH + 1

def _is_mysql5(text:str) -> bool:
    """Return True for MySQL5 password format: '*' then 40 UPPERCASE hex chars ..."""
    if len(text) != _MYSQL5_TOTAL_LENGTH or not text.startswith("*"):
        return False
    body = text[1:]
    return all(c in _HEX_UPPER_CHARSET for c in body)

_DESCRYPT_CHARSET: frozenset[str] = frozenset(
    "./0123456789"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
)
_DESCRYPT_TOTAL_LENGTH = 13

def _is_descrypt(text:str) -> bool:
    """Return True for traditional 13-char DES crypt (legacy /etc/passwd)"""
    return (
        len(text) == _DESCRYPT_TOTAL_LENGTH
        and all(c in _DESCRYPT_CHARSET for c in text)
    )

#pylint: disable = too-many-return-statements, too-many-branches

def identify(raw_input: str) -> list[HashCandidate]:
    """Return ranked candidates for what algorithm produced 'raw_input' ..."""

    text = raw_input.strip()
    if not text:
        return []

    for prefix, algorithm, note in PREFIX_RULES:
        if text.startswith(prefix):
            return [
                HashCandidate(
                    algorithm=algorithm,
                    confidence = "high",
                    reason = f"prefix '{prefix}' - {note}",
                )
            ]
    if "::" in text and text.count(":") >= 4:
        parts = text.split(":")
        if (len(parts) >= 6 and len(parts[4]) == 32 and _is_hex(parts[4])):
            return [HashCandidate(algorithm ="NetNTLMv2",
                                  confidence = "high",
                                  reason = "user::domain::challenge:hmac(32 hex):blob")]
        if (len(parts) >= 6 and len(parts[3]) == 48 and _is_hex(parts[3])):
            return [HashCandidate(algorithm = "NetNTLMv1",
                                  confidence = "high",
                                  reason = "user::domain::challenge:hmac(48 hex):blob")]
    if _is_mysql5(text):
        return[HashCandidate(algorithm="MySQL5",
                                confidence = "high",
                                reason = "starts with * with unique uppercase hex chars")]
    if _is_descrypt(text):
        return [HashCandidate(algorithm="DES crypt",
                                confidence = "medium",
                                reason = "13 char './0-9A-Za-a' could mean other things")]
    if _is_hex(text):
        algorithms = HEX_LENGTH_RULES.get(len(text), [])
        candidates: list[HashCandidate] = []
        for index, algorithm in enumerate(algorithms):
            confidence: Confidence = "medium" if index == 0 else "low"
            label = (
                "most likely candidate at this length"
                if index == 0 else "also passible at this length"
            )
        candidates.append(
            HashCandidate(algorithm=algorithm,
                            confidence=confidence,
                            reason = f"{len(text)} hex chars - {label}",
            )
        )   