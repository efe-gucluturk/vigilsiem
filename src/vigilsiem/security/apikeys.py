"""Agent API key generation and verification.

Key format: ``vsk_<prefix>.<secret>``. The prefix is a public lookup id; only the
SHA-256 digest of the *full* key is persisted. Verification is constant-time and
performs a dummy comparison when the prefix is unknown (no existence oracle).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass

KEY_TAG = "vsk_"
_PREFIX_BYTES = 6  # 12 hex chars
_DUMMY_HASH = hashlib.sha256(b"vigilsiem-dummy").hexdigest()
_MAX_KEY_LEN = 128


@dataclass(frozen=True)
class GeneratedKey:
    plaintext: str  # shown to the operator exactly once
    prefix: str
    key_hash: str


def hash_key(plaintext: str) -> str:
    return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()


def generate_key() -> GeneratedKey:
    prefix = secrets.token_hex(_PREFIX_BYTES)
    plaintext = f"{KEY_TAG}{prefix}.{secrets.token_urlsafe(32)}"
    return GeneratedKey(plaintext=plaintext, prefix=prefix, key_hash=hash_key(plaintext))


def extract_prefix(candidate: str | None) -> str | None:
    """Return the lookup prefix of a well-formed key, else None."""
    if not candidate or len(candidate) > _MAX_KEY_LEN or not candidate.isascii():
        return None
    if not candidate.startswith(KEY_TAG) or "." not in candidate:
        return None
    prefix = candidate[len(KEY_TAG) :].split(".", 1)[0]
    if len(prefix) != _PREFIX_BYTES * 2 or any(c not in "0123456789abcdef" for c in prefix):
        return None
    return prefix


def verify_key(candidate: str | None, stored_hash: str | None) -> bool:
    """Constant-time check. ``stored_hash=None`` still burns an equivalent comparison."""
    digest = hash_key(candidate) if candidate and candidate.isascii() else _DUMMY_HASH
    expected = stored_hash if stored_hash else _DUMMY_HASH
    matches = secrets.compare_digest(digest.encode("ascii"), expected.encode("ascii"))
    return matches and stored_hash is not None and candidate is not None
