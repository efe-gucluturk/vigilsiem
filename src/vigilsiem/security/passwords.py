"""Password hashing with stdlib scrypt (memory-hard, no extra dependency)."""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets

_N, _R, _P = 2**14, 8, 1
_DKLEN = 32
_MAXMEM = 64 * 1024 * 1024
_MAX_PASSWORD_LEN = 128
_SCHEME = "scrypt"


def _b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii")


def hash_password(password: str) -> str:
    if not 1 <= len(password) <= _MAX_PASSWORD_LEN:
        raise ValueError("password length out of bounds")
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=_N, r=_R, p=_P, dklen=_DKLEN, maxmem=_MAXMEM
    )
    return f"{_SCHEME}${_N}${_R}${_P}${_b64(salt)}${_b64(digest)}"


def verify_password(password: str, stored: str | None) -> bool:
    """Constant-time verify. A missing/invalid hash still costs one scrypt run."""
    if len(password) > _MAX_PASSWORD_LEN:
        password = password[:_MAX_PASSWORD_LEN]
    try:
        scheme, n, r, p, salt_b64, digest_b64 = (stored or "").split("$")
        if scheme != _SCHEME:
            raise ValueError
        salt = base64.urlsafe_b64decode(salt_b64)
        expected = base64.urlsafe_b64decode(digest_b64)
        params = (int(n), int(r), int(p))
        if params != (_N, _R, _P):
            raise ValueError
        valid = True
    except (ValueError, TypeError):
        salt, expected, params, valid = b"\x00" * 16, b"\x00" * _DKLEN, (_N, _R, _P), False
    actual = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=params[0],
        r=params[1],
        p=params[2],
        dklen=len(expected),
        maxmem=_MAXMEM,
    )
    return hmac.compare_digest(actual, expected) and valid
