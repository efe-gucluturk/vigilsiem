"""Signed admin session tokens (JWT, HS256 pinned) and CSRF tokens bound to them."""

from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import jwt

_ALGORITHM = "HS256"
_REQUIRED = ["exp", "iat", "nbf", "iss", "aud", "sub", "jti"]


class InvalidTokenError(Exception):
    """Any token validation failure. Message is internal-only."""


@dataclass(frozen=True)
class TokenClaims:
    subject: str
    session_id: str
    expires_at: datetime


def create_access_token(
    subject: str,
    *,
    secret: str,
    ttl_minutes: int,
    issuer: str,
    audience: str,
    now: datetime | None = None,
) -> tuple[str, TokenClaims]:
    issued = now or datetime.now(UTC)
    expires = issued + timedelta(minutes=ttl_minutes)
    jti = secrets.token_urlsafe(16)
    payload = {
        "sub": subject,
        "jti": jti,
        "iss": issuer,
        "aud": audience,
        "iat": issued,
        "nbf": issued,
        "exp": expires,
    }
    token = jwt.encode(payload, secret, algorithm=_ALGORITHM)
    return token, TokenClaims(subject=subject, session_id=jti, expires_at=expires)


def decode_access_token(token: str, *, secret: str, issuer: str, audience: str) -> TokenClaims:
    try:
        data = jwt.decode(
            token,
            secret,
            algorithms=[_ALGORITHM],  # pinned: rejects alg=none and algorithm confusion
            issuer=issuer,
            audience=audience,
            options={"require": _REQUIRED},
        )
    except jwt.PyJWTError as exc:
        raise InvalidTokenError(type(exc).__name__) from exc
    return TokenClaims(
        subject=str(data["sub"]),
        session_id=str(data["jti"]),
        expires_at=datetime.fromtimestamp(int(data["exp"]), tz=UTC),
    )


# --- CSRF -----------------------------------------------------------------


def _csrf_key(secret: str) -> bytes:
    return hmac.new(secret.encode("utf-8"), b"vigilsiem-csrf-v1", hashlib.sha256).digest()


def issue_csrf_token(session_id: str, *, secret: str) -> str:
    """Deterministic HMAC of the session id; embedded in pages, echoed in a header."""
    return hmac.new(_csrf_key(secret), session_id.encode("utf-8"), hashlib.sha256).hexdigest()


def verify_csrf_token(candidate: str | None, session_id: str, *, secret: str) -> bool:
    if not candidate or not candidate.isascii() or len(candidate) > 128:
        return False
    expected = issue_csrf_token(session_id, secret=secret)
    return hmac.compare_digest(candidate.encode("ascii"), expected.encode("ascii"))
