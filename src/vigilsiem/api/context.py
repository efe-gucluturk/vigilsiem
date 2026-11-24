"""Per-application runtime context (settings, DB, engine, limiters)."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from fastapi import Request

from vigilsiem.core.config import Settings
from vigilsiem.core.db import Database
from vigilsiem.core.notifier import WebhookNotifier
from vigilsiem.engine.correlation import RuleEngine
from vigilsiem.engine.pipeline import DetectionPipeline
from vigilsiem.security.ratelimit import SlidingWindowLimiter


@dataclass
class AppContext:
    settings: Settings
    db: Database
    rules: RuleEngine
    pipeline: DetectionPipeline
    notifier: WebhookNotifier
    ingest_limiter: SlidingWindowLimiter  # per API key prefix
    login_limiter: SlidingWindowLimiter  # per client IP
    admin_limiter: SlidingWindowLimiter  # per authenticated analyst
    key_fail_limiter: SlidingWindowLimiter = field(
        default_factory=lambda: SlidingWindowLimiter(20, 60)
    )  # bad API keys per client IP
    _revoked: dict[str, datetime] = field(default_factory=dict)  # session id -> token expiry

    def revoke_session(self, session_id: str, expires_at: datetime) -> None:
        now = datetime.now(UTC)
        self._revoked = {k: v for k, v in self._revoked.items() if v > now}  # prune expired
        self._revoked[session_id] = expires_at

    def is_revoked(self, session_id: str) -> bool:
        return session_id in self._revoked


def get_ctx(request: Request) -> AppContext:
    return request.app.state.ctx  # type: ignore[no-any-return]
