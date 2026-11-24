"""Structured JSON logging with automatic redaction of sensitive fields."""

from __future__ import annotations

import json
import logging
import sys
from datetime import UTC, datetime
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}
_SENSITIVE = ("key", "token", "password", "secret", "cookie", "authorization", "csrf", "hash")
REDACTED = "[REDACTED]"


def redact(value: Any, key: str = "") -> Any:
    """Recursively mask values whose key name looks sensitive."""
    if any(marker in key.lower() for marker in _SENSITIVE):
        return REDACTED
    if isinstance(value, dict):
        return {str(k): redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [redact(v, key) for v in value]
    return value


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=UTC).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for k, v in record.__dict__.items():
            if k not in _RESERVED:
                payload[k] = redact(v, k)
        if record.exc_info:
            # Internal logs only; never returned to API clients.
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=True)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"vigilsiem.{name}")
