from __future__ import annotations

import asyncio
import os
import secrets
import shutil
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import httpx
import pytest
from starlette.testclient import TestClient

# Test-only secret generated at import time; never a committed constant.
os.environ.setdefault("VIGIL_JWT_SECRET", secrets.token_urlsafe(48))

from vigilsiem.api.app import create_app
from vigilsiem.core.config import Settings
from vigilsiem.core.db import Database
from vigilsiem.core.notifier import WebhookNotifier
from vigilsiem.models.orm import ApiKey
from vigilsiem.security.apikeys import generate_key
from vigilsiem.security.passwords import hash_password

RULES_SRC = Path(__file__).resolve().parents[1] / "rules"
ADMIN_USER = "analyst"
ADMIN_PASSWORD = secrets.token_urlsafe(18)
_ADMIN_HASH = hash_password(ADMIN_PASSWORD)
PUBLIC_IP = "93.184.216.34"


@dataclass
class Env:
    client: TestClient
    app: object
    api_key: str
    other_key: str
    revoked_key: str
    sent: list[httpx.Request]
    settings: Settings
    rules_dir: Path

    def headers(self, key: str | None = None) -> dict[str, str]:
        return {"X-API-Key": key or self.api_key}

    def login(self, password: str = ADMIN_PASSWORD, username: str = ADMIN_USER) -> str:
        r = self.client.post(
            "/api/v1/auth/login", json={"username": username, "password": password}
        )
        assert r.status_code == 200, r.text
        return r.json()["csrf_token"]


async def _provision(url: str) -> tuple[str, str, str]:
    db = Database(url)
    await db.create_all()
    keys = {n: generate_key() for n in ("agent", "other", "revoked")}
    async with db.session() as s:
        for name, k in keys.items():
            s.add(
                ApiKey(
                    name=name, key_prefix=k.prefix, key_hash=k.key_hash, revoked=name == "revoked"
                )
            )
    await db.dispose()
    return keys["agent"].plaintext, keys["other"].plaintext, keys["revoked"].plaintext


def make_env(tmp_path: Path, *, dns: list[str] | None = None, **overrides) -> Iterator[Env]:
    """``dns`` is what the webhook resolver answers; it is read per call, so tests may mutate it."""
    rules_dir = tmp_path / "rules"
    shutil.copytree(RULES_SRC, rules_dir)
    url = f"sqlite+aiosqlite:///{tmp_path / 'siem.db'}"
    agent, other, revoked = asyncio.run(_provision(url))
    settings = Settings(
        _env_file=None,
        jwt_secret=os.environ["VIGIL_JWT_SECRET"],
        database_url=url,
        admin_username=ADMIN_USER,
        admin_password_hash=_ADMIN_HASH,
        rules_dir=str(rules_dir),
        cookie_secure=True,
        log_level="CRITICAL",
        **overrides,
    )
    sent: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append(request)
        return httpx.Response(204)

    async def resolver(_host: str, _port: int) -> list[str]:
        return list(dns) if dns is not None else [PUBLIC_IP]

    notifier = WebhookNotifier(resolver=resolver, transport=httpx.MockTransport(handler))
    app = create_app(settings, notifier=notifier)
    with TestClient(app, base_url="https://testserver", raise_server_exceptions=False) as client:
        yield Env(client, app, agent, other, revoked, sent, settings, rules_dir)


@pytest.fixture
def env(tmp_path: Path) -> Iterator[Env]:
    yield from make_env(tmp_path)


@pytest.fixture
def tight_env(tmp_path: Path) -> Iterator[Env]:
    """Low rate limits so throttling is cheap to exercise."""
    yield from make_env(
        tmp_path, ingest_rate_per_min=3, login_rate_per_min=5, admin_rate_per_min=20
    )
