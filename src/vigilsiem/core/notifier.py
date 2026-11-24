"""Outbound alert webhooks (Slack / Discord) with SSRF protection.

Every dispatch re-validates the URL (DNS may have changed since it was configured) and
connects to the exact IP that passed validation, sending the original hostname as the
``Host`` header and TLS SNI. That pins DNS and defeats rebinding between check and use.
Redirects are never followed and response bodies are never read.
"""

from __future__ import annotations

import re

import httpx

from vigilsiem.core.logging import get_logger
from vigilsiem.engine.detection import Detection
from vigilsiem.security.ssrf import Resolver, UnsafeWebhookURLError, validate_webhook_url

log = get_logger("notifier")

_DISCORD_HOSTS = ("discord.com", "discordapp.com")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_MAX_TEXT = 1500


def sanitize_text(text: str) -> str:
    """Neutralize log-derived text before it reaches chat platforms.

    Attacker-controlled log content (usernames, URIs) must not trigger @mentions or
    Slack link/markup injection.
    """
    text = _CONTROL.sub(" ", text)
    text = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    text = text.replace("@", "@​")
    return text[:_MAX_TEXT]


def mask_url(url: str) -> str:
    """Show scheme + host only: the path/token of a webhook URL is a secret."""
    m = re.match(r"^(https://[^/?#]{1,255})", url)
    return f"{m.group(1)}/…" if m else "https://…"


def build_payload(url: str, detection: Detection, alert_id: int | None = None) -> dict[str, str]:
    ref = f" (#{alert_id})" if alert_id is not None else ""
    body = (
        f"[{detection.severity.value.upper()}] {detection.rule_name}{ref} | "
        f"{detection.mitre_technique_id} {detection.mitre_technique} | {detection.summary}"
    )
    text = sanitize_text(body)
    host = (re.match(r"^https://([^/:?#]+)", url) or [None, ""])[1].lower()
    is_discord = host.endswith(_DISCORD_HOSTS)
    return {"content": text} if is_discord else {"text": text}


class WebhookNotifier:
    def __init__(
        self,
        *,
        resolver: Resolver | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout: float = 5.0,
    ) -> None:
        self._resolver = resolver
        self._transport = transport
        self._timeout = timeout

    async def validate(self, url: str) -> None:
        """Raise UnsafeWebhookURLError unless ``url`` is safe to call (used at config time)."""
        await validate_webhook_url(url, resolver=self._resolver)

    async def send(self, url: str, detection: Detection, alert_id: int | None = None) -> bool:
        """Best-effort delivery. Never raises; returns True on a 2xx response."""
        try:
            target = await validate_webhook_url(url, resolver=self._resolver)
        except UnsafeWebhookURLError as exc:
            log.warning("webhook_blocked", extra={"reason": str(exc), "host": mask_url(url)})
            return False

        parts = httpx.URL(target.url)
        pinned = parts.copy_with(host=target.ip, port=target.port)
        try:
            async with httpx.AsyncClient(
                transport=self._transport,
                timeout=self._timeout,
                follow_redirects=False,
                trust_env=False,  # ignore proxy env vars: they would bypass the pinning
            ) as client:
                response = await client.post(
                    pinned,
                    json=build_payload(url, detection, alert_id),
                    headers={"Host": target.hostname, "User-Agent": "VigilSIEM/0.1"},
                    extensions={"sni_hostname": target.hostname},
                )
        except httpx.HTTPError as exc:
            log.warning(
                "webhook_failed", extra={"host": mask_url(url), "error": type(exc).__name__}
            )
            return False
        ok = 200 <= response.status_code < 300
        if not ok:
            log.warning(
                "webhook_rejected", extra={"host": mask_url(url), "status": response.status_code}
            )
        return ok
