"""SSRF guard for outbound alert webhooks.

Policy: https only, port 443 only, no userinfo, and EVERY resolved address must be
a public, globally routable unicast IP. The validated IP is returned so the caller
connects to that exact address (pinning defeats DNS-rebinding between check and use).
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
Resolver = Callable[[str, int], Awaitable[list[str]]]

# Defense in depth on top of ``ip.is_global``.
BLOCKED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/128",
        "::1/128",
        "64:ff9b::/96",
        "100::/64",
        "2001:db8::/32",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    )
)
_MAX_URL_LEN = 2048
# Legacy inet_aton spellings (127.1, 2130706433, 0x7f000001, 0177.0.0.1): never a real DNS name.
_NUMERIC_LABEL = re.compile(r"(?:0x[0-9a-f]+|\d+)")


_INTERNAL_NAMES = ("localhost", "localdomain")
_INTERNAL_SUFFIXES = (".localhost", ".localdomain", ".local", ".internal", ".lan", ".home.arpa")


class UnsafeWebhookURLError(ValueError):
    """Raised when a webhook URL fails SSRF validation."""


@dataclass(frozen=True)
class WebhookTarget:
    url: str
    hostname: str
    port: int
    ip: str  # validated address to connect to


def _embedded_ipv4(ip: IPAddress) -> IPAddress | None:
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return ip.ipv4_mapped
        if ip.sixtofour:
            return ip.sixtofour
        if ip.teredo:
            return ip.teredo[1]
    return None


def is_public_ip(ip: IPAddress) -> bool:
    embedded = _embedded_ipv4(ip)
    if embedded is not None and not is_public_ip(embedded):
        return False
    if not ip.is_global or ip.is_multicast or ip.is_unspecified:
        return False
    return not any(ip in net for net in BLOCKED_NETWORKS if net.version == ip.version)


async def _default_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise UnsafeWebhookURLError("hostname does not resolve") from exc
    return sorted({str(info[4][0]) for info in infos})


async def validate_webhook_url(
    url: str,
    *,
    resolver: Resolver | None = None,
    allowed_hosts: frozenset[str] | None = None,
) -> WebhookTarget:
    if not url or len(url) > _MAX_URL_LEN or not url.isascii() or any(c.isspace() for c in url):
        raise UnsafeWebhookURLError("invalid URL")
    try:
        parts = urlsplit(url)
        port = parts.port or 443
    except ValueError as exc:
        raise UnsafeWebhookURLError("invalid URL") from exc

    if parts.scheme != "https":
        raise UnsafeWebhookURLError("only https URLs are allowed")
    if parts.username or parts.password or "@" in parts.netloc:
        raise UnsafeWebhookURLError("credentials in URL are not allowed")
    host = (parts.hostname or "").rstrip(".").lower()
    if not host:
        raise UnsafeWebhookURLError("missing hostname")
    if port != 443:
        raise UnsafeWebhookURLError("only port 443 is allowed")
    if allowed_hosts is not None and host not in allowed_hosts:
        raise UnsafeWebhookURLError("host is not on the allow-list")

    try:
        literal: IPAddress | None = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is None and (host in _INTERNAL_NAMES or host.endswith(_INTERNAL_SUFFIXES)):
        raise UnsafeWebhookURLError("internal hostnames are not allowed")
    if literal is None and all(_NUMERIC_LABEL.fullmatch(label) for label in host.split(".")):
        raise UnsafeWebhookURLError("non-canonical IP address")

    if literal is not None:
        addresses = [str(literal)]
    else:
        addresses = await (resolver or _default_resolver)(host, port)
    if not addresses:
        raise UnsafeWebhookURLError("hostname does not resolve")

    parsed: list[IPAddress] = []
    for raw in addresses:
        try:
            parsed.append(ipaddress.ip_address(raw.split("%", 1)[0]))
        except ValueError as exc:
            raise UnsafeWebhookURLError("unparseable resolved address") from exc
    # Reject if ANY record is non-public (blocks mixed public/private rebinding tricks).
    if not all(is_public_ip(ip) for ip in parsed):
        raise UnsafeWebhookURLError("destination resolves to a non-public address")

    return WebhookTarget(url=url, hostname=host, port=port, ip=str(parsed[0]))
