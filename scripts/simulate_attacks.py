#!/usr/bin/env python3
"""Synthetic attack simulator: benign baseline traffic mixed with attack waves.

Scenarios: ssh_bruteforce, password_spray, sqli, xss, traversal, scanner, sudo, anomaly.
Every attacker uses RFC 5737 documentation addresses (203.0.113.0/24, 198.51.100.0/24);
benign hosts use 10.20.0.0/16. Nothing leaves the machine except HTTPS calls to the SIEM
you point it at.

  # 1. offline: generate log files you can tail with agent/shipper.py
  python scripts/simulate_attacks.py --output-dir ./sim-logs
  # 2. offline: run the generated traffic through the parsers + rule engine in-process
  python scripts/simulate_attacks.py --self-check
  # 3. live: send to a running server and verify the alerts that came out of it
  export VIGIL_AGENT_API_KEY=vsk_...          # from scripts/manage_keys.py
  export VIGIL_ADMIN_USER=analyst VIGIL_ADMIN_PASSWORD=...   # only for --verify
  python scripts/simulate_attacks.py --server https://siem.example.com --verify

Credentials come from the environment/files, never argv.
"""

from __future__ import annotations

import argparse
import json
import os
import random
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from getpass import getpass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

ATTACKS = (
    "ssh_bruteforce",
    "password_spray",
    "sqli",
    "xss",
    "traversal",
    "scanner",
    "sudo",
    "anomaly",
)
EXPECTED_RULES = {
    "ssh_bruteforce": {"VSR-1001"},
    "password_spray": {"VSR-1002"},
    "sqli": {"VSR-2001", "VSR-2004"},
    "xss": {"VSR-2002"},
    "traversal": {"VSR-2003"},
    "scanner": {"VSR-2004", "VSR-2005"},
    "sudo": {"VSR-1003"},
    "anomaly": {"VSA-0001", "VSA-0002"},
}
SOURCE_FILES = {"ssh": "auth.log", "nginx": "access.log", "json": "app.jsonl"}
MIN_DURATION_MIN = 15
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}
_KEY_RE = re.compile(r"^vsk_[0-9a-f]{12}\.[A-Za-z0-9_-]{20,100}$")

BENIGN_URIS = (
    "/", "/index.html", "/about", "/pricing", "/static/app.js", "/static/site.css",
    "/api/v1/items?page=2&sort=name", "/products/select-your-plan", "/blog/2026/release-notes",
    "/search?q=ice+cream", "/contact", "/docs/getting-started",
)  # fmt: skip
BROWSER_UAS = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
)
SQLI_PAYLOADS = (
    "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
    "/item?id=1'%20OR%20'1'='1",
    "/item?id=1;SELECT%20SLEEP(5)--",
    "/item?id=1%20AND%201=2%20UNION%20SELECT%20table_name%20FROM%20information_schema.tables",
    "/login?user=admin'--&pass=x",
    "/item?id=1%27%20OR%201%3D1%23",
)
XSS_PAYLOADS = (
    "/search?q=<script>alert(document.cookie)</script>",
    "/profile?name=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
    "/redirect?u=javascript:alert(1)",
)
TRAVERSAL_PAYLOADS = (
    "/download?f=../../../../etc/passwd",
    "/download?f=..%2f..%2f..%2fetc%2fshadow",
    "/static/%252e%252e%252f%252e%252e%252fboot.ini",
)


# ---------------------------------------------------------------------------------------
# data model
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class SimLine:
    ts: datetime
    text: str
    scenario: str


@dataclass
class Scenario:
    streams: dict[str, list[SimLine]] = field(default_factory=lambda: {k: [] for k in SOURCE_FILES})
    expected_rules: set[str] = field(default_factory=set)
    attacker_ips: set[str] = field(default_factory=set)
    benign_ips: set[str] = field(default_factory=set)
    benign_users: set[str] = field(default_factory=set)

    def add(self, source: str, ts: datetime, text: str, scenario: str) -> None:
        self.streams[source].append(SimLine(ts, text, scenario))

    def finish(self) -> Scenario:
        for lines in self.streams.values():
            lines.sort(key=lambda line: line.ts)  # per-key chronological order matters
        return self

    @property
    def total_lines(self) -> int:
        return sum(len(v) for v in self.streams.values())


# ---------------------------------------------------------------------------------------
# log line formats
# ---------------------------------------------------------------------------------------


def _syslog(ts: datetime, proc: str, msg: str, rng: random.Random, host: str = "web01") -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} {host} {proc}[{rng.randint(1000, 60000)}]: {msg}"


def ssh_failed(ts, ip, user, rng):
    port = rng.randint(30000, 60000)
    return _syslog(ts, "sshd", f"Failed password for {user} from {ip} port {port} ssh2", rng)


def ssh_accepted(ts, ip, user, rng):
    port = rng.randint(30000, 60000)
    return _syslog(ts, "sshd", f"Accepted publickey for {user} from {ip} port {port} ssh2", rng)


def sudo_ok(ts, user, cmd, rng):
    msg = f"{user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
    return _syslog(ts, "sudo", msg, rng)


def sudo_fail(ts, user, rng):
    msg = f"{user} : 3 incorrect password attempts ; TTY=pts/1 ; USER=root ; COMMAND=/bin/bash"
    return _syslog(ts, "sudo", msg, rng)


def sudo_root_session(ts, user, rng):
    msg = f"pam_unix(sudo:session): session opened for user root by {user}(uid=1001)"
    return _syslog(ts, "sudo", msg, rng)


def nginx_line(ts, ip, uri, status, ua, rng, user="-"):
    size = rng.randint(200, 20000)
    stamp = f"{ts:%d/%b/%Y:%H:%M:%S} +0000"
    return f'{ip} - {user} [{stamp}] "GET {uri} HTTP/1.1" {status} {size} "-" "{ua}"'


def json_login(ts, ip, user, status="success"):
    return json.dumps(
        {
            "timestamp": ts.isoformat().replace("+00:00", "Z"),
            "source_ip": ip,
            "username": user,
            "category": "authentication",
            "action": "app_login",
            "status": status,
        }
    )


# ---------------------------------------------------------------------------------------
# scenario generators
# ---------------------------------------------------------------------------------------


def _baseline(sc: Scenario, rng: random.Random, start: datetime, minutes: int) -> None:
    span = minutes * 60
    for n, user in enumerate(("alice", "bob", "carol"), start=11):
        ip = f"10.20.0.{n}"
        sc.benign_ips.add(ip)
        sc.benign_users.add(user)
        for _ in range(6):
            ts = start + timedelta(seconds=rng.uniform(0, span))
            sc.add("ssh", ts, ssh_accepted(ts, ip, user, rng), "baseline")
        ts = start + timedelta(seconds=rng.uniform(0, span))  # one benign typo: below any threshold
        sc.add("ssh", ts, ssh_failed(ts, ip, user, rng), "baseline")
    for _ in range(4):
        ts = start + timedelta(seconds=rng.uniform(0, span))
        sc.add("ssh", ts, sudo_ok(ts, "alice", "/usr/bin/apt update", rng), "baseline")

    for n in range(1, 9):  # ~1 request/minute per host: nowhere near any volume threshold
        ip = f"10.20.1.{n}"
        sc.benign_ips.add(ip)
        for _ in range(minutes):
            ts = start + timedelta(seconds=rng.uniform(0, span))
            status = 404 if rng.random() < 0.03 else 200
            sc.add(
                "nginx",
                ts,
                nginx_line(ts, ip, rng.choice(BENIGN_URIS), status, rng.choice(BROWSER_UAS), rng),
                "baseline",
            )

    for n, user in enumerate(("erin", "frank"), start=1):
        ip = f"10.20.2.{n}"
        sc.benign_ips.add(ip)
        sc.benign_users.add(user)
        for _ in range(5):
            ts = start + timedelta(seconds=rng.uniform(0, span))
            sc.add("json", ts, json_login(ts, ip, user), "baseline")


def _ssh_bruteforce(sc, rng, start, minutes, waves):
    sc.expected_rules |= EXPECTED_RULES["ssh_bruteforce"]
    for i in range(waves):
        ip = f"203.0.113.{10 + i}"
        sc.attacker_ips.add(ip)
        t0 = start + timedelta(seconds=(minutes * 60 - 400) * (i + 0.5) / waves + 60)
        for k in range(12):  # 12 failures in ~22s against one account
            ts = t0 + timedelta(seconds=k * 2 + rng.random())
            sc.add("ssh", ts, ssh_failed(ts, ip, "root", rng), "ssh_bruteforce")


def _password_spray(sc, rng, start, minutes):
    sc.expected_rules |= EXPECTED_RULES["password_spray"]
    ip = "203.0.113.50"
    sc.attacker_ips.add(ip)
    users = ("admin", "oracle", "postgres", "ubuntu", "deploy", "test")
    t0 = start + timedelta(seconds=minutes * 30)
    for k in range(9):  # slow and low: 25s apart stays under the brute-force threshold
        ts = t0 + timedelta(seconds=k * 25 + rng.random())
        sc.add("ssh", ts, ssh_failed(ts, ip, users[k % len(users)], rng), "password_spray")


def _web_probe(sc, rng, start, minutes, name, ip, payloads, ua, gap, offset):
    sc.expected_rules |= EXPECTED_RULES[name]
    sc.attacker_ips.add(ip)
    t0 = start + timedelta(seconds=minutes * 60 * offset)
    for k, uri in enumerate(payloads):
        ts = t0 + timedelta(seconds=k * gap + rng.random())
        sc.add("nginx", ts, nginx_line(ts, ip, uri, rng.choice((200, 403, 500)), ua, rng), name)


def _scanner(sc, rng, start, minutes):
    sc.expected_rules |= EXPECTED_RULES["scanner"]
    ip = "198.51.100.33"
    sc.attacker_ips.add(ip)
    t0 = start + timedelta(seconds=minutes * 60 * 0.62)
    for k in range(30):  # forced browsing: 30 x 404 in ~40s
        ts = t0 + timedelta(seconds=k * 1.3 + rng.random() * 0.3)
        uri = (
            f"/{rng.choice(('admin', 'backup', 'wp-login', '.git/config', 'phpmyadmin', 'old'))}{k}"
        )
        sc.add(
            "nginx", ts, nginx_line(ts, ip, uri, 404, "Mozilla/5.00 (Nikto/2.1.6)", rng), "scanner"
        )


def _sudo(sc, rng, start, minutes):
    sc.expected_rules |= EXPECTED_RULES["sudo"]
    for i, user in enumerate(("mallory", "trent")):
        t0 = start + timedelta(seconds=minutes * 60 * (0.3 + 0.35 * i))
        sc.add("ssh", t0, sudo_fail(t0, user, rng), "sudo")
        t1 = t0 + timedelta(seconds=30 + rng.randint(0, 20))
        sc.add("ssh", t1, sudo_root_session(t1, user, rng), "sudo")


def _anomaly(sc, rng, start, end):
    """Off-hours login for a user with a learned 09-11h UTC baseline, plus a volume spike."""
    sc.expected_rules |= EXPECTED_RULES["anomaly"]
    user, ip = "dave", "10.20.0.50"
    sc.benign_ips.add(ip)
    sc.benign_users.add(user)
    day0 = (end - timedelta(days=1)).replace(hour=0, minute=0, second=0, microsecond=0)
    for d in range(10, 1, -1):  # nine prior days of normal business-hours logins
        base = day0 - timedelta(days=d)
        for hour in (9, 10, 11):
            ts = base + timedelta(hours=hour, minutes=rng.randint(0, 59))
            sc.add("json", ts, json_login(ts, ip, user), "anomaly")
    odd = day0 + timedelta(hours=3, minutes=rng.randint(5, 50))  # 03:xx UTC yesterday
    sc.add("json", odd, json_login(odd, ip, user), "anomaly")

    spike_ip = "198.51.100.77"  # steady trickle, then a sudden burst within one minute
    sc.attacker_ips.add(spike_ip)
    burst_minute = (end - timedelta(minutes=3)).replace(second=0, microsecond=0)
    for m in range(9, 3, -1):
        for _ in range(2):
            ts = burst_minute - timedelta(minutes=m) + timedelta(seconds=rng.uniform(0, 59))
            sc.add(
                "nginx",
                ts,
                nginx_line(ts, spike_ip, "/api/v1/items", 200, BROWSER_UAS[0], rng),
                "anomaly",
            )
    for k in range(70):
        ts = burst_minute + timedelta(seconds=k * 0.8)
        sc.add(
            "nginx",
            ts,
            nginx_line(ts, spike_ip, "/api/v1/items", 200, BROWSER_UAS[0], rng),
            "anomaly",
        )


def build_scenario(
    *,
    attacks: Sequence[str] = ATTACKS,
    baseline: bool = True,
    minutes: int = 20,
    waves: int = 3,
    seed: int = 1337,
    now: datetime | None = None,
) -> Scenario:
    unknown = set(attacks) - set(ATTACKS)
    if unknown:
        raise ValueError(f"unknown scenarios: {sorted(unknown)}")
    if minutes < MIN_DURATION_MIN:
        raise ValueError(f"duration must be at least {MIN_DURATION_MIN} minutes")
    rng = random.Random(seed)  # noqa: S311  # nosec B311
    end = (now or datetime.now(UTC)) - timedelta(seconds=10)
    start = end - timedelta(minutes=minutes)
    sc = Scenario()
    if baseline:
        _baseline(sc, rng, start, minutes)
    if "ssh_bruteforce" in attacks:
        _ssh_bruteforce(sc, rng, start, minutes, waves)
    if "password_spray" in attacks:
        _password_spray(sc, rng, start, minutes)
    if "sqli" in attacks:
        _web_probe(
            sc,
            rng,
            start,
            minutes,
            "sqli",
            "198.51.100.23",
            SQLI_PAYLOADS,
            "sqlmap/1.7.2#stable (https://sqlmap.org)",
            3,
            0.45,
        )
    if "xss" in attacks:
        _web_probe(
            sc, rng, start, minutes, "xss", "198.51.100.31", XSS_PAYLOADS, BROWSER_UAS[2], 4, 0.55
        )
    if "traversal" in attacks:
        _web_probe(
            sc,
            rng,
            start,
            minutes,
            "traversal",
            "198.51.100.32",
            TRAVERSAL_PAYLOADS,
            BROWSER_UAS[1],
            4,
            0.7,
        )
    if "scanner" in attacks:
        _scanner(sc, rng, start, minutes)
    if "sudo" in attacks:
        _sudo(sc, rng, start, minutes)
    if "anomaly" in attacks:
        _anomaly(sc, rng, start, end)
    return sc.finish()


# ---------------------------------------------------------------------------------------
# transport
# ---------------------------------------------------------------------------------------


def build_endpoint(server: str, *, allow_insecure_localhost: bool) -> str:
    parts = urlsplit(server)
    host = (parts.hostname or "").lower()
    if parts.username or parts.password or parts.query or parts.path not in ("", "/") or not host:
        raise ValueError("--server must be a bare origin such as https://siem.example.com")
    if parts.scheme != "https" and not (
        parts.scheme == "http" and host in _LOOPBACK and allow_insecure_localhost
    ):
        raise ValueError(
            "--server must be https:// (loopback http needs --allow-insecure-localhost)"
        )
    return f"{parts.scheme}://{parts.netloc}/api/v1/ingest"


def load_key(key_file: str | None, env: Mapping[str, str] = os.environ) -> str:
    key = (
        Path(key_file).read_text(encoding="utf-8").strip()
        if key_file
        else env.get("VIGIL_AGENT_API_KEY", "").strip()
    )
    if not _KEY_RE.fullmatch(key):
        raise ValueError("missing or malformed API key (set VIGIL_AGENT_API_KEY or --api-key-file)")
    return key


def make_batches(sc: Scenario, batch_size: int) -> list[tuple[str, list[str]]]:
    """Chunk each stream (kept chronological) and round-robin the streams so traffic mixes."""
    queues = {
        src: [
            [ln.text for ln in lines[i : i + batch_size]] for i in range(0, len(lines), batch_size)
        ]
        for src, lines in sc.streams.items()
        if lines
    }
    out: list[tuple[str, list[str]]] = []
    while any(queues.values()):
        for src, chunks in queues.items():
            if chunks:
                out.append((src, chunks.pop(0)))
    return out


@dataclass
class SendTotals:
    batches: int = 0
    accepted: int = 0
    rejected: int = 0
    alerts: int = 0


def send_all(
    client: httpx.Client,
    endpoint: str,
    key: str,
    batches: Sequence[tuple[str, list[str]]],
    *,
    host: str = "sim01",
    delay: float = 0.0,
    sleep: Callable[[float], None] = time.sleep,
    out: Callable[[str], None] = print,
) -> SendTotals:
    totals = SendTotals()
    for source, lines in batches:
        for _ in range(6):
            r = client.post(
                endpoint,
                json={"source_type": source, "host": host, "lines": lines},
                headers={"X-API-Key": key},
            )
            if r.status_code == 429:  # respect the server's rate limit
                sleep(min(int(r.headers.get("retry-after", "5")), 120))
                continue
            break
        if r.status_code != 200:
            raise RuntimeError(f"ingest failed with HTTP {r.status_code}: {r.text[:200]}")
        body = r.json()
        totals.batches += 1
        totals.accepted += body["accepted"]
        totals.rejected += body["rejected"]
        totals.alerts += body["alerts_created"]
        out(f"  sent {source:<6} {len(lines):>4} lines -> +{body['alerts_created']} alerts")
        if delay:
            sleep(delay)
    return totals


# ---------------------------------------------------------------------------------------
# verification
# ---------------------------------------------------------------------------------------


@dataclass
class Verdict:
    found: Counter[str]
    missing: set[str]
    unexpected: list[dict]

    @property
    def ok(self) -> bool:
        return not self.missing and not self.unexpected


def judge(alerts: Sequence[Mapping], sc: Scenario) -> Verdict:
    """Every expected rule fired, and no benign host/user was flagged (except dave's off-hours)."""
    found = Counter(a["rule_id"] for a in alerts)
    missing = sc.expected_rules - set(found)
    unexpected = [
        a
        for a in alerts
        if (a.get("source_ip") in sc.benign_ips or a.get("username") in sc.benign_users)
        and not (a["rule_id"] == "VSA-0001" and a.get("username") == "dave")
    ]
    return Verdict(found, missing, unexpected)


def fetch_alerts(
    client: httpx.Client, base: str, user: str, password: str, since: datetime
) -> list[dict]:
    r = client.post(f"{base}/api/v1/auth/login", json={"username": user, "password": password})
    if r.status_code != 200:
        raise RuntimeError(f"admin login failed (HTTP {r.status_code})")
    alerts: list[dict] = []
    for offset in range(0, 2000, 200):
        page = client.get(f"{base}/api/v1/alerts", params={"limit": 200, "offset": offset}).json()
        alerts += [a for a in page if _created(a) >= since]
        if len(page) < 200:
            break
    return alerts


def _created(alert: Mapping) -> datetime:
    ts = datetime.fromisoformat(alert["created_at"])
    return ts if ts.tzinfo else ts.replace(tzinfo=UTC)


def self_check(sc: Scenario, rules_dir: str = "rules") -> Verdict:
    """Run the generated traffic through the real parsers + engine, no server needed."""
    from vigilsiem.engine.anomaly import AnomalyScorer
    from vigilsiem.engine.correlation import RuleEngine
    from vigilsiem.engine.pipeline import DetectionPipeline
    from vigilsiem.models.enums import SourceType
    from vigilsiem.parsers.normalizer import normalize_batch

    pipe = DetectionPipeline(RuleEngine.from_directory(rules_dir), AnomalyScorer())
    alerts: list[dict] = []
    for source, lines in make_batches(sc, 100):
        res = normalize_batch(SourceType(source), "sim01", lines)
        if res.rejected:
            raise RuntimeError(
                f"{res.rejected} generated {source} lines failed to parse: {res.errors}"
            )
        for d in pipe.process(res.events):
            alerts.append(
                {
                    "rule_id": d.rule_id,
                    "source_ip": d.source_ip,
                    "username": d.username,
                    "created_at": d.timestamp.isoformat(),
                }
            )
    return judge(alerts, sc)


def print_verdict(v: Verdict, out: Callable[[str], None] = print) -> None:
    out("\nAlerts by rule:")
    for rule, n in sorted(v.found.items()):
        out(f"  {rule:<9} {n}")
    out(f"Missing expected rules: {sorted(v.missing) or 'none'}")
    out(f"Alerts on benign hosts/users (false positives): {len(v.unexpected) or 'none'}")
    for a in v.unexpected[:5]:
        out(f"    {a['rule_id']} ip={a.get('source_ip')} user={a.get('username')}")
    out("RESULT: " + ("PASS" if v.ok else "FAIL"))


# ---------------------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------------------


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="VigilSIEM synthetic attack simulator", allow_abbrev=False
    )
    p.add_argument("--server", help="SIEM origin, e.g. https://siem.example.com")
    p.add_argument("--api-key-file")
    p.add_argument("--scenarios", default="all", help=f"comma list of {','.join(ATTACKS)} or 'all'")
    p.add_argument("--no-baseline", action="store_true")
    p.add_argument("--minutes", type=int, default=20)
    p.add_argument("--waves", type=int, default=3)
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--batch-size", type=int, default=100)
    p.add_argument("--delay", type=float, default=0.6, help="seconds between batches (rate limit)")
    p.add_argument("--output-dir", type=Path, help="write auth.log/access.log/app.jsonl and exit")
    p.add_argument("--self-check", action="store_true", help="evaluate locally, no server")
    p.add_argument("--verify", action="store_true", help="login as admin and check the alerts")
    p.add_argument("--rules-dir", default="rules")
    p.add_argument("--allow-insecure-localhost", action="store_true")
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    attacks = (
        ATTACKS if args.scenarios == "all" else tuple(s.strip() for s in args.scenarios.split(","))
    )
    try:
        started = datetime.now(UTC)
        sc = build_scenario(
            attacks=attacks, baseline=not args.no_baseline, minutes=args.minutes,
            waves=args.waves, seed=args.seed,
        )  # fmt: skip
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(
        f"generated {sc.total_lines} lines: "
        + ", ".join(f"{k}={len(v)}" for k, v in sc.streams.items())
    )

    if args.output_dir:
        args.output_dir.mkdir(parents=True, exist_ok=True)
        for src, name in SOURCE_FILES.items():
            (args.output_dir / name).write_text(
                "".join(f"{ln.text}\n" for ln in sc.streams[src]), encoding="utf-8"
            )
        print(f"wrote {', '.join(SOURCE_FILES.values())} to {args.output_dir}")
        return 0
    if args.self_check:
        verdict = self_check(sc, args.rules_dir)
        print_verdict(verdict)
        return 0 if verdict.ok else 1
    if not args.server:
        print("error: give --server, --output-dir or --self-check", file=sys.stderr)
        return 2

    try:
        endpoint = build_endpoint(
            args.server, allow_insecure_localhost=args.allow_insecure_localhost
        )
        key = load_key(args.api_key_file)
        admin_user = os.environ.get("VIGIL_ADMIN_USER", "")
        admin_pw = os.environ.get("VIGIL_ADMIN_PASSWORD", "")
        if args.verify and not admin_pw and sys.stdin.isatty():
            admin_pw = getpass("Admin password (for --verify): ")
        if args.verify and not (admin_user and admin_pw):
            raise ValueError("--verify needs VIGIL_ADMIN_USER and VIGIL_ADMIN_PASSWORD")
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    base = endpoint.removesuffix("/api/v1/ingest")
    with httpx.Client(timeout=15.0, follow_redirects=False) as client:
        totals = send_all(
            client, endpoint, key, make_batches(sc, args.batch_size), delay=args.delay
        )
        print(
            f"\nsent {totals.batches} batches: accepted={totals.accepted} "
            f"rejected={totals.rejected} alerts={totals.alerts}"
        )
        if not args.verify:
            return 0
        verdict = judge(fetch_alerts(client, base, admin_user, admin_pw, started), sc)
    print_verdict(verdict)
    return 0 if verdict.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
