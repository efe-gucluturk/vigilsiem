"""Functional detection, end to end through the real HTTP API.

Raw log lines go in through ``POST /api/v1/ingest`` (API key auth, parsing, rules, anomaly scorer,
persistence) and the resulting alerts are read back through the admin API. Each test asserts the
alert's rule, severity, MITRE mapping and attribution, plus the negative cases that must stay quiet.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

import simulate_attacks as sim
from helpers import nginx_line, ssh_failed, ssh_ok

API = "/api/v1"


def ingest(env, source: str, lines: list[str], host: str = "web01"):
    r = env.client.post(
        f"{API}/ingest",
        json={"source_type": source, "host": host, "lines": lines},
        headers=env.headers(),
    )
    assert r.status_code == 200, r.text
    return r.json()


def alerts(env, **params) -> list[dict]:
    if "vigil_session" not in env.client.cookies:
        env.login()
    r = env.client.get(f"{API}/alerts", params={"limit": 200, **params})
    assert r.status_code == 200, r.text
    return r.json()


def by_rule(found: list[dict]) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for a in found:
        out.setdefault(a["rule_id"], []).append(a)
    return out


def recent(offset: float = 0) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=60) + timedelta(seconds=offset)


# --- SSH brute force -------------------------------------------------------------------------
def test_ssh_bruteforce_alert_has_severity_mitre_and_attribution(env):
    lines = [ssh_failed(recent(i), ip="203.0.113.50", user="root") for i in range(6)]
    assert ingest(env, "ssh", lines)["alerts_created"] == 1
    (a,) = alerts(env)
    assert a["rule_id"] == "VSR-1001" and a["severity"] == "high" and a["status"] == "open"
    assert a["source_ip"] == "203.0.113.50"
    assert a["mitre_tactic"] == "Credential Access" and a["mitre_technique"] == "T1110"


def test_ssh_four_failures_stay_below_the_threshold(env):
    lines = [ssh_failed(recent(i), ip="203.0.113.51") for i in range(4)]
    assert ingest(env, "ssh", lines)["alerts_created"] == 0
    assert alerts(env) == []


def test_ssh_bruteforce_is_per_source_ip(env):
    lines = []
    for i in range(4):  # 4 + 4 failures from two different IPs: neither crosses 5
        lines.append(ssh_failed(recent(i), ip="203.0.113.60"))
        lines.append(ssh_failed(recent(i + 0.5), ip="203.0.113.61"))
    assert ingest(env, "ssh", lines)["alerts_created"] == 0


def test_ssh_failures_across_batches_are_correlated(env):
    first = [ssh_failed(recent(i), ip="203.0.113.62") for i in range(3)]
    second = [ssh_failed(recent(3 + i), ip="203.0.113.62") for i in range(3)]
    assert ingest(env, "ssh", first)["alerts_created"] == 0
    assert ingest(env, "ssh", second)["alerts_created"] == 1


def test_successful_logins_do_not_alert(env):
    lines = [ssh_ok(recent(i), ip="198.51.100.7", user="alice") for i in range(10)]
    assert ingest(env, "ssh", lines)["alerts_created"] == 0


def test_alert_flood_is_suppressed_by_cooldown(env):
    lines = [ssh_failed(recent(i * 0.1), ip="203.0.113.63") for i in range(40)]
    ingest(env, "ssh", lines)
    assert len(by_rule(alerts(env))["VSR-1001"]) == 1


# --- password spraying -----------------------------------------------------------------------
def test_password_spraying_distinct_users_from_one_ip(env):
    users = ["alice", "bob", "carol", "dave"]
    lines = [ssh_failed(recent(i * 10), ip="203.0.113.70", user=u) for i, u in enumerate(users)]
    ingest(env, "ssh", lines)
    found = by_rule(alerts(env))
    assert set(found) == {"VSR-1002"}
    a = found["VSR-1002"][0]
    assert a["severity"] == "high" and a["source_ip"] == "203.0.113.70"
    assert a["mitre_technique"] == "T1110.003"
    assert a["mitre_technique_name"] == "Password Spraying"


def test_one_user_hammered_is_bruteforce_not_spraying(env):
    lines = [ssh_failed(recent(i), ip="203.0.113.71", user="alice") for i in range(6)]
    ingest(env, "ssh", lines)
    assert set(by_rule(alerts(env))) == {"VSR-1001"}


# --- SQL injection / XSS / traversal -----------------------------------------------------------
@pytest.mark.parametrize(
    ("uri", "rule", "severity"),
    [
        ("/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "VSR-2001", "high"),
        ("/item?id=1'%20OR%20'1'='1", "VSR-2001", "high"),
        ("/q?x=1;SELECT+SLEEP(5)--", "VSR-2001", "high"),
        ("/search?q=<script>alert(1)</script>", "VSR-2002", "medium"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "VSR-2002", "medium"),
        ("/p?u=javascript:alert(1)", "VSR-2002", "medium"),
        ("/download?f=../../../../etc/passwd", "VSR-2003", "high"),
        ("/download?f=..%2f..%2f..%2fetc%2fpasswd", "VSR-2003", "high"),
    ],
)
def test_web_attack_signatures_raise_alerts(env, uri, rule, severity):
    ingest(env, "nginx", [nginx_line(recent(), uri=uri, ip="203.0.113.80")])
    found = by_rule(alerts(env))
    assert rule in found, (uri, sorted(found))
    hit = found[rule][0]
    assert hit["severity"] == severity and hit["source_ip"] == "203.0.113.80"
    assert hit["mitre_tactic"] and hit["mitre_technique_name"]


def test_scanner_user_agent_is_flagged(env):
    ingest(env, "nginx", [nginx_line(recent(), ip="203.0.113.81", ua="sqlmap/1.7.2#stable")])
    assert "VSR-2004" in by_rule(alerts(env))


def test_benign_web_traffic_is_silent(env):
    uris = [
        "/",
        "/index.html",
        "/api/v1/items?page=2",
        "/static/app.css",
        "/search?q=cats+and+dogs",
    ]
    lines = [nginx_line(recent(i), uri=u, ip="198.51.100.20") for i, u in enumerate(uris * 4)]
    assert ingest(env, "nginx", lines)["alerts_created"] == 0
    assert alerts(env) == []


# --- sudo privilege escalation -----------------------------------------------------------------
def _sudo_fail(ts: datetime, user: str = "mallory") -> str:
    return (
        f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} h sudo: {user} : 3 incorrect password attempts ; "
        "TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"
    )


def _root_session(ts: datetime, user: str = "mallory", target: str = "root") -> str:
    return (
        f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S} h sudo: pam_unix(sudo:session): "
        f"session opened for user {target} by {user}(uid=1001)"
    )


def test_sudo_failures_then_root_session_is_critical(env):
    ingest(env, "ssh", [_sudo_fail(recent(0)), _root_session(recent(30))])
    found = by_rule(alerts(env))
    assert set(found) == {"VSR-1003"}
    a = found["VSR-1003"][0]
    assert a["severity"] == "critical" and a["username"] == "mallory"
    assert a["mitre_tactic"] == "Privilege Escalation"


def test_sudo_sequence_across_two_batches(env):
    ingest(env, "ssh", [_sudo_fail(recent(0))])
    assert alerts(env) == []
    ingest(env, "ssh", [_root_session(recent(20))])
    assert "VSR-1003" in by_rule(alerts(env))


@pytest.mark.parametrize(
    "lines",
    [
        lambda: [_root_session(recent(0)), _sudo_fail(recent(10))],  # wrong order
        lambda: [_sudo_fail(recent(0)), _root_session(recent(10), user="someone_else")],
        lambda: [_sudo_fail(recent(0)), _root_session(recent(10), target="postgres")],
    ],
)
def test_sudo_sequence_negative_cases(env, lines):
    ingest(env, "ssh", lines())
    assert alerts(env) == []


# --- behavioural anomalies ------------------------------------------------------------------------
def test_anomaly_off_hours_login_and_volume_spike(env):
    sc = sim.build_scenario(attacks=("anomaly",), baseline=False)
    totals = sim.send_all(
        env.client,
        f"https://testserver{API}/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    assert totals.rejected == 0
    found = by_rule(alerts(env))
    assert set(found) == {"VSA-0001", "VSA-0002"}
    assert found["VSA-0001"][0]["username"] == "dave"
    assert found["VSA-0002"][0]["source_ip"] == "198.51.100.77"


def test_normal_hours_logins_never_trip_the_anomaly_detector(env):
    sc = sim.build_scenario(attacks=(), baseline=True)
    sim.send_all(
        env.client,
        f"https://testserver{API}/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    assert alerts(env) == []


# --- every attack, mixed with benign traffic, through the API ------------------------------------------
@pytest.mark.parametrize("name", sim.ATTACKS)
def test_each_simulated_attack_is_detected_without_collateral_alerts(env, name):
    sc = sim.build_scenario(attacks=(name,), baseline=True)
    sim.send_all(
        env.client,
        f"https://testserver{API}/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    verdict = sim.judge(alerts(env), sc)
    assert verdict.ok, (name, verdict.missing, verdict.unexpected)
    assert set(verdict.found) == sim.EXPECTED_RULES[name]


def test_alerts_are_filterable_and_triageable_after_detection(env):
    sc = sim.build_scenario()
    sim.send_all(
        env.client,
        f"https://testserver{API}/ingest",
        env.api_key,
        sim.make_batches(sc, 100),
        delay=0,
        out=lambda _: None,
    )
    crit = alerts(env, severity="critical")
    assert crit and {a["severity"] for a in crit} == {"critical"}
    assert {a["rule_id"] for a in crit} == {"VSR-1003"}
    assert alerts(env, status="resolved") == []
    detail = env.client.get(f"{API}/alerts/{crit[0]['id']}").json()
    assert detail["events"] and detail["rule_id"] == "VSR-1003"
