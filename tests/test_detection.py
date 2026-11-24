from __future__ import annotations

from datetime import timedelta

import pytest

from helpers import NOW, RULES_DIR, at, events, nginx_line, ssh_failed, ssh_ok
from vigilsiem.engine.correlation import RuleEngine
from vigilsiem.engine.pipeline import DetectionPipeline
from vigilsiem.models.enums import Severity, SourceType

SSH, WEB = SourceType.SSH, SourceType.NGINX


@pytest.fixture
def engine() -> RuleEngine:
    return RuleEngine.from_directory(RULES_DIR)


def run(engine: RuleEngine, evs):
    out = []
    for e in evs:
        out.extend(engine.evaluate(e))
    return out


def ids(dets):
    return [d.rule_id for d in dets]


# --- SSH brute force (threshold) ---------------------------------------------------
def test_bruteforce_fires_exactly_at_fifth_failure(engine):
    evs = events(SSH, [ssh_failed(at(i * 5)) for i in range(5)])
    assert ids(run(engine, evs[:4])) == []
    dets = run(engine, evs[4:])
    assert ids(dets) == ["VSR-1001"]
    d = dets[0]
    assert d.severity is Severity.HIGH and d.source_ip == "203.0.113.9"
    assert (d.mitre_tactic, d.mitre_technique_id) == ("Credential Access", "T1110")
    assert len(d.events) == 5


def test_bruteforce_respects_window_and_ip_isolation(engine):
    slow = events(SSH, [ssh_failed(at(i * 20)) for i in range(8)])  # 1 per 20s -> max 3-4 per 60s
    assert "VSR-1001" not in ids(run(engine, slow))
    mixed = events(SSH, [ssh_failed(at(i), ip=f"203.0.113.{i}") for i in range(10)])
    assert run(engine, mixed) == []


def test_bruteforce_cooldown_prevents_alert_flood(engine):
    evs = events(SSH, [ssh_failed(at(i)) for i in range(40)])  # 40 failures in 40s
    assert ids(run(engine, evs)).count("VSR-1001") == 1


def test_bruteforce_realerts_after_window(engine):
    wave1 = events(SSH, [ssh_failed(at(i)) for i in range(6)])
    wave2 = events(SSH, [ssh_failed(at(600 + i)) for i in range(6)])
    assert ids(run(engine, wave1 + wave2)).count("VSR-1001") == 2


def test_out_of_window_old_event_ignored(engine):
    evs = events(SSH, [ssh_failed(at(1000 + i)) for i in range(4)] + [ssh_failed(at(0))])
    assert run(engine, evs) == []


# --- password spraying (distinct) ------------------------------------------------------
def test_password_spraying(engine):
    users = ["alice", "bob", "carol", "dave"]
    evs = events(SSH, [ssh_failed(at(i * 30), user=u) for i, u in enumerate(users)])
    assert ids(run(engine, evs)) == ["VSR-1002"]


def test_same_user_repeated_is_not_spraying(engine):
    evs = events(SSH, [ssh_failed(at(i * 10), user="alice") for i in range(4)])
    assert "VSR-1002" not in ids(run(engine, evs))


# --- sudo escalation (sequence) ---------------------------------------------------------
def sudo_fail(ts, user="mallory"):
    return f"Nov 24 {ts:%H:%M:%S} h sudo: {user} : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/bash"


def root_session(ts, user="mallory", target="root"):
    return f"Nov 24 {ts:%H:%M:%S} h sudo: pam_unix(sudo:session): session opened for user {target} by {user}(uid=1001)"


def test_sudo_failure_then_root_session_fires(engine):
    evs = events(SSH, [sudo_fail(at(0)), root_session(at(40))])
    dets = run(engine, evs)
    assert ids(dets) == ["VSR-1003"]
    assert dets[0].severity is Severity.CRITICAL and dets[0].username == "mallory"
    assert dets[0].mitre_technique_id == "T1548.003"


def test_sequence_negative_cases(engine):
    # wrong order
    assert run(engine, events(SSH, [root_session(at(0)), sudo_fail(at(10))])) == []
    # too late
    assert run(engine, events(SSH, [sudo_fail(at(0)), root_session(at(400))])) == []
    # different user
    assert run(engine, events(SSH, [sudo_fail(at(0)), root_session(at(10), user="other")])) == []
    # non-root target
    assert (
        run(engine, events(SSH, [sudo_fail(at(0)), root_session(at(10), target="postgres")])) == []
    )


# --- web signatures ------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("uri", "rule"),
    [
        ("/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users", "VSR-2001"),
        ("/item?id=1'%20OR%20'1'='1", "VSR-2001"),
        ("/item?id=1%2527%2520OR%25201=1--", None),  # double-encoded; see below
        ("/q?x=1;SELECT+SLEEP(5)--", "VSR-2001"),
        ("/search?q=<script>alert(1)</script>", "VSR-2002"),
        ("/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "VSR-2002"),
        ("/p?u=javascript:alert(1)", "VSR-2002"),
        ("/download?f=../../../../etc/passwd", "VSR-2003"),
        ("/download?f=..%2f..%2f..%2fetc%2fpasswd", "VSR-2003"),
        ("/download?f=%252e%252e%252f%252e%252e%252fboot.ini", "VSR-2003"),
    ],
)
def test_web_signatures(engine, uri, rule):
    dets = run(engine, events(WEB, [nginx_line(at(0), uri=uri)]))
    if rule:
        assert rule in ids(dets), (uri, ids(dets))
        assert all(
            d.mitre_technique_id == "T1190"
            for d in dets
            if d.rule_id.startswith("VSR-20") and d.rule_id != "VSR-2004"
        )
    else:
        assert dets  # double-encoded SQLi still caught by some SQLi signature


def test_double_encoded_sqli_detected(engine):
    dets = run(engine, events(WEB, [nginx_line(at(0), uri="/i?id=1%2527%2520OR%25201%253D1")]))
    assert "VSR-2001" in ids(dets)


def test_scanner_user_agents(engine):
    for ua in (
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.1.6)",
        "Nmap Scripting Engine",
    ):
        dets = run(RuleEngine.from_directory(RULES_DIR), events(WEB, [nginx_line(at(0), ua=ua)]))
        assert "VSR-2004" in ids(dets), ua


def test_benign_traffic_produces_no_alerts(engine):
    lines = [
        nginx_line(at(i), uri=u)
        for i, u in enumerate(
            [
                "/",
                "/index.html",
                "/static/app.js",
                "/api/v1/items?page=2&sort=name",
                "/about",
                "/products/select-your-plan",
            ]
        )
    ]
    assert run(engine, events(WEB, lines)) == []
    assert run(engine, events(SSH, [ssh_ok(at(0)), ssh_failed(at(1)), ssh_ok(at(2))])) == []


def test_signature_dedupe_and_hit_counts(engine):
    uri = "/i?id=1%20UNION%20SELECT%201"
    evs = events(WEB, [nginx_line(at(i), uri=uri) for i in range(10)])
    dets = run(engine, evs)
    assert ids(dets).count("VSR-2001") == 1  # one alert per 60s per IP...
    hits = {r["id"]: r["hits"] for r in engine.describe()}
    assert hits["VSR-2001"] == 10  # ...but every match is counted


def test_error_flood(engine):
    evs = events(WEB, [nginx_line(at(i), uri=f"/x{i}", code=404) for i in range(20)])
    assert "VSR-2005" in ids(run(engine, evs))


def test_disabled_rule_not_evaluated(tmp_path):
    from vigilsiem.engine.rules import parse_rule_yaml

    spec = parse_rule_yaml((RULES_DIR / "ssh_bruteforce.yml").read_text() + "enabled: false\n")
    eng = RuleEngine([spec])
    assert run(eng, events(SSH, [ssh_failed(at(i)) for i in range(10)])) == []
    assert eng.describe()[0]["enabled"] is False


def test_describe_exposes_source_and_mitre(engine):
    row = next(r for r in engine.describe() if r["id"] == "VSR-1001")
    assert row["mitre_technique_id"] == "T1110" and "threshold" in row["source"]


def test_state_memory_is_bounded(engine, monkeypatch):
    import vigilsiem.engine.correlation as corr

    monkeypatch.setattr(corr, "MAX_KEYS_PER_RULE", 50)
    eng = RuleEngine.from_directory(RULES_DIR)
    for i in range(500):
        run(eng, events(SSH, [ssh_failed(at(i), ip=f"10.1.{i // 250}.{i % 250}")]))
    assert all(len(r._slots) <= 50 for r in eng._rules)


# --- end-to-end through pipeline ----------------------------------------------------------------
def test_pipeline_mixed_attack_traffic():
    pipe = DetectionPipeline(RuleEngine.from_directory(RULES_DIR))
    lines = [ssh_failed(at(i)) for i in range(6)]
    web = [nginx_line(at(10), uri="/x?a=1' or 1=1--", ip="198.51.100.99")]
    dets = pipe.process(events(SSH, lines) + events(WEB, web))
    assert {"VSR-1001", "VSR-2001"} <= set(ids(dets))
    assert all(d.timestamp >= NOW - timedelta(seconds=1) for d in dets)
