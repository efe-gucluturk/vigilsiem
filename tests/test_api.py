from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import pytest

from conftest import ADMIN_PASSWORD, ADMIN_USER, PUBLIC_IP
from helpers import nginx_line, ssh_failed

API = "/api/v1"


def now(offset: float = 0) -> datetime:
    return datetime.now(UTC) + timedelta(seconds=offset)


def ssh_batch(n: int = 6, ip: str = "203.0.113.9", user: str = "root") -> dict:
    base = now(-30)
    return {
        "source_type": "ssh",
        "host": "web01",
        "lines": [ssh_failed(base + timedelta(seconds=i), ip=ip, user=user) for i in range(n)],
    }


def post_ingest(env, body, key=None, **kw):
    return env.client.post(f"{API}/ingest", json=body, headers=env.headers(key), **kw)


def assert_clean_error(resp, status: int, code: str | None = None):
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"} and "code" in body["error"] and "message" in body["error"]
    assert code is None or body["error"]["code"] == code
    text = resp.text
    assert "Traceback" not in text and "sqlalchemy" not in text.lower() and ".py" not in text


# --- ingest: authentication -----------------------------------------------------------------
def test_ingest_requires_valid_api_key(env):
    body = ssh_batch(1)
    assert_clean_error(env.client.post(f"{API}/ingest", json=body), 401, "unauthorized")
    for bad in ("", "nope", "vsk_" + "0" * 12 + ".garbage", "A" * 500):
        r = env.client.post(f"{API}/ingest", json=body, headers={"X-API-Key": bad})
        assert_clean_error(r, 401)
    assert_clean_error(post_ingest(env, body, key=env.revoked_key), 401)
    # right prefix, wrong secret
    forged = env.api_key.split(".")[0] + ".forged-secret"
    assert_clean_error(post_ingest(env, body, key=forged), 401)
    assert post_ingest(env, body).status_code == 200


def test_auth_checked_before_body_validation(env):
    r = env.client.post(
        f"{API}/ingest", content=b"{not json", headers={"Content-Type": "application/json"}
    )
    assert r.status_code == 401  # unauthenticated callers learn nothing about the schema


def test_admin_cookie_is_not_accepted_on_ingest_and_key_not_on_admin(env):
    env.login()
    assert env.client.post(f"{API}/ingest", json=ssh_batch(1)).status_code == 401
    env.client.cookies.clear()
    assert env.client.get(f"{API}/alerts", headers=env.headers()).status_code == 401


def test_failed_key_guessing_is_throttled(env):
    codes = [
        env.client.post(
            f"{API}/ingest", json=ssh_batch(1), headers={"X-API-Key": f"bad{i}"}
        ).status_code
        for i in range(25)
    ]
    assert codes[:20] == [401] * 20 and set(codes[20:]) == {429}
    # throttled even for a valid key until the window passes
    assert post_ingest(env, ssh_batch(1)).status_code == 429


# --- ingest: validation / hardening ----------------------------------------------------------------
@pytest.mark.parametrize(
    "body",
    [
        {"source_type": "ssh", "host": "h", "lines": ["x"], "extra": 1},
        {"source_type": "bogus", "host": "h", "lines": ["x"]},
        {"source_type": "ssh", "host": "h; rm -rf /", "lines": ["x"]},
        {"source_type": "ssh", "host": "h", "lines": []},
        {"source_type": "ssh", "host": "h", "lines": ["x" * 9000]},
        {"source_type": "ssh", "host": "h", "lines": [1, 2]},
        {"source_type": "ssh", "lines": ["x"]},
        ["not", "an", "object"],
    ],
)
def test_ingest_rejects_invalid_bodies(env, body):
    assert_clean_error(post_ingest(env, body), 422, "validation_error")


def test_ingest_content_type_and_garbage(env):
    r = env.client.post(
        f"{API}/ingest", content=b"x=1", headers={**env.headers(), "Content-Type": "text/plain"}
    )
    assert_clean_error(r, 415)
    r = env.client.post(
        f"{API}/ingest",
        content=b"\xff\xfe{",
        headers={**env.headers(), "Content-Type": "application/json"},
    )
    assert_clean_error(r, 422)


def test_oversized_payload_gets_413(env):
    big = {"source_type": "json", "host": "h", "lines": ["a" * 8000 for _ in range(70)]}  # > 512 KB
    r = post_ingest(env, big)
    assert_clean_error(r, 413, "payload_too_large")
    assert r.headers["x-content-type-options"] == "nosniff"  # headers survive early rejection

    def chunks():  # no Content-Length: must be cut off while streaming
        for _ in range(100):
            yield b"a" * 8192

    r = env.client.post(
        f"{API}/ingest",
        content=chunks(),
        headers={**env.headers(), "Content-Type": "application/json"},
    )
    assert r.status_code == 413


def test_batch_line_cap(tmp_path):
    from conftest import make_env

    gen = make_env(tmp_path, max_batch_lines=5)
    e = next(gen)
    try:
        assert_clean_error(post_ingest(e, ssh_batch(6)), 413, "batch_too_large")
    finally:
        gen.close()


def test_ingest_rate_limit_per_key(tight_env):
    env = tight_env
    assert [post_ingest(env, ssh_batch(1)).status_code for _ in range(3)] == [200] * 3
    r = post_ingest(env, ssh_batch(1))
    assert_clean_error(r, 429, "rate_limited")
    assert 1 <= int(r.headers["retry-after"]) <= 60
    assert post_ingest(env, ssh_batch(1), key=env.other_key).status_code == 200  # isolated


def test_injection_payloads_are_stored_inertly(env):
    evil = "x';DROP/**/TABLE/**/events;--"
    r = post_ingest(env, ssh_batch(6, user=evil))
    assert r.status_code == 200 and r.json()["accepted"] == 6
    env.login()
    alerts = env.client.get(f"{API}/alerts").json()
    assert alerts and alerts[0]["username"] == evil
    detail = env.client.get(f"{API}/alerts/{alerts[0]['id']}").json()
    assert len(detail["events"]) == 5 and evil in detail["events"][0]["raw_log"]
    assert post_ingest(env, ssh_batch(1)).status_code == 200  # tables intact


def test_partial_batch_rejections_are_counted_not_echoed(env):
    body = {"source_type": "ssh", "host": "h", "lines": ["garbage-TOPSECRET", ssh_failed(now())]}
    r = post_ingest(env, body)
    assert r.json() == {"accepted": 1, "rejected": 1, "alerts_created": 0}
    assert "TOPSECRET" not in r.text


# --- admin auth -----------------------------------------------------------------------------------------
def test_login_cookie_flags_and_generic_failures(env):
    r = env.client.post(
        f"{API}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD}
    )
    assert r.status_code == 200 and len(r.json()["csrf_token"]) == 64
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "Secure" in cookie and "SameSite=strict" in cookie
    env.client.cookies.clear()
    wrong = env.client.post(
        f"{API}/auth/login", json={"username": ADMIN_USER, "password": "wrong-password"}
    )
    ghost = env.client.post(
        f"{API}/auth/login", json={"username": "nobody", "password": "wrong-password"}
    )
    assert wrong.status_code == ghost.status_code == 401
    assert wrong.json() == ghost.json()  # no user-enumeration oracle
    assert "set-cookie" not in wrong.headers


def test_login_bruteforce_throttled_per_ip(env):
    codes = [
        env.client.post(
            f"{API}/auth/login", json={"username": ADMIN_USER, "password": f"guess-{i}"}
        ).status_code
        for i in range(7)
    ]
    assert codes == [401] * 5 + [429] * 2
    r = env.client.post(
        f"{API}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD}
    )
    assert r.status_code == 429 and "retry-after" in r.headers  # even the right password is refused


def test_login_validation(env):
    for body in (
        {"username": "a", "password": "x"},
        {"username": ADMIN_USER},
        {"username": ADMIN_USER, "password": "x" * 500},
        {"username": ADMIN_USER, "password": "x", "admin": True},
    ):
        assert env.client.post(f"{API}/auth/login", json=body).status_code == 422


PROTECTED_GET = [
    "/api/v1/alerts",
    "/api/v1/alerts/1",
    "/api/v1/stats",
    "/api/v1/rules",
    "/api/v1/webhooks",
    "/ui/metrics",
    "/ui/alerts",
    "/ui/alerts/1",
]


@pytest.mark.parametrize("path", PROTECTED_GET)
def test_unauthenticated_routes_denied(env, path):
    assert env.client.get(path).status_code == 401


@pytest.mark.parametrize("path", ["/", "/rules", "/webhooks"])
def test_unauthenticated_pages_redirect_to_login(env, path):
    r = env.client.get(path, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"


@pytest.mark.parametrize(
    ("method", "path"),
    [
        ("PATCH", "/api/v1/alerts/1"),
        ("POST", "/api/v1/rules/reload"),
        ("POST", "/api/v1/webhooks"),
        ("DELETE", "/api/v1/webhooks/1"),
        ("POST", "/api/v1/auth/logout"),
        ("POST", "/ui/alerts/1/status"),
        ("POST", "/ui/rules/reload"),
        ("POST", "/ui/webhooks"),
        ("DELETE", "/ui/webhooks/1"),
        ("POST", "/ui/logout"),
    ],
)
def test_unauthenticated_writes_denied(env, method, path):
    assert env.client.request(method, path).status_code == 401


def test_forged_and_tampered_cookies_rejected(env):
    import base64
    import json

    env.login()
    good = env.client.cookies.get("vigil_session")
    assert env.client.get(f"{API}/stats").status_code == 200
    head, payload, sig = good.split(".")
    none_hdr = (
        base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
        .rstrip(b"=")
        .decode()
    )
    claims = json.loads(base64.urlsafe_b64decode(payload + "=="))
    forged_payload = (
        base64.urlsafe_b64encode(json.dumps({**claims, "sub": "root"}).encode())
        .rstrip(b"=")
        .decode()
    )
    for bad in (
        f"{none_hdr}.{payload}.",
        f"{head}.{forged_payload}.{sig}",
        good[:-3] + "AAA",
        "garbage",
        "a.b.c",
    ):
        env.client.cookies.clear()
        env.client.cookies.set("vigil_session", bad)
        assert env.client.get(f"{API}/stats").status_code == 401, bad


def test_logout_revokes_the_session_server_side(env):
    csrf = env.login()
    stolen = env.client.cookies.get("vigil_session")
    assert env.client.post(f"{API}/auth/logout", headers={"X-CSRF-Token": csrf}).status_code == 204
    env.client.cookies.set("vigil_session", stolen)  # replay the old token
    assert env.client.get(f"{API}/stats").status_code == 401


def test_openapi_and_docs_disabled(env):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert env.client.get(path).status_code == 404


def test_security_headers_on_every_kind_of_response(env):
    for resp in (
        env.client.get("/healthz"),
        env.client.get("/nope"),
        env.client.get(f"{API}/stats"),
        env.client.get("/login"),
        env.client.get("/static/css/app.css"),
    ):
        h = resp.headers
        assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"
        assert h["referrer-policy"] == "no-referrer" and "strict-transport-security" in h
        csp = h["content-security-policy"]
        assert (
            "script-src 'self'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
        )
        assert "server" not in h


def test_unhandled_exception_is_sanitized(env):
    @env.app.get("/boom")
    async def boom():
        raise RuntimeError("secret internal path C:\\Users\\x\\app.py SELECT * FROM users")

    r = env.client.get("/boom")
    assert_clean_error(r, 500, "internal_error")
    assert "secret" not in r.text and "SELECT" not in r.text


# --- CSRF + triage ------------------------------------------------------------------------------------------------
def seeded_alert(env) -> int:
    assert post_ingest(env, ssh_batch(6)).json()["alerts_created"] >= 1
    return env.client.get(f"{API}/alerts").json()[0]["id"]


def test_csrf_required_on_state_changing_routes(env):
    csrf = env.login()
    post_ingest(env, ssh_batch(6))
    aid = env.client.get(f"{API}/alerts").json()[0]["id"]
    url, body = f"{API}/alerts/{aid}", {"status": "investigating"}
    assert_clean_error(env.client.patch(url, json=body), 403, "csrf_failed")
    assert env.client.patch(url, json=body, headers={"X-CSRF-Token": "0" * 64}).status_code == 403
    assert (
        env.client.patch(
            url, json=body, headers={"X-CSRF-Token": csrf, "Origin": "https://evil.example"}
        ).status_code
        == 403
    )
    ok = env.client.patch(
        url, json=body, headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"}
    )
    assert ok.status_code == 200 and ok.json()["status"] == "investigating"


def test_csrf_token_is_bound_to_the_session(env):
    env.login()
    other_csrf = None
    env.client.cookies.clear()
    other_csrf = env.login()  # a second, different session
    env.client.cookies.clear()
    env.login()
    aid = seeded_alert(env)
    r = env.client.patch(
        f"{API}/alerts/{aid}", json={"status": "resolved"}, headers={"X-CSRF-Token": other_csrf}
    )
    assert r.status_code == 403


def test_triage_flow_filters_and_validation(env):
    csrf = env.login()
    aid = seeded_alert(env)
    h = {"X-CSRF-Token": csrf}
    for status in ("investigating", "resolved", "false_positive", "open"):
        r = env.client.patch(f"{API}/alerts/{aid}", json={"status": status}, headers=h)
        assert r.json()["status"] == status
    env.client.patch(f"{API}/alerts/{aid}", json={"status": "resolved"}, headers=h)
    assert len(env.client.get(f"{API}/alerts", params={"status": "resolved"}).json()) == 1
    assert env.client.get(f"{API}/alerts", params={"status": "open"}).json() == []
    assert len(env.client.get(f"{API}/alerts", params={"severity": "high"}).json()) == 1
    for bad in ({"status": "deleted"}, {"status": "open", "severity": "low"}, {}):
        assert env.client.patch(f"{API}/alerts/{aid}", json=bad, headers=h).status_code == 422
    for q in ({"severity": "extreme"}, {"limit": 0}, {"limit": 9999}, {"offset": -1}):
        assert env.client.get(f"{API}/alerts", params=q).status_code == 422
    assert env.client.get(f"{API}/alerts/abc").status_code == 422
    assert env.client.get(f"{API}/alerts/0").status_code == 422
    assert_clean_error(env.client.get(f"{API}/alerts/99999"), 404, "not_found")
    assert (
        env.client.patch(f"{API}/alerts/99999", json={"status": "open"}, headers=h).status_code
        == 404
    )


def test_alert_detail_has_events_rule_and_mitre(env):
    env.login()
    aid = seeded_alert(env)
    d = env.client.get(f"{API}/alerts/{aid}").json()
    assert (
        d["rule_id"] == "VSR-1001"
        and d["mitre_technique"] == "T1110"
        and d["mitre_tactic"] == "Credential Access"
    )
    assert (
        d["mitre_technique_name"] == "Brute Force"
        and "threshold" in d["rule_source"]
        and len(d["events"]) == 5
    )
    assert set(d) >= {"id", "severity", "status", "summary", "created_at"}


def test_stats_and_rule_hit_counts(env):
    env.login()
    seeded_alert(env)
    post_ingest(
        env,
        {
            "source_type": "nginx",
            "host": "w",
            "lines": [nginx_line(now(), uri="/i?id=1%20UNION%20SELECT%201", ip="198.51.100.77")],
        },
    )
    s = env.client.get(f"{API}/stats").json()
    assert (
        s["active_by_severity"]["high"] >= 2 and s["total_events"] >= 7 and s["events_per_sec"] > 0
    )
    assert s["top_ips"][0][1] >= 1 and any(t[0].startswith("T1190") for t in s["top_techniques"])
    rules = {r["id"]: r for r in env.client.get(f"{API}/rules").json()}
    assert rules["VSR-1001"]["hits"] >= 1 and rules["VSR-2001"]["hits"] == 1


# --- rules reload -----------------------------------------------------------------------------------------------------------
def test_rules_reload_validates_and_keeps_old_rules_on_error(env):
    csrf = env.login()
    h = {"X-CSRF-Token": csrf}
    assert env.client.post(f"{API}/rules/reload", headers=h).json() == {"loaded": 8}
    assert env.client.post(f"{API}/rules/reload").status_code == 403
    (env.rules_dir / "evil.yml").write_text("!!python/object/apply:os.system ['calc']")
    r = env.client.post(f"{API}/rules/reload", headers=h)
    assert_clean_error(r, 400, "rules_invalid")
    assert len(env.client.get(f"{API}/rules").json()) == 8  # still serving the old set
    (env.rules_dir / "evil.yml").unlink()


# --- webhooks / SSRF ------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/T/B/X",
        "https://127.0.0.1/hook",
        "https://10.0.0.5/hook",
        "https://172.16.5.5/x",
        "https://192.168.1.10/x",
        "https://169.254.169.254/latest/meta-data/",
        "https://[::1]/x",
        "https://[::ffff:7f00:1]/x",
        "https://hooks.slack.com:8443/x",
        "https://user:pw@hooks.slack.com/x",
        "file:///etc/passwd",
        "gopher://hooks.slack.com/x",
    ],
)
def test_webhook_ssrf_blocked_at_configuration(env, url):
    csrf = env.login()
    r = env.client.post(
        f"{API}/webhooks", json={"name": "x", "url": url}, headers={"X-CSRF-Token": csrf}
    )
    assert r.status_code == 422 and r.json()["error"]["code"] in {
        "unsafe_webhook_url",
        "validation_error",
    }
    assert env.client.get(f"{API}/webhooks").json() == []


def test_webhook_dns_to_private_ip_blocked(tmp_path):
    import httpx

    from conftest import make_env
    from vigilsiem.core.notifier import WebhookNotifier

    async def evil_resolver(_h, _p):
        return ["169.254.169.254"]

    gen = make_env(tmp_path)
    e = next(gen)
    try:
        e.app.state.ctx.notifier = WebhookNotifier(
            resolver=evil_resolver, transport=httpx.MockTransport(lambda r: httpx.Response(204))
        )
        csrf = e.login()
        r = e.client.post(
            f"{API}/webhooks",
            json={"name": "x", "url": "https://metadata.attacker.example/x"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 422 and r.json()["error"]["code"] == "unsafe_webhook_url"
    finally:
        gen.close()


def test_webhook_lifecycle_and_secret_never_returned(env):
    csrf = env.login()
    h = {"X-CSRF-Token": csrf}
    secret_url = "https://hooks.slack.com/services/T000/B000/SUPERSECRETTOKEN"
    r = env.client.post(f"{API}/webhooks", json={"name": "soc", "url": secret_url}, headers=h)
    assert (
        r.status_code == 201
        and "SUPERSECRET" not in r.text
        and r.json()["url_masked"].startswith("https://hooks.slack.com")
    )
    assert "SUPERSECRET" not in env.client.get(f"{API}/webhooks").text
    assert (
        env.client.post(
            f"{API}/webhooks", json={"name": "soc", "url": secret_url}, headers=h
        ).status_code
        == 409
    )
    low = {"name": "low", "url": secret_url, "min_severity": "low"}
    assert env.client.post(f"{API}/webhooks", json=low, headers=h).status_code == 422
    assert (
        env.client.post(
            f"{API}/webhooks", json={"name": "bad name!", "url": secret_url}, headers=h
        ).status_code
        == 422
    )
    wid = r.json()["id"]
    assert env.client.delete(f"{API}/webhooks/{wid}", headers=h).status_code == 204
    assert env.client.delete(f"{API}/webhooks/{wid}", headers=h).status_code == 404


def test_alert_delivery_is_pinned_sanitized_and_redirect_free(env):
    csrf = env.login()
    url = "https://hooks.slack.com/services/T000/B000/TOKEN"
    env.client.post(
        f"{API}/webhooks", json={"name": "soc", "url": url}, headers={"X-CSRF-Token": csrf}
    )
    assert post_ingest(env, ssh_batch(6, user="@everyone")).json()["alerts_created"] == 1
    assert len(env.sent) == 1
    req = env.sent[0]
    assert req.url.host == PUBLIC_IP  # connected to the validated address, not re-resolved
    assert req.headers["host"] == "hooks.slack.com" and req.url.path == "/services/T000/B000/TOKEN"
    text = __import__("json").loads(req.content)["text"]
    assert "[HIGH] SSH Brute Force" in text and "T1110" in text
    assert "@everyone" not in text


async def test_notifier_refuses_private_targets_at_dispatch_time():
    import httpx

    from helpers import RULES_DIR, at, events
    from helpers import ssh_failed as sf
    from vigilsiem.core.notifier import WebhookNotifier, build_payload
    from vigilsiem.engine.correlation import RuleEngine
    from vigilsiem.models.enums import SourceType

    calls = []

    async def rebinding_resolver(_h, _p):
        return ["10.0.0.7"]  # DNS now points inside the network

    notifier = WebhookNotifier(
        resolver=rebinding_resolver,
        transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(204)),
    )
    eng = RuleEngine.from_directory(RULES_DIR)
    det = next(
        d for e in events(SourceType.SSH, [sf(at(i)) for i in range(5)]) for d in eng.evaluate(e)
    )
    assert await notifier.send("https://hooks.slack.com/services/x", det) is False
    assert calls == []
    assert "content" in build_payload("https://discord.com/api/webhooks/1/abc", det)
    assert "text" in build_payload("https://hooks.slack.com/services/x", det)


# --- dashboard ------------------------------------------------------------------------------------------------------------------------
def form_login(env, password=ADMIN_PASSWORD):
    return env.client.post(
        "/login", data={"username": ADMIN_USER, "password": password}, follow_redirects=False
    )


def test_login_form_flow(env):
    assert env.client.get("/login").status_code == 200
    bad = form_login(env, "wrong-password")
    assert (
        bad.status_code == 401
        and "Invalid credentials" in bad.text
        and "set-cookie" not in bad.headers
    )
    ok = form_login(env)
    assert (
        ok.status_code == 303
        and ok.headers["location"] == "/"
        and "HttpOnly" in ok.headers["set-cookie"]
    )
    page = env.client.get("/")
    assert page.status_code == 200 and "Security Overview" in page.text
    assert env.client.get("/login", follow_redirects=False).status_code == 303


def test_dashboard_html_is_csp_clean(env):
    form_login(env)
    for path in ("/", "/rules", "/webhooks", "/login"):
        html = env.client.get(path).text
        assert not re.search(r"<script(?![^>]*\bsrc=)", html), path  # no inline scripts
        assert not re.search(r"\sstyle\s*=", html), path  # no inline styles
        assert not re.search(r"\son(click|load|error)\s*=", html, re.I), path
        assert (
            "//cdn" not in html
            and "http://" not in html
            and "https://" not in html.replace("https://hooks", "")
        )
    assert 'hx-headers=\'{"X-CSRF-Token": "' in env.client.get("/").text


def test_dashboard_fragments_and_rendering(env):
    form_login(env)
    post_ingest(env, ssh_batch(6, ip="203.0.113.50"))
    assert (
        "203.0.113.50" in env.client.get("/ui/metrics").text
        and "Top MITRE techniques" in env.client.get("/ui/metrics").text
    )
    feed = env.client.get("/ui/alerts")
    assert "SSH Brute Force" in feed.text and "T1110" in feed.text and "sev-high" in feed.text
    assert (
        "SSH Brute Force" not in env.client.get("/ui/alerts", params={"severity": "critical"}).text
    )
    assert env.client.get("/ui/alerts", params={"severity": "bogus"}).status_code == 422
    aid = re.search(r"/ui/alerts/(\d+)", feed.text).group(1)
    detail = env.client.get(f"/ui/alerts/{aid}")
    assert detail.headers["hx-trigger"] == "open-detail"
    assert (
        "Failed password for root" in detail.text
        and "id: VSR-1001" in detail.text
        and "Credential Access" in detail.text
    )
    rules = env.client.get("/rules").text
    assert "VSR-2001" in rules and "SQL Injection Probe" in rules and "Reload rules" in rules


def test_dashboard_escapes_attacker_controlled_content(env):
    form_login(env)
    xss_user = "<svg/onload=alert(1)>"
    post_ingest(env, ssh_batch(6, user=xss_user))
    web_line = nginx_line(now(), uri="/s?q=<script>alert(1)</script>", ip="198.51.100.66")
    post_ingest(env, {"source_type": "nginx", "host": "w", "lines": [web_line]})
    pages = [env.client.get("/ui/alerts").text]
    for aid in set(re.findall(r"/ui/alerts/(\d+)", pages[0])):
        pages.append(env.client.get(f"/ui/alerts/{aid}").text)
    blob = "\n".join(pages)
    assert "&lt;svg/onload=alert(1)&gt;" in blob and "&lt;script&gt;alert(1)" in blob
    assert "<svg/onload" not in blob and "<script>alert" not in blob


def test_ui_triage_requires_csrf_and_updates(env):
    form_login(env)
    aid = seeded_alert(env)
    token = re.search(r'"X-CSRF-Token": "([0-9a-f]{64})"', env.client.get("/").text).group(1)
    assert (
        env.client.post(f"/ui/alerts/{aid}/status", data={"status": "resolved"}).status_code == 403
    )
    r = env.client.post(
        f"/ui/alerts/{aid}/status", data={"status": "resolved"}, headers={"X-CSRF-Token": token}
    )
    assert r.status_code == 200 and "status-resolved" in r.text
    assert (
        env.client.post(
            f"/ui/alerts/{aid}/status", data={"status": "nope"}, headers={"X-CSRF-Token": token}
        ).status_code
        == 422
    )


def test_ui_webhook_form_shows_ssrf_error_and_masks_urls(env):
    form_login(env)
    token = re.search(r'"X-CSRF-Token": "([0-9a-f]{64})"', env.client.get("/").text).group(1)
    h = {"X-CSRF-Token": token}
    bad = env.client.post(
        "/ui/webhooks",
        data={"name": "meta", "url": "https://169.254.169.254/x", "min_severity": "high"},
        headers=h,
    )
    assert (
        bad.status_code == 200
        and "rejected" in bad.text
        and "169.254.169.254" not in bad.text.split("rejected")[0]
    )
    good = env.client.post(
        "/ui/webhooks",
        data={
            "name": "ok",
            "url": "https://discord.com/api/webhooks/1/SECRETTOKEN",
            "min_severity": "critical",
        },
        headers=h,
    )
    assert "SECRETTOKEN" not in good.text and "https://discord.com/…" in good.text
    assert "SECRETTOKEN" not in env.client.get("/webhooks").text


def test_ui_logout_clears_cookie_and_revokes(env):
    form_login(env)
    token = re.search(r'"X-CSRF-Token": "([0-9a-f]{64})"', env.client.get("/").text).group(1)
    r = env.client.post("/ui/logout", headers={"X-CSRF-Token": token})
    assert r.status_code == 204 and r.headers["hx-redirect"] == "/login"
    assert env.client.get("/", follow_redirects=False).status_code == 303


def test_deleting_admin_user_invalidates_sessions(env):
    import asyncio

    from sqlalchemy import delete

    from vigilsiem.models.orm import AdminUser

    env.login()
    ctx = env.app.state.ctx

    async def wipe():
        from vigilsiem.core.db import Database

        db = Database(env.settings.database_url)
        async with db.session() as s:
            await s.execute(delete(AdminUser))
        await db.dispose()

    asyncio.run(wipe())
    assert env.client.get(f"{API}/stats").status_code == 401
    assert ctx is not None
