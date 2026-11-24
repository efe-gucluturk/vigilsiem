"""Adversarial API security suite (OWASP API Top 10 oriented).

Everything here attacks the running app over HTTP the way an outsider would. The route-coverage
tests discover routes from the live application, so a newly added endpoint is attacked
automatically instead of silently escaping the suite.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount

from conftest import PUBLIC_IP, make_env
from helpers import ssh_failed

API = "/api/v1"
UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
LOGIN_PATHS = {"/login", f"{API}/auth/login"}
SQLI = [
    "' OR '1'='1",
    "'; DROP TABLE alerts;--",
    "x' UNION SELECT key_hash FROM api_keys--",
    '" OR ""="',
    "1; SELECT pg_sleep(5)--",
    "' AND (SELECT COUNT(*) FROM sqlite_master)>0--",
    "\\'; EXEC xp_cmdshell('dir');--",
    "%27%20OR%201%3D1",
]
LEAKS = re.compile(
    r"traceback|sqlalchemy|sqlite|aiosqlite|syntax error|\.py\"|select .* from", re.I
)


def when(offset: float = 0) -> datetime:
    return datetime.now(UTC) - timedelta(seconds=60) + timedelta(seconds=offset)


def batch(lines=None, **over) -> dict:
    body = {"source_type": "ssh", "host": "web01", "lines": lines or [ssh_failed(when())]}
    body.update(over)
    return body


def post(env, body, key=None, **kw):
    return env.client.post(f"{API}/ingest", json=body, headers=env.headers(key), **kw)


def assert_no_leak(resp: httpx.Response) -> None:
    assert resp.status_code < 500, resp.text
    assert not LEAKS.search(resp.text), resp.text
    if resp.status_code >= 400 and "json" in resp.headers.get("content-type", ""):
        assert set(resp.json()) == {"error"}


def _walk(routes):
    for r in routes:
        if hasattr(r, "original_router"):
            yield from _walk(r.original_router.routes)
        else:
            yield r


def all_routes(app) -> list[tuple[str, str]]:
    found = []
    for r in _walk(app.router.routes):
        if isinstance(r, Mount) or not isinstance(r, APIRoute):
            continue
        for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
            found.append((m, re.sub(r"\{[^}]+\}", "1", r.path)))
    return found


def admin_routes(app, *, unsafe: bool) -> list[tuple[str, str]]:
    skip = LOGIN_PATHS | {f"{API}/ingest", "/healthz"}
    return [
        (m, p)
        for m, p in all_routes(app)
        if p not in skip and (m in UNSAFE) == unsafe and not p.startswith("/static")
    ]


# =================================================================================================
# 1. Invalid / hostile API keys
# =================================================================================================
@pytest.mark.parametrize(
    "key",
    [
        "",
        " ",
        "vsk_",
        "vsk_.",
        "vsk_000000000000.",
        "Bearer vsk_000000000000.abc",
        "vsk_000000000000.abc\x00",
        "vsk_‮000000000000.abc",
        "' OR '1'='1",
        "vsk_' OR 1=1--.abc",
        "A" * 4096,
        "../../etc/passwd",
        "null",
        "undefined",
    ],
)
def test_malformed_and_hostile_api_keys_are_rejected_cleanly(env, key):
    try:
        r = env.client.post(f"{API}/ingest", json=batch(), headers={"X-API-Key": key})
    except (UnicodeEncodeError, httpx.InvalidURL, ValueError):
        return  # the client itself refuses to put such a header on the wire
    assert r.status_code == 401, r.text
    assert r.json()["error"]["code"] == "unauthorized"
    assert not LEAKS.search(r.text)


def test_key_in_wrong_place_is_not_authentication(env):
    body = batch()
    for kwargs in (
        {"params": {"api_key": env.api_key}},
        {"headers": {"Authorization": f"Bearer {env.api_key}"}},
        {"headers": {"X-Api-Token": env.api_key}},
    ):
        assert env.client.post(f"{API}/ingest", json=body, **kwargs).status_code == 401


def test_revoked_and_unknown_keys_get_the_same_answer_as_wrong_secret(env):
    prefix = env.api_key.split(".")[0]
    responses = {
        "revoked": post(env, batch(), key=env.revoked_key),
        "unknown": post(env, batch(), key="vsk_ffffffffffff." + "z" * 40),
        "wrong-secret": post(env, batch(), key=f"{prefix}.{'z' * 40}"),
    }
    assert {r.status_code for r in responses.values()} == {401}
    assert len({r.text for r in responses.values()}) == 1  # no oracle for key existence


def test_valid_key_still_works_after_failed_attempts_from_other_clients(env):
    for i in range(5):
        post(env, batch(), key=f"vsk_{i:012d}.nope")
    assert post(env, batch()).status_code == 200


# =================================================================================================
# 2. SQL injection payloads in every field the API accepts
# =================================================================================================
def _db_intact(env) -> None:
    """Tables survive and the data plane still works after the attack."""
    assert post(env, batch()).status_code == 200
    env.login()
    assert env.client.get(f"{API}/stats").status_code == 200
    assert env.client.get(f"{API}/alerts").status_code == 200


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_ingest_fields(env, payload):
    for body in (
        batch(host=payload),
        batch(source_type=payload),
        batch(lines=[payload]),
        batch(lines=[ssh_failed(when(), user=payload)]),
        batch(
            lines=[f'{payload} - - [24/Nov/2026:12:00:00 +0000] "GET /{payload} HTTP/1.1" 200 1']
        ),
    ):
        assert_no_leak(post(env, body))
    _db_intact(env)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_login_fields(env, payload):
    for path in (f"{API}/auth/login",):
        r = env.client.post(path, json={"username": payload, "password": payload})
        assert r.status_code in {401, 422}, r.text
        assert_no_leak(r)
    r = env.client.post("/login", data={"username": payload, "password": payload})
    assert r.status_code in {200, 401, 422} and r.status_code < 500
    assert "vigil_session" not in env.client.cookies


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_query_and_path_parameters(env, payload):
    env.login()
    for params in (
        {"severity": payload},
        {"status": payload},
        {"limit": payload},
        {"offset": payload},
    ):
        r = env.client.get(f"{API}/alerts", params=params)
        assert r.status_code == 422, (params, r.text)
        assert_no_leak(r)
    for path in (f"{API}/alerts/{payload}", f"{API}/webhooks/{payload}", f"/ui/alerts/{payload}"):
        r = env.client.get(path)
        assert r.status_code in {404, 405, 422}, (path, r.status_code)
        assert_no_leak(r)
    _db_intact(env)


@pytest.mark.parametrize("payload", SQLI)
def test_sqli_in_admin_write_bodies(env, payload):
    csrf = env.login()
    h = {"X-CSRF-Token": csrf}
    r = env.client.post(
        f"{API}/webhooks",
        json={"name": payload, "url": f"https://hooks.example/{payload}"},
        headers=h,
    )
    assert r.status_code in {201, 422}, r.text
    assert_no_leak(r)
    r = env.client.patch(f"{API}/alerts/1", json={"status": payload}, headers=h)
    assert r.status_code in {404, 422}
    assert_no_leak(r)
    _db_intact(env)


def test_injected_values_are_returned_as_data_not_executed(env):
    evil = "x';DROP/**/TABLE/**/events;--"
    lines = [ssh_failed(when(i), user=evil) for i in range(6)]
    assert post(env, batch(lines)).status_code == 200
    env.login()
    (alert,) = env.client.get(f"{API}/alerts").json()
    assert alert["username"] == evil  # stored verbatim, bound as a parameter
    _db_intact(env)


# =================================================================================================
# 3. Payload size: 413
# =================================================================================================
def _raw(env, body: bytes, path=f"{API}/ingest", headers=None):
    h = {"Content-Type": "application/json", **(headers or {})}
    return env.client.post(path, content=body, headers=h)


def test_body_just_over_512kb_is_413_and_just_under_is_not(env):
    limit = env.settings.max_body_bytes
    assert limit == 512 * 1024
    over = b'{"pad":"' + b"a" * (limit + 1) + b'"}'
    r = _raw(env, over, headers=env.headers())
    assert r.status_code == 413 and r.json()["error"]["code"] == "payload_too_large"
    under = b'{"pad":"' + b"a" * (limit - 64) + b'"}'
    r = _raw(env, under, headers=env.headers())
    assert r.status_code != 413  # accepted by the size gate (then rejected by the schema)


def test_413_is_issued_before_authentication_and_parsing(env):
    r = _raw(env, b"{" + b"a" * (513 * 1024))  # no key, invalid JSON, too large
    assert r.status_code == 413
    assert not LEAKS.search(r.text)


@pytest.mark.parametrize(
    "path", [f"{API}/ingest", f"{API}/auth/login", "/login", f"{API}/webhooks"]
)
def test_size_limit_is_global_not_just_ingest(env, path):
    r = _raw(env, b"x" * (600 * 1024), path=path)
    assert r.status_code == 413


def test_lying_or_absent_content_length_cannot_bypass_the_limit(env):
    # Declares a small body but streams a huge one.
    def chunks():
        for _ in range(100):
            yield b"a" * 8192

    r = env.client.post(
        f"{API}/ingest",
        content=chunks(),
        headers={**env.headers(), "Content-Type": "application/json"},
    )
    assert r.status_code == 413
    # Declared huge, nothing actually sent.
    r = env.client.post(
        f"{API}/ingest",
        content=b"{}",
        headers={**env.headers(), "Content-Type": "application/json", "Content-Length": "9999999"},
    )
    assert r.status_code in {400, 413, 422}


def test_oversized_request_does_not_poison_the_connection(env):
    assert _raw(env, b"a" * (600 * 1024), headers=env.headers()).status_code == 413
    assert post(env, batch()).status_code == 200


def test_many_small_lines_cannot_exceed_the_batch_cap(tmp_path):
    gen = make_env(tmp_path, max_batch_lines=10)
    e = next(gen)
    try:
        r = post(e, batch([ssh_failed(when(i)) for i in range(11)]))
        assert r.status_code == 413 and r.json()["error"]["code"] == "batch_too_large"
    finally:
        gen.close()


# =================================================================================================
# 4. Sliding-window rate limits: 429 + Retry-After
# =================================================================================================
def test_ingest_default_limit_is_120_per_minute_per_key(env):
    assert env.settings.ingest_rate_per_min == 120
    codes = [post(env, batch()).status_code for _ in range(120)]
    assert codes == [200] * 120
    r = post(env, batch())
    assert r.status_code == 429 and r.json()["error"]["code"] == "rate_limited"
    assert 1 <= int(r.headers["retry-after"]) <= 60
    # another key has its own budget
    assert post(env, batch(), key=env.other_key).status_code == 200


def test_login_default_limit_is_5_per_minute_per_ip(env):
    assert env.settings.login_rate_per_min == 5
    bad = {"username": "analyst", "password": "wrong-password-123"}
    codes = [env.client.post(f"{API}/auth/login", json=bad).status_code for _ in range(5)]
    assert codes == [401] * 5
    r = env.client.post(f"{API}/auth/login", json=bad)
    assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 60
    # even the correct password is refused while throttled
    from conftest import ADMIN_PASSWORD, ADMIN_USER

    ok = {"username": ADMIN_USER, "password": ADMIN_PASSWORD}
    assert env.client.post(f"{API}/auth/login", json=ok).status_code == 429


def test_window_slides_instead_of_resetting_on_a_fixed_boundary(tight_env):
    env = tight_env
    clock = [1000.0]
    limiter = env.app.state.ctx.ingest_limiter
    limiter._clock = lambda: clock[0]
    limiter.reset()
    assert post(env, batch()).status_code == 200  # t=0
    clock[0] += 30
    assert post(env, batch()).status_code == 200  # t=30
    assert post(env, batch()).status_code == 200  # t=30  (3/3 used)
    assert post(env, batch()).status_code == 429
    clock[0] += 31  # t=61: only the first hit has aged out
    assert post(env, batch()).status_code == 200
    assert post(env, batch()).status_code == 429  # the two t=30 hits still count
    clock[0] += 30  # t=91: everything has aged out
    assert post(env, batch()).status_code == 200


def test_retry_after_shrinks_as_the_window_drains(tight_env):
    env = tight_env
    clock = [5000.0]
    limiter = env.app.state.ctx.ingest_limiter
    limiter._clock = lambda: clock[0]
    limiter.reset()
    for _ in range(3):
        assert post(env, batch()).status_code == 200
    first = int(post(env, batch()).headers["retry-after"])
    clock[0] += 40
    second = int(post(env, batch()).headers["retry-after"])
    assert second < first <= 60


def test_rejected_requests_do_not_extend_the_penalty(tight_env):
    env = tight_env
    clock = [9000.0]
    limiter = env.app.state.ctx.ingest_limiter
    limiter._clock = lambda: clock[0]
    limiter.reset()
    for _ in range(3):
        post(env, batch())
    for _ in range(50):  # hammering while limited must not push the window out
        assert post(env, batch()).status_code == 429
    clock[0] += 61
    assert post(env, batch()).status_code == 200


def test_spoofed_forwarded_for_cannot_dodge_the_login_limit(env):
    bad = {"username": "analyst", "password": "wrong-password-123"}
    codes = [
        env.client.post(
            f"{API}/auth/login", json=bad, headers={"X-Forwarded-For": f"198.51.100.{i}"}
        ).status_code
        for i in range(8)
    ]
    assert codes[:5] == [401] * 5 and set(codes[5:]) == {429}


def test_429_responses_carry_security_headers_and_no_internals(tight_env):
    env = tight_env
    for _ in range(3):
        post(env, batch())
    r = post(env, batch())
    assert r.status_code == 429
    assert r.headers["x-content-type-options"] == "nosniff"
    assert not LEAKS.search(r.text)


# =================================================================================================
# 5. SSRF: loopback / private / link-local / reserved destinations
# =================================================================================================
BLOCKED_URLS = [
    "https://127.0.0.1/h",
    "https://127.1/h",
    "https://2130706433/h",  # decimal 127.0.0.1
    "https://0x7f000001/h",  # hex
    "https://0177.0.0.1/h",  # octal
    "https://localhost/h",
    "https://LOCALHOST./h",
    "https://[::1]/h",
    "https://[::]/h",
    "https://[::ffff:127.0.0.1]/h",
    "https://[::ffff:a00:1]/h",
    "https://0.0.0.0/h",
    "https://10.0.0.1/h",
    "https://10.255.255.255/h",
    "https://172.16.0.1/h",
    "https://172.31.255.255/h",
    "https://192.168.0.1/h",
    "https://100.64.0.1/h",  # CGNAT
    "https://169.254.169.254/latest/meta-data/",  # cloud metadata
    "https://169.254.0.1/h",
    "https://[fe80::1]/h",  # IPv6 link-local
    "https://[fd00::1]/h",  # IPv6 unique local
    "https://[fd00:ec2::254]/h",  # AWS IPv6 metadata
    "https://224.0.0.1/h",  # multicast
    "https://240.0.0.1/h",  # reserved
    "https://255.255.255.255/h",
    "https://metadata.google.internal/h",
    "https://example.com@127.0.0.1/h",  # userinfo trick
    "https://127.0.0.1#@example.com/h",
    "http://example.com/h",  # not https
    "ftp://example.com/h",
    "file:///etc/passwd",
    "gopher://example.com/h",
    "javascript:alert(1)",
    "//example.com/h",
    "https:///h",
    "https://",
    "",
]


@pytest.mark.parametrize("url", BLOCKED_URLS)
def test_webhook_config_refuses_unsafe_destinations_via_api_and_ui(env, url):
    csrf = env.login()
    h = {"X-CSRF-Token": csrf}
    r = env.client.post(f"{API}/webhooks", json={"name": "t", "url": url}, headers=h)
    assert r.status_code == 422, (url, r.status_code, r.text)
    assert_no_leak(r)
    r = env.client.post("/ui/webhooks", data={"name": "t", "url": url}, headers=h)
    assert r.status_code in {200, 400, 422}
    assert env.client.get(f"{API}/webhooks").json() == [], url  # nothing was stored


@pytest.mark.parametrize(
    "answers",
    [
        ["127.0.0.1"],
        ["10.1.2.3"],
        ["169.254.169.254"],
        ["::1"],
        ["fe80::1"],
        ["::ffff:10.0.0.1"],
        [PUBLIC_IP, "10.0.0.5"],  # one poisoned record among good ones
        ["10.0.0.5", PUBLIC_IP],
        [],
    ],
)
def test_hostname_resolving_to_a_forbidden_address_is_refused(tmp_path, answers):
    gen = make_env(tmp_path, dns=answers)
    env = next(gen)
    try:
        csrf = env.login()
        r = env.client.post(
            f"{API}/webhooks",
            json={"name": "rebind", "url": "https://hooks.attacker.example/x"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 422, r.text
        assert env.client.get(f"{API}/webhooks").json() == []
        assert env.sent == []  # nothing was ever sent
    finally:
        gen.close()


def test_dispatch_time_revalidation_stops_dns_rebinding(tmp_path):
    """Public at configuration time, private by the time an alert fires."""
    answers = [PUBLIC_IP]
    gen = make_env(tmp_path, dns=answers)
    env = next(gen)
    try:
        csrf = env.login()
        r = env.client.post(
            f"{API}/webhooks",
            json={"name": "ok", "url": "https://hooks.example.org/x"},
            headers={"X-CSRF-Token": csrf},
        )
        assert r.status_code == 201, r.text
        control = [ssh_failed(when(i), ip="203.0.113.98") for i in range(6)]
        assert post(env, batch(control)).json()["alerts_created"] == 1
        assert len(env.sent) == 1 and env.sent[0].url.host == PUBLIC_IP  # control: delivery works
        env.sent.clear()
        answers[:] = ["169.254.169.254"]  # attacker flips the DNS record
        lines = [ssh_failed(when(i), ip="203.0.113.99") for i in range(6)]
        assert post(env, batch(lines)).json()["alerts_created"] == 1
        assert env.sent == []  # revalidated at dispatch time: nothing left the building
    finally:
        gen.close()


def test_ssrf_error_does_not_reveal_resolved_addresses(env):
    csrf = env.login()
    r = env.client.post(
        f"{API}/webhooks",
        json={"name": "x", "url": "https://169.254.169.254/latest"},
        headers={"X-CSRF-Token": csrf},
    )
    assert r.status_code == 422
    assert "169.254" not in r.json()["error"]["message"]


# =================================================================================================
# 6. Unauthenticated / missing-CSRF access to the dashboard and admin API
# =================================================================================================
def test_route_discovery_finds_the_expected_surface(env):
    routes = all_routes(env.app)
    assert len(routes) >= 26
    assert admin_routes(env.app, unsafe=True) and admin_routes(env.app, unsafe=False)


def test_every_admin_route_rejects_unauthenticated_requests(env):
    failures = []
    for unsafe in (False, True):
        for method, path in admin_routes(env.app, unsafe=unsafe):
            r = env.client.request(method, path, follow_redirects=False)
            page = method == "GET" and path in {"/", "/rules", "/webhooks"}
            expected = 303 if page else 401
            if r.status_code != expected:
                failures.append((method, path, r.status_code))
            if page:
                assert r.headers["location"] == "/login"
            else:
                assert_no_leak(r)
    assert not failures, failures


def test_every_state_changing_route_rejects_a_session_without_csrf(env):
    env.login()
    failures = []
    for method, path in admin_routes(env.app, unsafe=True):
        if path in {f"{API}/auth/logout", "/ui/logout"}:
            continue  # exercised separately: logging out must also require CSRF
        r = env.client.request(method, path, json={}, follow_redirects=False)
        if r.status_code != 403:
            failures.append((method, path, r.status_code))
    assert not failures, failures
    # and nothing was changed: still logged in, still no webhooks
    assert env.client.get(f"{API}/webhooks").json() == []


def test_logout_requires_csrf_and_a_forged_logout_does_not_end_the_session(env):
    env.login()
    assert env.client.post(f"{API}/auth/logout").status_code == 403
    assert env.client.post("/ui/logout", follow_redirects=False).status_code == 403
    assert env.client.get(f"{API}/stats").status_code == 200


def test_every_state_changing_route_rejects_a_wrong_or_foreign_csrf_token(env):
    csrf = env.login()
    bad_tokens = [
        "",
        "0" * 64,
        csrf[:-1] + ("0" if csrf[-1] != "0" else "1"),
        csrf + "x",
        "A" * 5000,
    ]
    for token in bad_tokens:
        for method, path in admin_routes(env.app, unsafe=True):
            r = env.client.request(
                method, path, json={}, headers={"X-CSRF-Token": token}, follow_redirects=False
            )
            assert r.status_code == 403, (method, path, token[:8], r.status_code)


def test_csrf_token_in_body_or_query_is_not_a_substitute_for_the_header(env):
    csrf = env.login()
    r = env.client.post(
        f"{API}/webhooks",
        params={"csrf_token": csrf},
        json={"name": "x", "url": "https://hooks.example.org/x", "csrf_token": csrf},
    )
    assert r.status_code in {403, 422}
    assert env.client.get(f"{API}/webhooks").json() == []


def test_cross_origin_requests_are_refused_even_with_a_valid_token(env):
    csrf = env.login()
    for origin in ("https://evil.example", "null", "http://testserver"):
        r = env.client.post(f"{API}/rules/reload", headers={"X-CSRF-Token": csrf, "Origin": origin})
        assert r.status_code == 403, origin
    ok = env.client.post(
        f"{API}/rules/reload", headers={"X-CSRF-Token": csrf, "Origin": "https://testserver"}
    )
    assert ok.status_code == 200


def test_session_cookie_is_strict_httponly_secure(env):
    r = env.client.post(
        f"{API}/auth/login", json={"username": "analyst", "password": "wrong-password-123"}
    )
    assert "set-cookie" not in r.headers
    env.login()
    # re-issue to inspect the raw header
    env.client.cookies.clear()
    from conftest import ADMIN_PASSWORD, ADMIN_USER

    r = env.client.post(
        f"{API}/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASSWORD}
    )
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "secure" in cookie and "samesite=strict" in cookie


def test_expired_and_garbage_sessions_are_treated_as_unauthenticated(env):
    for value in ("", "garbage", "a.b.c", "eyJhbGciOiJub25lIn0.e30.", "x" * 8000):
        env.client.cookies.clear()
        env.client.cookies.set("vigil_session", value)
        assert env.client.get(f"{API}/alerts").status_code == 401
        assert env.client.get("/", follow_redirects=False).status_code == 303


def test_api_key_cannot_reach_the_dashboard_or_admin_api(env):
    for method, path in admin_routes(env.app, unsafe=False):
        r = env.client.request(method, path, headers=env.headers(), follow_redirects=False)
        assert r.status_code in {401, 303}, (path, r.status_code)


def test_health_endpoint_is_public_but_discloses_nothing(env):
    r = env.client.get("/healthz")
    assert r.status_code == 200
    assert set(r.json()) <= {"status"}


def test_unknown_routes_and_methods_do_not_leak(env):
    for method, path in (("GET", "/nope"), ("GET", "/api/v1/../../etc/passwd"), ("TRACE", "/")):
        r = env.client.request(method, path)
        assert r.status_code in {404, 405}
        assert not LEAKS.search(r.text)
    assert env.client.get("/docs").status_code == 404
    assert env.client.get("/openapi.json").status_code == 404
