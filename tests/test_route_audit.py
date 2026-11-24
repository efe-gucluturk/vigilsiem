"""Permanent guard: every registered route must have the right auth / CSRF / rate-limit wiring.

If someone adds a route and forgets a dependency, this fails instead of shipping.
"""

from __future__ import annotations

import pytest
from fastapi.routing import APIRoute
from starlette.routing import Mount

from vigilsiem.api import deps

UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}
# Intentionally unauthenticated. Page routes authenticate inside the handler (redirect to
# /login) and are covered behaviourally by test_unauthenticated_pages_redirect_to_login.
PUBLIC = {
    ("GET", "/healthz"),
    ("GET", "/login"),
    ("POST", "/login"),
    ("POST", "/api/v1/auth/login"),
}
PAGES = {("GET", "/"), ("GET", "/rules"), ("GET", "/webhooks")}


def _walk(routes):
    for r in routes:
        if hasattr(r, "original_router"):  # lazily nested include_router (FastAPI >= 0.16x)
            yield from _walk(r.original_router.routes)
        else:
            yield r


def _calls(dep):
    yield dep.call
    for sub in dep.dependencies:
        yield from _calls(sub)


def _routes(app):
    for r in _walk(app.router.routes):
        if isinstance(r, Mount):
            continue
        assert isinstance(r, APIRoute), f"unexpected route type {type(r).__name__}"
        calls = set(_calls(r.dependant))
        for method in sorted(r.methods - {"HEAD", "OPTIONS"}):
            yield method, r.path, calls


def test_every_route_is_discovered(env):
    found = {(m, p) for m, p, _ in _routes(env.app)}
    assert len(found) == 26  # update deliberately when routes are added
    assert ("POST", "/api/v1/ingest") in found and ("DELETE", "/ui/webhooks/{webhook_id}") in found


def test_authentication_and_csrf_wiring(env):
    for method, path, calls in _routes(env.app):
        key = (method, path)
        if key in PUBLIC or key in PAGES:
            continue
        if path == "/api/v1/ingest":
            assert deps.require_api_key in calls, "ingest must require an API key (+ rate limit)"
            assert deps.require_admin not in calls, "ingest must not accept the admin plane"
            continue
        assert deps.require_admin in calls, f"{method} {path} lacks admin authentication"
        assert deps.require_api_key not in calls, f"{method} {path} mixes auth planes"
        if method in UNSAFE:
            assert deps.require_csrf in calls, f"{method} {path} lacks CSRF protection"


def test_safe_methods_never_mutate(env):
    # GETs must not require CSRF (they are idempotent) and no GET handler may be state-changing.
    for method, path, calls in _routes(env.app):
        if method == "GET":
            assert deps.require_csrf not in calls or path.startswith("/ui"), path


def test_all_limiters_exist_and_are_applied(env):
    ctx = env.app.state.ctx
    assert ctx.ingest_limiter.limit == env.settings.ingest_rate_per_min
    assert ctx.login_limiter.limit == env.settings.login_rate_per_min
    assert ctx.admin_limiter.limit == env.settings.admin_rate_per_min
    assert ctx.key_fail_limiter.limit == 20


def test_admin_plane_is_rate_limited_per_session(tight_env):
    env = tight_env
    env.login()
    codes = [env.client.get("/api/v1/stats").status_code for _ in range(23)]
    assert codes[:20] == [200] * 20 and set(codes[20:]) == {429}
    r = env.client.get("/api/v1/stats")
    assert r.status_code == 429 and 1 <= int(r.headers["retry-after"]) <= 60
    # dashboard fragments and pages share the same budget
    assert env.client.get("/ui/metrics").status_code == 429
    assert env.client.get("/", follow_redirects=False).status_code == 429


@pytest.mark.parametrize(
    "path", ["/static/vendor/htmx.min.js", "/static/js/app.js", "/static/css/app.css"]
)
def test_static_assets_served_locally(env, path):
    r = env.client.get(path)
    assert r.status_code == 200 and len(r.content) > 100
