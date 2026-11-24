# CLAUDE.md — VigilSIEM

Secure-by-design mini-SIEM: ingest logs → parse/normalize → detect (YAML rules + anomaly baselines) → alert → SOC dashboard / webhooks. Portfolio-grade: security rules below are **non-negotiable**.

## Commands
```bash
python -m venv .venv && . .venv/Scripts/activate      # (Linux/macOS: .venv/bin/activate)
pip install -e ".[dev]"
cp .env.example .env   # then set VIGIL_JWT_SECRET (>=32 random chars)
pytest                                   # all tests
ruff check src tests agent scripts       # lint (includes flake8-bandit "S" rules)
bandit -r src/ -c pyproject.toml         # SAST — must report 0 issues
python scripts/manage_keys.py create --name web-01   # mint an agent API key
python scripts/manage_admin.py hash          # -> VIGIL_ADMIN_PASSWORD_HASH
VIGIL_COOKIE_SECURE=false uvicorn --factory vigilsiem.api.app:create_app   # local http dev only
```

## Layout
`src/vigilsiem/` — `core/` (config, logging, db, errors) · `models/` (ORM, strict schemas, enums) · `security/` (apikeys, passwords, tokens/CSRF, ratelimit, middleware, ssrf) · `parsers/` · `engine/` (rules, correlation, anomaly) · `api/` · `web/` (Jinja2 + HTMX + Alpine). Also `rules/*.yml`, `agent/shipper.py`, `scripts/`, `tests/`.

Agent/simulator: `python agent/shipper.py --help` (key via `VIGIL_AGENT_API_KEY` or `--api-key-file`, never argv);
`python scripts/simulate_attacks.py --self-check` (offline) | `--output-dir logs/` | `--server URL --verify`.
Tests: `tests/test_functional_detection_api.py` (attacks through the real ingest API) and
`tests/test_adversarial_api.py` (auth, SQLi, 413, 429, SSRF, CSRF; discovers routes from the live app).

## Security invariants (never violate)
1. **No** `eval`, `exec`, `pickle`, `yaml.load` (only `yaml.safe_load`), `shell=True`, `os.system`, or `subprocess` with user data.
2. **No raw SQL / f-string SQL.** SQLAlchemy ORM/Core expressions with bound params only.
3. **No hardcoded secrets.** Secrets come from `VIGIL_*` env vars; `Settings.jwt_secret` has no default (fail closed). Never log secrets (`core/logging.redact`).
4. API keys: store SHA-256 only; compare with `secrets.compare_digest`; unknown prefix still does a dummy compare.
5. Pydantic models inherit `StrictModel` (`extra="forbid"`), every `str` has `max_length`, IPs use `IPvAnyAddress`, enums for closed sets.
6. Admin auth = JWT (HS256 pinned) in `HttpOnly; Secure; SameSite=Strict` cookie + CSRF header on POST/PUT/PATCH/DELETE. Ingest auth = `X-API-Key` only. The two never mix.
7. Outbound webhooks MUST pass `security.ssrf.validate_webhook_url` and connect to the returned pinned IP.
8. Errors to clients are `{"error":{"code","message"}}` only — no stack traces, paths, SQL. Details go to the JSON log.
9. CSP is strict (`script-src 'self'`): vendor htmx/Alpine (CSP build)/compiled Tailwind locally; no inline scripts/styles, no CDN at runtime.
10. YAML rules are data, never code: rule conditions are declarative; regexes are compiled with length limits (ReDoS guard).

## Conventions
- Python 3.12, `from __future__ import annotations`, ruff line-length 100, fully typed.
- Every new endpoint ships with an adversarial test (no auth, bad auth, oversize, malformed, injection payload).
- Phases: 1 foundation → 2 parsers/engine → 3 API/dashboard → 4 agent/simulator → 5 tests → 6 CI/Docker/README.
