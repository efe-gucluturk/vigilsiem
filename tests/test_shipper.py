from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import httpx
import pytest

import shipper as sh
from conftest import PUBLIC_IP  # noqa: F401  (ensures env vars are set first)

KEY = "vsk_0123456789ab." + "A" * 43
ENDPOINT = "https://siem.example.com/api/v1/ingest"


# --- configuration -----------------------------------------------------------------------
def test_build_endpoint_enforces_tls_and_bare_origin():
    assert sh.build_endpoint("https://siem.example.com") == ENDPOINT
    assert (
        sh.build_endpoint("https://siem.example.com:8443/")
        == "https://siem.example.com:8443/api/v1/ingest"
    )
    for bad in (
        "http://siem.example.com",
        "http://127.0.0.1:8000",  # loopback http needs the explicit flag
        "ftp://siem.example.com",
        "https://user:pw@siem.example.com",
        "https://siem.example.com/some/path",
        "https://siem.example.com?x=1",
        "https://",
        "siem.example.com",
        "https://siem.example.com:notaport",
    ):
        with pytest.raises(sh.ConfigError):
            sh.build_endpoint(bad)
    assert sh.build_endpoint("http://127.0.0.1:8000", allow_insecure_localhost=True).startswith(
        "http://127.0.0.1"
    )
    with pytest.raises(sh.ConfigError):  # the flag never opens up non-loopback http
        sh.build_endpoint("http://siem.example.com", allow_insecure_localhost=True)


def test_load_api_key(tmp_path):
    assert sh.load_api_key(None, {"VIGIL_AGENT_API_KEY": KEY + "\n"}) == KEY
    f = tmp_path / "k"
    f.write_text(KEY + "\n")
    assert sh.load_api_key(str(f), {}) == KEY
    for env in ({}, {"VIGIL_AGENT_API_KEY": "nope"}, {"VIGIL_AGENT_API_KEY": KEY + "x y"}):
        with pytest.raises(sh.ConfigError):
            sh.load_api_key(None, env)
    with pytest.raises(sh.ConfigError):
        sh.load_api_key(str(tmp_path / "missing"), {})


def test_api_key_is_not_accepted_on_argv():
    with pytest.raises(SystemExit):
        sh.parse_args(["--server", "https://x.example", "--source", "ssh=a", "--api-key", KEY])


def test_sanitize_host_and_sources(tmp_path):
    assert sh.sanitize_host("web 01/über") == "web-01--ber"
    assert sh.sanitize_host("---") == "agent" and sh.sanitize_host("") == "agent"
    assert len(sh.sanitize_host("a" * 200)) == 64
    assert sh.parse_source(f"ssh={tmp_path / 'auth.log'}").source_type == "ssh"
    for bad in ("ssh", "bogus=/x", "ssh=", f"nginx={tmp_path}"):
        with pytest.raises(sh.ConfigError):
            sh.parse_source(bad)


def test_main_config_errors_exit_2(monkeypatch, capsys):
    monkeypatch.delenv("VIGIL_AGENT_API_KEY", raising=False)
    assert (
        sh.main(["--server", "https://siem.example.com", "--source", "ssh=/nonexistent/auth.log"])
        == 2
    )
    monkeypatch.setenv("VIGIL_AGENT_API_KEY", KEY)
    assert sh.main(["--server", "http://siem.example.com", "--source", "ssh=/x"]) == 2
    assert (
        sh.main(
            ["--server", "https://siem.example.com", "--source", "ssh=/x", "--batch-lines", "9999"]
        )
        == 2
    )


# --- batching --------------------------------------------------------------------------------
def test_chunk_lines_caps_lines_and_bytes():
    lines = [f"line {i}" for i in range(1050)]
    chunks = list(sh.chunk_lines(lines, 500))
    assert [len(c) for c in chunks] == [500, 500, 50]
    assert len(next(iter(sh.chunk_lines(lines, 100000)))) == 500  # hard server cap
    big = ["x" * 8000] * 100
    sized = list(sh.chunk_lines(big, 500, max_bytes=100_000))
    assert all(sum(len(x) for x in c) < 100_000 for c in sized) and sum(map(len, sized)) == 100
    assert list(sh.chunk_lines([])) == []


def test_decode_lines_handles_junk():
    raw = [b"ok line\r", b"", b"   ", b"bad \xff\xfe bytes", b"x" * 20000]
    out = sh.decode_lines(raw)
    assert (
        out[0] == "ok line" and "�" in out[1] and len(out[2]) == sh.MAX_LINE_CHARS and len(out) == 3
    )


# --- tailing -----------------------------------------------------------------------------------
def append(path: Path, text: str) -> None:
    with open(path, "ab") as fh:
        fh.write(text.encode())


def test_tailer_reads_only_new_complete_lines(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"old1\nold2\n")
    t = sh.FileTailer(p)
    assert t.poll()[0] == []  # starts at EOF: history is not re-shipped
    append(p, "new1\nnew2\npart")
    lines, committed = t.poll()
    assert lines == [b"new1", b"new2"] and committed == len("old1\nold2\nnew1\nnew2\n")
    append(p, "ial\n")
    assert t.poll()[0] == [b"partial"]
    assert t.poll()[0] == []


def test_tailer_from_beginning_and_missing_file(tmp_path):
    p = tmp_path / "a.log"
    t = sh.FileTailer(p, from_beginning=True)
    assert t.poll() == ([], 0)  # file does not exist yet: no crash
    p.write_bytes(b"a\nb\n")
    assert t.poll()[0] == [b"a", b"b"]


def test_tailer_survives_rotation_and_truncation(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    t = sh.FileTailer(p)
    t.poll()
    append(p, "before-rotate\n")
    assert t.poll()[0] == [b"before-rotate"]
    os.replace(p, tmp_path / "a.log.1")  # logrotate: rename, then a fresh file
    p.write_bytes(b"after-rotate\n")
    assert t.poll()[0] == [b"after-rotate"]
    p.write_bytes(b"t\n")  # truncated in place (copytruncate)
    assert t.poll()[0] == [b"t"]


def test_tailer_bounds_memory_on_newline_free_data(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"")
    t = sh.FileTailer(p)
    t.poll()
    append(p, "x" * (sh.MAX_PARTIAL_BYTES * 3))
    for _ in range(5):
        t.poll()
    assert len(t._partial) <= sh.MAX_PARTIAL_BYTES


def test_tailer_resume_requires_matching_identity(tmp_path):
    p = tmp_path / "a.log"
    p.write_bytes(b"one\ntwo\nthree\n")
    st = os.stat(p)
    good = {"offset": 4, "dev": st.st_dev, "ino": st.st_ino}
    assert sh.FileTailer(p, resume=good).poll()[0] == [b"two", b"three"]
    other_file = {**good, "ino": st.st_ino + 1}
    assert sh.FileTailer(p, resume=other_file).poll()[0] == []  # different file: start at EOF
    assert sh.FileTailer(p, resume={**good, "offset": 9999}).poll()[0] == []


def test_state_store_roundtrip_and_corruption(tmp_path):
    f = tmp_path / "state.json"
    s = sh.StateStore(f)
    s.commit("/var/log/a", 42, (1, 2))
    assert sh.StateStore(f).get("/var/log/a") == {"offset": 42, "dev": 1, "ino": 2}
    assert not (tmp_path / "state.json.tmp").exists()
    f.write_text("{not json")
    assert sh.StateStore(f).get("/var/log/a") is None
    f.write_text(json.dumps({"files": {"x": {"offset": "evil", "dev": 1, "ino": 1}}}))
    assert sh.StateStore(f).get("x") is None


# --- sender --------------------------------------------------------------------------------------
def make_sender(handler, **kw):
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    sleeps: list[float] = []
    sender = sh.Sender(client, ENDPOINT, KEY, "host1", sleep=sleeps.append, **kw)
    return sender, sleeps


def test_sender_success_payload_and_headers():
    seen = []

    def handler(req):
        seen.append(req)
        return httpx.Response(200, json={"accepted": 2, "rejected": 0, "alerts_created": 0})

    sender, _ = make_sender(handler)
    assert sender.send("ssh", ["a", "b"]) == []
    req = seen[0]
    assert req.headers["x-api-key"] == KEY and req.url.path == "/api/v1/ingest"
    assert json.loads(req.content) == {"source_type": "ssh", "host": "host1", "lines": ["a", "b"]}


def test_sender_auth_failure_is_fatal_and_not_retried():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(401, json={})

    sender, _ = make_sender(handler)
    with pytest.raises(sh.AuthError):
        sender.send("ssh", ["a"])
    assert len(calls) == 1


def test_sender_splits_on_413_and_drops_unshippable_line():
    sizes = []

    def handler(req):
        n = len(json.loads(req.content)["lines"])
        sizes.append(n)
        return httpx.Response(413 if n > 2 else 200, json={})

    sender, _ = make_sender(handler)
    assert sender.send("ssh", [f"l{i}" for i in range(8)]) == []
    assert sizes[0] == 8 and max(sizes[1:]) <= 4 and sum(s for s in sizes if s <= 2) == 8

    sender2, _ = make_sender(lambda r: httpx.Response(413, json={}))
    assert sender2.send("ssh", ["only"]) == [] and sender2.dropped_lines == 1


def test_sender_drops_batches_the_server_calls_invalid():
    sender, _ = make_sender(lambda r: httpx.Response(422, json={}))
    assert sender.send("ssh", ["a", "b"]) == [] and sender.dropped_lines == 2


def test_sender_honors_retry_after_and_caps_it():
    replies = iter(
        [
            httpx.Response(429, headers={"retry-after": "7"}),
            httpx.Response(429, headers={"retry-after": "99999"}),
            httpx.Response(429, headers={"retry-after": "junk"}),
            httpx.Response(200, json={}),
        ]
    )
    sender, sleeps = make_sender(lambda r: next(replies))
    assert sender.send("ssh", ["a"]) == []
    assert sleeps == [7, sh.MAX_RETRY_AFTER, 5]


def test_sender_retries_server_errors_then_gives_lines_back():
    calls = []

    def handler(req):
        calls.append(1)
        return httpx.Response(503)

    sender, sleeps = make_sender(handler, max_attempts=3)
    assert sender.send("ssh", ["a", "b"]) == ["a", "b"] and len(calls) == 3 and len(sleeps) == 3
    assert all(s <= 31 for s in sleeps) and sleeps == sorted(sleeps)


def test_sender_survives_network_errors():
    def handler(req):
        raise httpx.ConnectError("boom")

    sender, _ = make_sender(handler, max_attempts=2)
    assert sender.send("ssh", ["a"]) == ["a"]


def test_sender_never_follows_redirects():
    hosts = []

    def handler(req):
        hosts.append(req.url.host)
        return httpx.Response(302, headers={"location": "https://evil.example/steal"})

    sender, _ = make_sender(handler, max_attempts=2)
    assert sender.send("ssh", ["a"]) == ["a"]
    assert set(hosts) == {"siem.example.com"}  # the API key never reached evil.example


def test_key_never_appears_in_logs(caplog):
    caplog.set_level(logging.DEBUG)
    sender, _ = make_sender(lambda r: httpx.Response(500), max_attempts=2)
    sender.send("ssh", ["a"])
    assert KEY not in caplog.text and "vsk_" not in caplog.text


# --- shipper loop ------------------------------------------------------------------------------------
def build(tmp_path, handler, **kw):
    log = tmp_path / "auth.log"
    log.write_bytes(b"")
    sender, _ = make_sender(handler, max_attempts=1)
    state = sh.StateStore(tmp_path / "state.json")
    now = [1000.0]
    shipper = sh.Shipper([sh.SourceSpec("ssh", log)], sender, state, clock=lambda: now[0], **kw)
    shipper.step()
    return shipper, log, state, now


def test_offset_is_committed_only_after_ack_and_retried_with_backoff(tmp_path):
    up = [False]
    received = []

    def handler(req):
        if not up[0]:
            return httpx.Response(503)
        received.extend(json.loads(req.content)["lines"])
        return httpx.Response(200, json={})

    shipper, log, state, now = build(tmp_path, handler)
    append(log, "l1\nl2\nl3\n")
    shipper.step()
    assert state.get(str(log)) is None and shipper.pending_lines == 3  # nothing lost, nothing acked
    up[0] = True
    shipper.step()
    assert received == [] and shipper.pending_lines == 3  # still inside the cool-off window
    now[0] += 120
    shipper.step()
    assert received == ["l1", "l2", "l3"] and shipper.pending_lines == 0
    assert state.get(str(log))["offset"] == len("l1\nl2\nl3\n")


def test_restart_resumes_without_duplicates_or_gaps(tmp_path):
    received = []
    shipper, log, _, _ = build(
        tmp_path,
        lambda r: (received.extend(json.loads(r.content)["lines"]), httpx.Response(200, json={}))[
            1
        ],
    )
    append(log, "a\nb\n")
    shipper.step()
    append(log, "c\n")  # appended while the agent is "down"
    sender, _ = make_sender(
        lambda r: (received.extend(json.loads(r.content)["lines"]), httpx.Response(200, json={}))[1]
    )
    again = sh.Shipper([sh.SourceSpec("ssh", log)], sender, sh.StateStore(tmp_path / "state.json"))
    again.step()
    assert received == ["a", "b", "c"]


def test_pending_queue_is_bounded(tmp_path):
    shipper, log, _, _ = build(
        tmp_path, lambda r: httpx.Response(503), max_pending=3, batch_lines=1
    )
    for i in range(10):
        append(log, f"line{i}\n")
        shipper.step()
    assert len(shipper._pending) <= 3 and shipper.overflow_dropped > 0


def test_auth_error_propagates_out_of_step(tmp_path):
    shipper, log, _, _ = build(tmp_path, lambda r: httpx.Response(401))
    append(log, "x\n")
    with pytest.raises(sh.AuthError):
        shipper.step()


def test_multiple_sources_keep_their_types(tmp_path):
    seen = []
    sender, _ = make_sender(
        lambda r: (seen.append(json.loads(r.content)), httpx.Response(200, json={}))[1]
    )
    a, b = tmp_path / "a.log", tmp_path / "b.log"
    a.write_bytes(b"ssh line\n")
    b.write_bytes(b"web line\n")
    s = sh.Shipper(
        [sh.SourceSpec("ssh", a), sh.SourceSpec("nginx", b)], sender, from_beginning=True
    )
    s.step()
    assert {(m["source_type"], m["lines"][0]) for m in seen} == {
        ("ssh", "ssh line"),
        ("nginx", "web line"),
    }
