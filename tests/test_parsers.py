from __future__ import annotations

import time
from datetime import UTC, datetime

import pytest

from helpers import NOW
from vigilsiem.models.enums import EventCategory, SourceType
from vigilsiem.parsers import json_app, nginx, ssh
from vigilsiem.parsers.base import ParseContext, ParseError
from vigilsiem.parsers.normalizer import normalize_batch


def ctx(source: SourceType, now: datetime = NOW) -> ParseContext:
    return ParseContext(host="web01", source_type=source, now=now)


S = SourceType.SSH


# --- ssh / sudo --------------------------------------------------------------
def test_ssh_failed_password():
    e = ssh.parse(
        "Nov 24 11:59:01 web01 sshd[100]: Failed password for invalid user bob from 203.0.113.9 "
        "port 4444 ssh2",
        ctx(S),
    )
    assert e.event_category is EventCategory.AUTHENTICATION
    assert (e.action, e.status, e.username) == ("ssh_login", "failure", "bob")
    assert str(e.source_ip) == "203.0.113.9"
    assert e.metadata["invalid_user"] is True and e.metadata["port"] == 4444
    assert e.timestamp == datetime(2026, 11, 24, 11, 59, 1, tzinfo=UTC)


def test_ssh_accepted_and_invalid_user_distinct_action():
    ok = ssh.parse(
        "Nov  4 08:00:00 h sshd[1]: Accepted publickey for alice from 10.0.0.5 port 22 ssh2", ctx(S)
    )
    assert (ok.action, ok.status) == ("ssh_login", "success")
    inv = ssh.parse(
        "Nov 24 08:00:00 h sshd[1]: Invalid user admin from 203.0.113.9 port 22", ctx(S)
    )
    assert inv.action == "ssh_invalid_user"  # not double-counted as ssh_login


def test_ssh_ipv6_and_iso_timestamp():
    e = ssh.parse(
        "2026-11-24T11:00:00.123456+00:00 h sshd[1]: Failed password for root from 2001:db8::1 port 22 ssh2",
        ctx(S),
    )
    assert str(e.source_ip) == "2001:db8::1" and e.timestamp.hour == 11


def test_sudo_variants():
    base = "Nov 24 11:00:00 h sudo: "
    ok = ssh.parse(
        base + "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/ls /root", ctx(S)
    )
    assert (ok.action, ok.status, ok.username) == ("sudo", "success", "alice")
    assert ok.metadata["target_user"] == "root" and ok.metadata["command"] == "/bin/ls /root"
    bad = ssh.parse(
        base + "alice : 3 incorrect password attempts ; TTY=pts/0 ; USER=root ; COMMAND=/bin/su",
        ctx(S),
    )
    assert bad.status == "failure"
    pam = ssh.parse(
        base + "pam_unix(sudo:auth): authentication failure; logname=alice uid=1000 euid=0 "
        "tty=/dev/pts/0 ruser=alice rhost=  user=alice",
        ctx(S),
    )
    assert (pam.action, pam.status, pam.username) == ("sudo", "failure", "alice")
    sess = ssh.parse(
        base + "pam_unix(sudo:session): session opened for user root by alice(uid=1000)", ctx(S)
    )
    assert (sess.action, sess.username, sess.metadata["target_user"]) == (
        "sudo_session",
        "alice",
        "root",
    )


def test_syslog_year_rollover():
    jan = datetime(2027, 1, 2, tzinfo=UTC)
    e = ssh.parse(
        "Dec 31 23:59:59 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2", ctx(S, jan)
    )
    assert e.timestamp.year == 2026


@pytest.mark.parametrize(
    "line",
    [
        "garbage",
        "Nov 24 11:00:00 h cron[1]: (root) CMD (run-parts)",
        "Nov 24 11:00:00 h sshd[1]: Connection closed by 1.2.3.4",
        "Feb 31 11:00:00 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",
        "Xyz 24 11:00:00 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",
    ],
)
def test_ssh_rejects(line):
    with pytest.raises(ParseError):
        ssh.parse(line, ctx(S))


# --- nginx -------------------------------------------------------------------
N = SourceType.NGINX


def test_nginx_combined():
    line = (
        '203.0.113.50 - bob [24/Nov/2026:13:00:05 +0100] "GET /search?q=1%27+OR+1=1 HTTP/1.1" '
        '403 123 "http://ref/" "sqlmap/1.7"'
    )
    e = nginx.parse(line, ctx(N))
    assert e.event_category is EventCategory.WEB and e.username == "bob"
    assert (e.action, e.status) == ("http_request", "failure")
    assert e.timestamp == datetime(2026, 11, 24, 12, 0, 5, tzinfo=UTC)  # tz-normalized
    m = e.metadata
    assert m["method"] == "GET" and m["status_code"] == 403 and m["user_agent"] == "sqlmap/1.7"
    assert m["path"] == "/search" and m["query"] == "q=1%27+OR+1=1"


def test_nginx_without_referrer_and_malformed_request():
    e = nginx.parse('1.2.3.4 - - [24/Nov/2026:12:00:00 +0000] "-" 400 0', ctx(N))
    assert e.metadata["method"] == "UNKNOWN" and e.username is None
    assert e.metadata.get("user_agent") is None


def test_nginx_rejects_garbage():
    with pytest.raises(ParseError):
        nginx.parse("not an access log", ctx(N))
    with pytest.raises(ParseError):
        nginx.parse('1.2.3.4 - - [32/Nov/2026:12:00:00 +0000] "GET / HTTP/1.1" 200 1', ctx(N))


# --- json --------------------------------------------------------------------
J = SourceType.JSON


def test_json_event_mapping():
    e = json_app.parse(
        '{"ts": 1795608000, "src_ip": "198.51.100.1", "user": "carol", "category": "authentication",'
        ' "event": "login", "result": "denied", "attempt": 3, "nested": {"x": 1}}',
        ctx(J),
    )
    assert e.event_category is EventCategory.AUTHENTICATION and e.status == "failure"
    assert (e.action, e.username) == ("login", "carol") and str(e.source_ip) == "198.51.100.1"
    assert e.metadata["attempt"] == 3 and "nested" not in e.metadata


def test_json_defaults_and_invalid_ip_dropped():
    e = json_app.parse('{"source_ip": "999.1.1.1", "category": "weird"}', ctx(J))
    assert e.source_ip is None and e.event_category is EventCategory.APPLICATION
    assert e.timestamp == NOW and e.action == "event" and e.status == "unknown"


@pytest.mark.parametrize(
    "line",
    [
        "[1,2]",
        "not json",
        '"str"',
        '{"timestamp": "yesterday"}',
        '{"timestamp": 99999999999999}',
        '{"timestamp": true}',
    ],
)
def test_json_rejects(line):
    with pytest.raises(ParseError):
        json_app.parse(line, ctx(J))


def test_json_deep_nesting_does_not_crash():
    with pytest.raises(ParseError):
        json_app.parse("[" * 5000 + "]" * 5000, ctx(J))


# --- hygiene / adversarial -----------------------------------------------------
def test_control_chars_and_newlines_neutralized():
    e = ssh.parse(
        "Nov 24 11:59:01 h sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2\x00\x1b[31m\nForged: line",
        ctx(S),
    )
    assert "\n" not in e.raw_log and "\x00" not in e.raw_log and "\x1b" not in e.raw_log


@pytest.mark.parametrize("source", list(SourceType))
@pytest.mark.parametrize(
    "payload",
    [
        "a" * 8192,
        " " * 8192,
        "Nov 24 11:00:00 h sshd[1]: " + "Failed password for " * 400,
        '1.2.3.4 - - [24/Nov/2026:12:00:00 +0000] "' + "A " * 4000,
        '{"a":' + '"' + "\\" * 8000,
        "1.2.3.4" + " -" * 4000,
    ],
)
def test_parsers_linear_time_on_hostile_input(source, payload):
    start = time.perf_counter()
    res = normalize_batch(source, "web01", [payload[:8192]], now=NOW)
    assert time.perf_counter() - start < 0.5
    assert res.rejected + len(res.events) == 1


def test_batch_isolates_bad_lines_and_never_echoes_input():
    secret_marker = "TOPSECRET-TOKEN"
    lines = [
        "Nov 24 11:59:01 h sshd[1]: Failed password for a from 1.2.3.4 port 1 ssh2",
        f"junk {secret_marker}",
        "x" * 9000,
    ] + [f"bad {i}" for i in range(30)]
    res = normalize_batch(S, "web01", lines, now=NOW)
    assert len(res.events) == 1 and res.rejected == len(lines) - 1
    assert len(res.errors) == 10  # error report is capped
    assert secret_marker not in repr(res.errors)


def test_nginx_raw_spaces_in_uri_do_not_truncate_payload():
    line = '1.2.3.4 - - [24/Nov/2026:12:00:00 +0000] "GET /x?a=1\' or 1=1-- HTTP/1.1" 400 0 "-" "-"'
    e = nginx.parse(line, ctx(N))
    assert e.metadata["uri"] == "/x?a=1' or 1=1--" and e.metadata["protocol"] == "HTTP/1.1"
