"""Linux auth.log parser: sshd logins and sudo activity."""

from __future__ import annotations

import re
from datetime import datetime

from vigilsiem.models.enums import EventCategory
from vigilsiem.models.schemas import SecurityEvent
from vigilsiem.parsers.base import (
    ParseContext,
    ParseError,
    clean_line,
    make_event,
    safe_ip,
    syslog_timestamp,
    to_utc,
)

_HOST = r"[A-Za-z0-9._-]{1,64}"
_PROC = r"[A-Za-z0-9_./-]{1,32}"
_IP = r"[0-9A-Fa-f:.]{2,45}"

_SYSLOG = re.compile(
    rf"^(?P<mon>[A-Z][a-z]{{2}}) {{1,2}}(?P<day>\d{{1,2}}) "
    rf"(?P<h>\d{{2}}):(?P<m>\d{{2}}):(?P<s>\d{{2}}) (?P<host>{_HOST}) "
    rf"(?P<proc>{_PROC})(?:\[\d{{1,7}}\])?: (?P<msg>.*)$"
)
_ISO = re.compile(
    rf"^(?P<ts>\d{{4}}-\d{{2}}-\d{{2}}T\d{{2}}:\d{{2}}:\d{{2}}(?:\.\d{{1,9}})?"
    rf"(?:Z|[+-]\d{{2}}:\d{{2}})?) (?P<host>{_HOST}) "
    rf"(?P<proc>{_PROC})(?:\[\d{{1,7}}\])?: (?P<msg>.*)$"
)

_FAILED = re.compile(
    rf"^Failed (?P<method>[a-z/-]{{1,32}}) for (?P<invalid>invalid user )?(?P<user>\S{{1,64}}) "
    rf"from (?P<ip>{_IP}) port (?P<port>\d{{1,5}})"
)
_ACCEPTED = re.compile(
    rf"^Accepted (?P<method>[a-z/-]{{1,32}}) for (?P<user>\S{{1,64}}) "
    rf"from (?P<ip>{_IP}) port (?P<port>\d{{1,5}})"
)
_INVALID_USER = re.compile(rf"^Invalid user (?P<user>\S{{0,64}}) from (?P<ip>{_IP})")

_SUDO_CMD = re.compile(r"^(?P<user>[^\s:]{1,64}) : (?P<rest>.*)$")
_PAM_SESSION = re.compile(
    r"^pam_unix\(sudo:session\): session opened for user (?P<target>\S{1,64}) "
    r"by (?P<user>[^\s(]{0,64})\(uid=(?P<uid>\d{1,10})\)"
)
_PAM_AUTH_FAIL_PREFIX = "pam_unix(sudo:auth): authentication failure"


def parse(line: str, ctx: ParseContext) -> SecurityEvent:
    raw = clean_line(line)
    ts, proc, msg = _split_header(raw, ctx.now)
    if proc == "sshd":
        return _parse_sshd(ctx, ts, msg, raw)
    if proc == "sudo":
        return _parse_sudo(ctx, ts, msg, raw)
    raise ParseError("unsupported process")


def _split_header(raw: str, now: datetime) -> tuple[datetime, str, str]:
    if m := _SYSLOG.match(raw):
        ts = syslog_timestamp(m["mon"], m["day"], (m["h"], m["m"], m["s"]), now)
        return ts, m["proc"], m["msg"]
    if m := _ISO.match(raw):
        try:
            return to_utc(datetime.fromisoformat(m["ts"])), m["proc"], m["msg"]
        except ValueError as exc:
            raise ParseError("bad ISO timestamp") from exc
    raise ParseError("not a syslog line")


def _parse_sshd(ctx: ParseContext, ts: datetime, msg: str, raw: str) -> SecurityEvent:
    if m := _FAILED.match(msg):
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
            status="failure",
            raw=raw,
            source_ip=safe_ip(m["ip"]),
            username=m["user"],
            metadata={
                "method": m["method"],
                "port": int(m["port"]),
                "invalid_user": m["invalid"] is not None,
            },
        )
    if m := _ACCEPTED.match(msg):
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.AUTHENTICATION,
            action="ssh_login",
            status="success",
            raw=raw,
            source_ip=safe_ip(m["ip"]),
            username=m["user"],
            metadata={"method": m["method"], "port": int(m["port"])},
        )
    if m := _INVALID_USER.match(msg):
        # Distinct action so the paired "Failed password for invalid user" line
        # is not double-counted by threshold rules.
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.AUTHENTICATION,
            action="ssh_invalid_user",
            status="failure",
            raw=raw,
            source_ip=safe_ip(m["ip"]),
            username=m["user"] or None,
        )
    raise ParseError("unrecognized sshd message")


def _parse_sudo(ctx: ParseContext, ts: datetime, msg: str, raw: str) -> SecurityEvent:
    if m := _SUDO_CMD.match(msg):
        fields = {}
        for part in m["rest"].split(" ; "):
            key, sep, value = part.partition("=")
            if sep:
                fields[key.strip()] = value.strip()
        failed = "incorrect password attempt" in m["rest"] or "NOT in sudoers" in m["rest"]
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.PRIVILEGE,
            action="sudo",
            status="failure" if failed else "success",
            raw=raw,
            username=m["user"],
            metadata={
                "target_user": fields.get("USER"),
                "command": fields.get("COMMAND"),
                "tty": fields.get("TTY"),
            },
        )
    if msg.startswith(_PAM_AUTH_FAIL_PREFIX):
        kv = {}
        for tok in msg.split():
            key, sep, value = tok.partition("=")
            if sep:
                kv[key] = value
        user = kv.get("user") or kv.get("logname")
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.PRIVILEGE,
            action="sudo",
            status="failure",
            raw=raw,
            source_ip=safe_ip(kv.get("rhost")),
            username=user,
            metadata={"tty": kv.get("tty")},
        )
    if m := _PAM_SESSION.match(msg):
        return make_event(
            ctx,
            timestamp=ts,
            category=EventCategory.PRIVILEGE,
            action="sudo_session",
            status="success",
            raw=raw,
            username=m["user"] or None,
            metadata={"target_user": m["target"], "uid": int(m["uid"])},
        )
    raise ParseError("unrecognized sudo message")
