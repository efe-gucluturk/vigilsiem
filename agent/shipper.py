#!/usr/bin/env python3
"""VigilSIEM log shipper: tails log files and forwards batches to /api/v1/ingest.

Standalone on purpose (stdlib + httpx only; it does not import the server package).

Security properties
  * TLS is mandatory and certificates are always verified. Plain HTTP is accepted only
    for a loopback host AND an explicit --allow-insecure-localhost.
  * The API key is read from a file or the VIGIL_AGENT_API_KEY environment variable,
    never from argv (argv is world-readable via `ps`). The key is never logged.
  * Redirects are not followed (a redirect must never carry the key to another host).
  * Memory is bounded: capped line length, capped partial line, capped pending queue.
  * Delivery is at-least-once: a file offset is persisted only after the server accepts
    the batch, so a crash can duplicate lines but never lose them.

Usage
  export VIGIL_AGENT_API_KEY=vsk_...        # or --api-key-file /etc/vigil/agent.key
  python shipper.py --server https://siem.example.com \\
      --source ssh=/var/log/auth.log --source nginx=/var/log/nginx/access.log \\
      --state-file /var/lib/vigil/shipper-state.json
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import secrets
import signal
import socket
import stat
import sys
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import httpx

log = logging.getLogger("vigil-shipper")

MAX_LINE_CHARS = 8192  # server-side per-line limit
MAX_BATCH_LINES = 500  # server default cap on lines per request
MAX_BATCH_BYTES = 400_000  # keep well under the server's 512 KB body limit
MAX_READ_BYTES = 1_048_576
MAX_PARTIAL_BYTES = 65_536
MAX_RETRY_AFTER = 120
SOURCE_TYPES = ("ssh", "nginx", "json")
ENDPOINT_PATH = "/api/v1/ingest"
_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_KEY_RE = re.compile(r"^vsk_[0-9a-f]{12}\.[A-Za-z0-9_-]{20,100}$")
_LOOPBACK = {"localhost", "127.0.0.1", "::1"}

OK, DROPPED = "ok", "dropped"


class ConfigError(Exception):
    """Invalid configuration (exit code 2)."""


class AuthError(Exception):
    """Server rejected our API key (exit code 3). Retrying would only hammer it."""


# --------------------------------------------------------------------------------------
# configuration helpers
# --------------------------------------------------------------------------------------


def build_endpoint(server: str, *, allow_insecure_localhost: bool = False) -> str:
    try:
        parts = urlsplit(server)
        host = (parts.hostname or "").lower()
        parts.port  # noqa: B018 - raises ValueError on a malformed port
    except ValueError as exc:
        raise ConfigError("invalid --server URL") from exc
    if parts.username or parts.password:
        raise ConfigError("credentials must not be embedded in the server URL")
    if parts.query or parts.fragment or parts.path not in ("", "/"):
        raise ConfigError("--server must be a bare origin, e.g. https://siem.example.com")
    if not host:
        raise ConfigError("--server is missing a hostname")
    if parts.scheme == "https":
        pass
    elif parts.scheme == "http" and host in _LOOPBACK and allow_insecure_localhost:
        log.warning("INSECURE: sending over plain HTTP to loopback")
    else:
        raise ConfigError(
            "--server must be https:// (http is allowed only for loopback with "
            "--allow-insecure-localhost)"
        )
    return f"{parts.scheme}://{parts.netloc}{ENDPOINT_PATH}"


def load_api_key(key_file: str | None, env: Mapping[str, str] = os.environ) -> str:
    if key_file:
        path = Path(key_file).expanduser()
        try:
            mode = path.stat().st_mode
            if os.name == "posix" and mode & (stat.S_IRWXG | stat.S_IRWXO):
                log.warning("API key file %s is accessible by other users (chmod 600)", path.name)
            key = path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"cannot read API key file: {exc.strerror}") from exc
    else:
        key = env.get("VIGIL_AGENT_API_KEY", "").strip()
    if not key:
        raise ConfigError("no API key: set VIGIL_AGENT_API_KEY or pass --api-key-file")
    if not _KEY_RE.fullmatch(key):
        raise ConfigError("API key is malformed")
    return key


def sanitize_host(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", name).lstrip("._-")[:64]
    return cleaned if _HOST_RE.fullmatch(cleaned) else "agent"


@dataclass(frozen=True)
class SourceSpec:
    source_type: str
    path: Path


def parse_source(spec: str) -> SourceSpec:
    source_type, sep, raw_path = spec.partition("=")  # '=' (not ':') so C:\ paths work
    if not sep or source_type not in SOURCE_TYPES or not raw_path:
        raise ConfigError(f"--source must be TYPE=PATH with TYPE in {SOURCE_TYPES}: {spec!r}")
    path = Path(raw_path).expanduser()
    if path.is_dir():
        raise ConfigError(f"--source path is a directory: {path}")
    return SourceSpec(source_type, path)


# --------------------------------------------------------------------------------------
# batching
# --------------------------------------------------------------------------------------


def decode_lines(raw_lines: Sequence[bytes]) -> list[str]:
    out = []
    for raw in raw_lines:
        text = raw.decode("utf-8", errors="replace").rstrip("\r")
        if text.strip():
            out.append(text[:MAX_LINE_CHARS])
    return out


def chunk_lines(
    lines: Sequence[str], max_lines: int = 200, max_bytes: int = MAX_BATCH_BYTES
) -> Iterator[list[str]]:
    max_lines = max(1, min(max_lines, MAX_BATCH_LINES))
    chunk: list[str] = []
    size = 0
    for line in lines:
        cost = len(line.encode("utf-8")) + 4  # JSON quoting overhead, conservative
        if chunk and (len(chunk) >= max_lines or size + cost > max_bytes):
            yield chunk
            chunk, size = [], 0
        chunk.append(line)
        size += cost
    if chunk:
        yield chunk


@dataclass
class Batch:
    source_type: str
    lines: list[str]
    commit: tuple[str, int, tuple[int, int]] | None = None  # (path, offset, (dev, ino))


# --------------------------------------------------------------------------------------
# tailing
# --------------------------------------------------------------------------------------


class FileTailer:
    """Poll-based tail that survives rotation and truncation and caps its memory."""

    def __init__(self, path: Path, *, from_beginning: bool = False, resume: dict | None = None):
        self.path = path
        self._from_beginning = from_beginning
        self._resume = resume
        self._offset: int | None = None
        self._ident: tuple[int, int] | None = None
        self._partial = b""

    @property
    def ident(self) -> tuple[int, int]:
        return self._ident or (0, 0)

    def poll(self) -> tuple[list[bytes], int]:
        """Return (complete lines, committed offset). Offset excludes any partial line."""
        try:
            st = os.stat(self.path)
        except OSError:
            return [], self._committed()
        ident = (st.st_dev, st.st_ino)

        if self._offset is None:
            self._ident = ident
            resume = self._resume or {}
            if (
                resume.get("dev") == ident[0]
                and resume.get("ino") == ident[1]
                and 0 <= resume.get("offset", -1) <= st.st_size
            ):
                self._offset = resume["offset"]
            else:
                self._offset = 0 if self._from_beginning else st.st_size
        elif ident != self._ident:  # rotated: start the new file from its beginning
            log.info("rotation detected: %s", self.path.name)
            self._ident, self._offset, self._partial = ident, 0, b""
        elif st.st_size < self._offset:  # truncated in place
            log.info("truncation detected: %s", self.path.name)
            self._offset, self._partial = 0, b""

        if st.st_size == self._offset:
            return [], self._committed()
        try:
            with open(self.path, "rb") as fh:
                fh.seek(self._offset)
                data = fh.read(MAX_READ_BYTES)
        except OSError as exc:
            log.warning("cannot read %s: %s", self.path.name, exc.strerror)
            return [], self._committed()
        self._offset += len(data)
        *complete, rest = (self._partial + data).split(b"\n")
        self._partial = rest if len(rest) <= MAX_PARTIAL_BYTES else b""
        return complete, self._committed()

    def _committed(self) -> int:
        return max(0, (self._offset or 0) - len(self._partial))


class StateStore:
    """Persists acknowledged offsets atomically (tmp file + os.replace)."""

    def __init__(self, path: Path | None) -> None:
        self.path = path
        self._data: dict[str, dict[str, int]] = {}
        if path and path.exists():
            try:
                loaded = json.loads(path.read_text(encoding="utf-8"))
                for key, rec in loaded.get("files", {}).items():
                    if isinstance(key, str) and all(
                        isinstance(rec.get(f), int) for f in ("offset", "dev", "ino")
                    ):
                        self._data[key] = {f: rec[f] for f in ("offset", "dev", "ino")}
            except (OSError, ValueError, AttributeError):
                log.warning("ignoring unreadable state file")

    def get(self, file_path: str) -> dict[str, int] | None:
        return self._data.get(file_path)

    def commit(self, file_path: str, offset: int, ident: tuple[int, int]) -> None:
        self._data[file_path] = {"offset": offset, "dev": ident[0], "ino": ident[1]}
        if not self.path:
            return
        tmp = self.path.with_name(self.path.name + ".tmp")
        try:
            tmp.write_text(json.dumps({"files": self._data}), encoding="utf-8")
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("cannot persist state: %s", exc.strerror)


# --------------------------------------------------------------------------------------
# sending
# --------------------------------------------------------------------------------------


class Sender:
    def __init__(
        self,
        client: httpx.Client,
        endpoint: str,
        api_key: str,
        host: str,
        *,
        max_attempts: int = 4,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._client = client
        self._endpoint = endpoint
        self._key = api_key
        self._host = host
        self._max_attempts = max_attempts
        self._sleep = sleep
        self.dropped_lines = 0

    def _backoff(self, attempt: int) -> None:
        self._sleep(min(2**attempt, 30) + secrets.randbelow(1000) / 1000)

    def send(self, source_type: str, lines: list[str]) -> list[str]:
        """Deliver ``lines``; return the lines that still need to be retried later."""
        payload = {"source_type": source_type, "host": self._host, "lines": lines}
        for attempt in range(self._max_attempts):
            try:
                resp = self._client.post(
                    self._endpoint, json=payload, headers={"X-API-Key": self._key}
                )
            except httpx.HTTPError as exc:
                log.warning("send failed (%s); retrying", type(exc).__name__)
                self._backoff(attempt)
                continue
            code = resp.status_code
            if code == 200:
                return []
            if code in (401, 403):
                raise AuthError("server rejected the API key")
            if code == 413:
                if len(lines) == 1:
                    self.dropped_lines += 1
                    log.warning("dropping a line the server refuses as too large")
                    return []
                mid = len(lines) // 2
                return self.send(source_type, lines[:mid]) + self.send(source_type, lines[mid:])
            if code == 422:  # schema rejection will never succeed on retry
                self.dropped_lines += len(lines)
                log.warning("server rejected a batch as invalid; dropped %d lines", len(lines))
                return []
            if code == 429:
                try:
                    wait = min(int(resp.headers.get("retry-after", "5")), MAX_RETRY_AFTER)
                except ValueError:
                    wait = 5
                log.info("rate limited; waiting %ss", wait)
                self._sleep(max(1, wait))
                continue
            log.warning("server error %s; retrying", code)
            self._backoff(attempt)
        return lines


class Shipper:
    def __init__(
        self,
        sources: Sequence[SourceSpec],
        sender: Sender,
        state: StateStore | None = None,
        *,
        from_beginning: bool = False,
        batch_lines: int = 200,
        max_pending: int = 200,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._state = state or StateStore(None)
        self._tailers = [
            (
                s,
                FileTailer(
                    s.path, from_beginning=from_beginning, resume=self._state.get(str(s.path))
                ),
            )
            for s in sources
        ]
        self._sender = sender
        self._batch_lines = batch_lines
        self._pending: deque[Batch] = deque()
        self._max_pending = max_pending
        self._clock = clock
        self._retry_at = 0.0
        self._failures = 0
        self.shipped_lines = 0
        self.overflow_dropped = 0

    @property
    def pending_lines(self) -> int:
        return sum(len(b.lines) for b in self._pending)

    def _enqueue(self, batch: Batch) -> None:
        self._pending.append(batch)
        while len(self._pending) > self._max_pending:  # server down for a long time
            self.overflow_dropped += len(self._pending.popleft().lines)

    def collect(self) -> int:
        """Read new lines from every source into the pending queue."""
        total = 0
        for spec, tailer in self._tailers:
            for _ in range(10):  # catch up on big backlogs without starving other sources
                raw, committed = tailer.poll()
                lines = decode_lines(raw)
                chunks = list(chunk_lines(lines, self._batch_lines))
                for i, chunk in enumerate(chunks):
                    last = i == len(chunks) - 1
                    commit = (str(spec.path), committed, tailer.ident) if last else None
                    self._enqueue(Batch(spec.source_type, chunk, commit))
                total += len(lines)
                if not raw:
                    break
        return total

    def drain(self) -> None:
        if self._clock() < self._retry_at:
            return
        while self._pending:
            batch = self._pending[0]
            leftover = self._sender.send(batch.source_type, batch.lines)
            if leftover:
                self.shipped_lines += len(batch.lines) - len(leftover)
                self._pending[0] = Batch(batch.source_type, leftover, batch.commit)
                self._failures += 1
                self._retry_at = self._clock() + min(60, 2**self._failures)
                return
            self._pending.popleft()
            self.shipped_lines += len(batch.lines)
            self._failures = 0
            if batch.commit:
                self._state.commit(*batch.commit)

    def step(self) -> int:
        read = self.collect()
        self.drain()
        return read

    def run(self, stop: threading.Event, poll_interval: float) -> None:
        while not stop.is_set():
            self.step()
            stop.wait(poll_interval)
        self._retry_at = 0.0  # final best-effort flush on shutdown
        self.step()


# --------------------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------------------


def make_client(ca_bundle: str | None) -> httpx.Client:
    return httpx.Client(
        timeout=httpx.Timeout(10.0),
        verify=ca_bundle or True,
        follow_redirects=False,
        headers={"User-Agent": "vigil-shipper/0.1"},
    )


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="VigilSIEM log shipper", allow_abbrev=False)
    p.add_argument("--server", required=True, help="origin, e.g. https://siem.example.com")
    p.add_argument("--source", action="append", required=True, metavar="TYPE=PATH")
    p.add_argument("--host", default=socket.gethostname())
    p.add_argument("--api-key-file")
    p.add_argument("--ca-bundle", help="PEM bundle for a private CA (verification stays on)")
    p.add_argument("--state-file", type=Path)
    p.add_argument("--from-beginning", action="store_true")
    p.add_argument("--poll-interval", type=float, default=2.0)
    p.add_argument("--batch-lines", type=int, default=200)
    p.add_argument("--allow-insecure-localhost", action="store_true")
    p.add_argument("--once", action="store_true", help="ship what exists, then exit")
    p.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    return p.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=args.log_level, stream=sys.stderr, format="%(asctime)s %(levelname)s %(message)s"
    )
    try:
        endpoint = build_endpoint(
            args.server, allow_insecure_localhost=args.allow_insecure_localhost
        )
        key = load_api_key(args.api_key_file)
        sources = [parse_source(s) for s in args.source]
        if not 0.2 <= args.poll_interval <= 300 or not 1 <= args.batch_lines <= MAX_BATCH_LINES:
            raise ConfigError("poll-interval must be 0.2-300 and batch-lines 1-500")
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 2

    with make_client(args.ca_bundle) as client:
        sender = Sender(client, endpoint, key, sanitize_host(args.host))
        shipper = Shipper(
            sources,
            sender,
            StateStore(args.state_file),
            from_beginning=args.from_beginning or args.once,
            batch_lines=args.batch_lines,
        )
        stop = threading.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
        try:
            if args.once:
                while shipper.step():
                    pass
                shipper.drain()
            else:
                log.info("shipping %d source(s) to %s", len(sources), endpoint)
                shipper.run(stop, args.poll_interval)
        except AuthError:
            log.error("API key rejected by server; exiting")
            return 3
    log.info(
        "done: shipped=%d pending=%d dropped=%d",
        shipper.shipped_lines,
        shipper.pending_lines,
        sender.dropped_lines + shipper.overflow_dropped,
    )
    return 1 if args.once and shipper.pending_lines else 0


if __name__ == "__main__":
    raise SystemExit(main())
