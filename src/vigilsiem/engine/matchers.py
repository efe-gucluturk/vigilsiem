"""Compile declarative ``Condition`` objects into plain predicate callables."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from urllib.parse import unquote_plus

from vigilsiem.engine.fields import get_field
from vigilsiem.engine.regex_guard import MAX_MATCH_INPUT, compile_safe
from vigilsiem.engine.rules import Condition
from vigilsiem.models.schemas import SecurityEvent

Predicate = Callable[[SecurityEvent], bool]


def _variants(value: str) -> tuple[str, ...]:
    """Raw value plus up to two rounds of URL-decoding (defeats %27 / double-encoding evasion).

    Every variant is length-capped BEFORE any regex sees it (ReDoS bound).
    """
    raw = value[:MAX_MATCH_INPUT]
    once = unquote_plus(raw)[:MAX_MATCH_INPUT]
    twice = unquote_plus(once)[:MAX_MATCH_INPUT]
    out = [raw]
    out.extend(v for v in (once, twice) if v not in out)
    return tuple(out)


def build_matcher(cond: Condition) -> Predicate:
    path = cond.field

    if cond.exists is not None:
        want = cond.exists
        return lambda e: (get_field(e, path) is not None) == want

    if cond.equals is not None:
        expected = cond.equals
        return lambda e: (
            (v := get_field(e, path)) is not None and (v == expected or str(v) == str(expected))
        )

    if cond.one_of is not None:
        allowed = {str(x) for x in cond.one_of}
        return lambda e: (v := get_field(e, path)) is not None and str(v) in allowed

    if cond.contains_any is not None:
        needles = tuple(n.lower() for n in cond.contains_any)

        def contains(e: SecurityEvent) -> bool:
            v = get_field(e, path)
            if v is None:
                return False
            return any(n in var.lower() for var in _variants(str(v)) for n in needles)

        return contains

    if cond.regex_any is not None:
        patterns = tuple(compile_safe(p) for p in cond.regex_any)

        def regex(e: SecurityEvent) -> bool:
            v = get_field(e, path)
            if v is None:
                return False
            return any(p.search(var) for var in _variants(str(v)) for p in patterns)

        return regex

    low, high = cond.gte, cond.lte

    def numeric(e: SecurityEvent) -> bool:
        v = get_field(e, path)
        if v is None or isinstance(v, bool):
            return False
        try:
            num = float(v)
        except (TypeError, ValueError):
            return False
        return (low is None or num >= low) and (high is None or num <= high)

    return numeric


def build_all(conditions: Iterable[Condition]) -> Predicate:
    matchers = tuple(build_matcher(c) for c in conditions)
    return lambda e: all(m(e) for m in matchers)
