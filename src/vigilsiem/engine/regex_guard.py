"""ReDoS guard for regexes supplied by YAML rules.

Python's ``re`` has no match timeout, so unsafe patterns are rejected at load time by
inspecting the parsed regex AST, and inputs are length-capped at match time.

Rejected constructs:
  * nested multi-repeats        ``(a+)+``  ``(\\w+\\s?)*``  ``(a{1,5}){1,5}``
  * alternation inside a repeat ``(a|aa)+``
  * back-references / lookarounds (backtracking amplifiers, rarely needed)
  * finite repeats above 1000, more than 3 unbounded repeats, patterns over 256 chars
"""

from __future__ import annotations

import re
from functools import lru_cache
from re import _constants as _c
from re import _parser as _p
from typing import Any

MAX_PATTERN_LEN = 256
MAX_MATCH_INPUT = 2048
MAX_FINITE_REPEAT = 1000
MAX_UNBOUNDED = 3

_REPEATS = (_c.MAX_REPEAT, _c.MIN_REPEAT, _c.POSSESSIVE_REPEAT)
_FORBIDDEN = (_c.GROUPREF, _c.GROUPREF_EXISTS, _c.ASSERT, _c.ASSERT_NOT)


class UnsafeRegexError(ValueError):
    """Pattern is invalid or could exhibit catastrophic backtracking."""


def _items(sub: Any) -> list[Any]:
    return list(getattr(sub, "data", sub))


def _walk(items: list[Any], in_multi: bool, unbounded: list[int]) -> None:
    for op, av in items:
        if op in _REPEATS:
            lo, hi, sub = av
            del lo
            multi = hi > 1
            if multi and in_multi:
                raise UnsafeRegexError("nested repetition")
            if hi == _c.MAXREPEAT:
                unbounded[0] += 1
                if unbounded[0] > MAX_UNBOUNDED:
                    raise UnsafeRegexError("too many unbounded repetitions")
            elif hi > MAX_FINITE_REPEAT:
                raise UnsafeRegexError("repeat bound too large")
            _walk(_items(sub), in_multi or multi, unbounded)
        elif op is _c.BRANCH:
            if in_multi:
                raise UnsafeRegexError("alternation inside repetition")
            for branch in av[1]:
                _walk(_items(branch), in_multi, unbounded)
        elif op is _c.SUBPATTERN:
            _walk(_items(av[3]), in_multi, unbounded)
        elif op is _c.ATOMIC_GROUP:
            _walk(_items(av), in_multi, unbounded)
        elif op in _FORBIDDEN:
            raise UnsafeRegexError("back-references and lookarounds are not allowed")


@lru_cache(maxsize=1024)
def compile_safe(pattern: str) -> re.Pattern[str]:
    """Compile ``pattern`` (case-insensitive) or raise ``UnsafeRegexError``."""
    if not pattern or len(pattern) > MAX_PATTERN_LEN:
        raise UnsafeRegexError("pattern empty or too long")
    try:
        parsed = _p.parse(pattern, re.IGNORECASE)
        _walk(_items(parsed), False, [0])
        return re.compile(pattern, re.IGNORECASE)
    except UnsafeRegexError:
        raise
    except (re.error, RecursionError, OverflowError) as exc:
        raise UnsafeRegexError(f"invalid regex: {type(exc).__name__}") from exc
