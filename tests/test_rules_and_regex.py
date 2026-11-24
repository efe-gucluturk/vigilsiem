from __future__ import annotations

import time
from pathlib import Path

import pytest

from helpers import RULES_DIR
from vigilsiem.engine.correlation import RuleEngine
from vigilsiem.engine.regex_guard import MAX_MATCH_INPUT, UnsafeRegexError, compile_safe
from vigilsiem.engine.rules import MAX_RULE_FILE_BYTES, RuleLoadError, load_rules, parse_rule_yaml

# --- regex guard ---------------------------------------------------------------
UNSAFE = [
    r"(a+)+$",
    r"(a*)*",
    r"(\w+\s?)*",
    r"(a|aa)+",
    r"(a|a)*b",
    r"(?:x+x+)+y",
    r"(a{1,5}){1,5}",
    r"(a)\1",
    r"(?=a)a",
    r"(?!a)b",
    r"a{1,5000}",
    r".*.*.*.*",
    "a" * 300,
    "",
    "(unclosed",
    "[z-a]",
]
SAFE = [
    r"\bunion\b.{0,40}\bselect\b",
    r"<\s{0,3}script",
    r"\bon(?:error|load)\s{0,3}=",
    r"'\s{0,5}or\s{1,5}[\w']{1,20}\s{0,5}=",
    r"^/admin(?:/|$)",
    r".*foo",
]


@pytest.mark.parametrize("pattern", UNSAFE)
def test_unsafe_regex_rejected(pattern):
    with pytest.raises(UnsafeRegexError):
        compile_safe(pattern)


@pytest.mark.parametrize("pattern", SAFE)
def test_safe_regex_accepted_and_fast_on_pathological_input(pattern):
    rx = compile_safe(pattern)
    for hostile in (
        "a" * MAX_MATCH_INPUT,
        "'" + " " * MAX_MATCH_INPUT,
        "<" + " " * MAX_MATCH_INPUT,
    ):
        start = time.perf_counter()
        rx.search(hostile)
        assert time.perf_counter() - start < 0.25


# --- YAML hardening --------------------------------------------------------------
VALID = """
id: VSR-9001
name: Test
severity: high
mitre: {tactic: Credential Access, technique_id: T1110, technique: Brute Force}
type: threshold
match:
  - {field: status, equals: failure}
group_by: source_ip
"""


def test_valid_rule_parses():
    spec = parse_rule_yaml(VALID)
    assert spec.id == "VSR-9001" and spec.window_seconds == 60 and spec.threshold == 5


@pytest.mark.parametrize(
    "text",
    [
        "!!python/object/apply:os.system ['echo pwned']",
        VALID.replace("name: Test", "name: !!python/object/apply:os.getcwd []"),
        VALID.replace("name: Test", "name: &a Test\ndescription: *a"),
        "---\n" + VALID + "\n---\n" + VALID,
        "- just\n- a list",
        "just a string",
        ": : :\n\t- [",
        VALID + "\nextra_field: 1",
        VALID.replace("high", "apocalyptic"),
        VALID.replace("T1110", "X9"),
        VALID.replace("Credential Access", "Made Up Tactic"),
        VALID.replace("group_by: source_ip\n", ""),
        VALID.replace(
            "{field: status, equals: failure}", "{field: status, equals: x, one_of: [a]}"
        ),
        VALID.replace("{field: status, equals: failure}", "{field: status}"),
        VALID.replace("{field: status, equals: failure}", "{field: 'bad field', equals: x}"),
        VALID.replace("{field: status, equals: failure}", "{field: status, regex_any: ['(a+)+$']}"),
        VALID.replace("threshold\n", "threshold\nthreshold: 99999\n"),
    ],
)
def test_malicious_or_invalid_rules_rejected(text):
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(text)


def test_alias_bomb_rejected_quickly():
    bomb = "a: &a [x,x,x,x,x,x,x,x,x]\n" + "".join(
        f"{chr(98 + i)}: &{chr(98 + i)} [{','.join(['*' + chr(97 + i)] * 9)}]\n" for i in range(8)
    )
    start = time.perf_counter()
    with pytest.raises(RuleLoadError):
        parse_rule_yaml(bomb)
    assert time.perf_counter() - start < 1


def test_no_yaml_load_or_unsafe_apis_in_source():
    root = Path(__file__).resolve().parents[1] / "src"
    banned = (
        "yaml.load(",
        "eval(",
        "exec(",
        "pickle",
        "shell=True",
        "os.system",
        "yaml.unsafe_load",
    )
    for py in root.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        for token in banned:
            assert token not in text.replace("`", ""), f"{token} found in {py.name}"


# --- loader ------------------------------------------------------------------------
def test_shipped_rules_load_and_map_to_mitre():
    loaded = load_rules(RULES_DIR)
    assert len(loaded) >= 8
    for r in loaded:
        assert r.spec.mitre.technique_id.startswith("T")
    ids = {r.spec.id for r in loaded}
    assert {"VSR-1001", "VSR-1002", "VSR-1003", "VSR-2001"} <= ids


def test_loader_errors(tmp_path):
    (tmp_path / "a.yml").write_text(VALID)
    (tmp_path / "b.yml").write_text(VALID)
    with pytest.raises(RuleLoadError, match="duplicate"):
        load_rules(tmp_path)
    (tmp_path / "b.yml").write_text("x" * (MAX_RULE_FILE_BYTES + 1))
    with pytest.raises(RuleLoadError, match="too large"):
        load_rules(tmp_path)
    (tmp_path / "b.yml").write_bytes(b"\xff\xfe\x00bad")
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path)
    with pytest.raises(RuleLoadError):
        load_rules(tmp_path / "missing")


def test_reload_is_atomic(tmp_path):
    (tmp_path / "a.yml").write_text(VALID)
    engine = RuleEngine.from_directory(tmp_path)
    assert [r["id"] for r in engine.describe()] == ["VSR-9001"]
    (tmp_path / "bad.yml").write_text("!!python/object/apply:os.system ['x']")
    with pytest.raises(RuleLoadError):
        engine.reload_from_directory(tmp_path)
    assert [r["id"] for r in engine.describe()] == ["VSR-9001"]  # old rules still active
    (tmp_path / "bad.yml").unlink()
    (tmp_path / "c.yml").write_text(VALID.replace("VSR-9001", "VSR-9002"))
    assert engine.reload_from_directory(tmp_path) == 2
