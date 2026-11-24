"""Declarative detection-rule schema and the hardened YAML loader.

Rules are DATA. There is no expression language, no code execution, and YAML is parsed
exclusively with ``yaml.safe_load`` after an event-level pre-scan that rejects aliases,
anchors, explicit tags, multi-document files and oversized documents (billion-laughs).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import Field, ValidationError, model_validator

from vigilsiem.engine.fields import FIELD_PATTERN
from vigilsiem.engine.regex_guard import compile_safe
from vigilsiem.models.enums import Severity
from vigilsiem.models.schemas import StrictModel

MAX_RULE_FILE_BYTES = 64 * 1024
MAX_RULE_FILES = 200
MAX_YAML_EVENTS = 5000

FieldPath = Annotated[str, Field(pattern=FIELD_PATTERN)]
Scalar = str | int | bool
_OPERATORS = ("equals", "one_of", "contains_any", "regex_any", "exists", "gte", "lte")


class RuleLoadError(Exception):
    """Rule file(s) could not be loaded. The message is safe to show to an admin."""


class Mitre(StrictModel):
    tactic: Literal[
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]
    technique_id: Annotated[str, Field(pattern=r"^T\d{4}(?:\.\d{3})?$")]
    technique: Annotated[str, Field(min_length=1, max_length=96)]


class Condition(StrictModel):
    """One predicate on one field. Exactly one operator must be given."""

    field: FieldPath
    equals: Scalar | None = None
    one_of: Annotated[list[str | int], Field(max_length=100)] | None = None
    contains_any: (
        Annotated[list[Annotated[str, Field(min_length=1, max_length=128)]], Field(max_length=50)]
        | None
    ) = None
    regex_any: (
        Annotated[list[Annotated[str, Field(min_length=1, max_length=256)]], Field(max_length=20)]
        | None
    ) = None
    exists: bool | None = None
    gte: float | None = None
    lte: float | None = None

    @model_validator(mode="after")
    def _single_operator(self) -> Self:
        used = [op for op in _OPERATORS if op in self.model_fields_set]
        if len(used) != 1:
            raise ValueError("exactly one operator is required per condition")
        for pattern in self.regex_any or ():
            compile_safe(pattern)  # raises UnsafeRegexError (a ValueError) if unsafe
        return self


class Step(StrictModel):
    match: Annotated[list[Condition], Field(min_length=1, max_length=10)]


class RuleSpec(StrictModel):
    id: Annotated[str, Field(pattern=r"^[A-Z]{2,5}-\d{3,6}$")]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    description: Annotated[str, Field(max_length=512)] = ""
    severity: Severity
    enabled: bool = True
    mitre: Mitre
    type: Literal["signature", "threshold", "distinct", "sequence"]
    match: Annotated[list[Condition], Field(max_length=10)] = Field(default_factory=list)
    steps: Annotated[list[Step], Field(max_length=5)] = Field(default_factory=list)
    group_by: FieldPath | None = None
    distinct_field: FieldPath | None = None
    window_seconds: Annotated[int, Field(ge=1, le=86_400)] = 60
    threshold: Annotated[int, Field(ge=2, le=1000)] = 5
    dedupe_seconds: Annotated[int, Field(ge=0, le=3600)] = 60

    @model_validator(mode="after")
    def _shape_matches_type(self) -> Self:
        if self.type == "sequence":
            if not 2 <= len(self.steps) <= 5 or self.match:
                raise ValueError("sequence rules need 2-5 'steps' and no top-level 'match'")
            if not self.group_by:
                raise ValueError("sequence rules require group_by")
        else:
            if self.steps or not self.match:
                raise ValueError(f"{self.type} rules need 'match' and no 'steps'")
            if self.type != "signature" and not self.group_by:
                raise ValueError(f"{self.type} rules require group_by")
        if self.type == "distinct" and not self.distinct_field:
            raise ValueError("distinct rules require distinct_field")
        if self.type != "distinct" and self.distinct_field:
            raise ValueError("distinct_field is only valid for distinct rules")
        return self


@dataclass(frozen=True)
class LoadedRule:
    spec: RuleSpec
    filename: str
    source: str


def parse_rule_yaml(text: str) -> RuleSpec:
    """Validate + parse one rule document. Never executes or constructs arbitrary objects."""
    try:
        for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader), 1):
            if count > MAX_YAML_EVENTS:
                raise RuleLoadError("YAML document too complex")
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise RuleLoadError("YAML anchors/aliases are not allowed")
            if getattr(event, "tag", None):
                raise RuleLoadError("YAML tags are not allowed")
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleLoadError("invalid YAML") from exc
    if not isinstance(data, dict):
        raise RuleLoadError("rule file must contain a mapping")
    try:
        return RuleSpec.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()[:5]
        )
        raise RuleLoadError(f"schema error: {problems}") from exc


def load_rules(directory: str | Path) -> list[LoadedRule]:
    """Load every ``*.yml`` in ``directory`` (non-recursive). All-or-nothing."""
    root = Path(directory)
    if not root.is_dir():
        raise RuleLoadError("rules directory not found")
    files = sorted(p for p in root.iterdir() if p.suffix == ".yml")
    if len(files) > MAX_RULE_FILES:
        raise RuleLoadError("too many rule files")

    loaded: list[LoadedRule] = []
    seen: set[str] = set()
    for path in files:
        if path.is_symlink() or not path.is_file():
            raise RuleLoadError(f"{path.name}: not a regular file")
        with path.open("rb") as fh:
            blob = fh.read(MAX_RULE_FILE_BYTES + 1)
        if len(blob) > MAX_RULE_FILE_BYTES:
            raise RuleLoadError(f"{path.name}: file too large")
        try:
            text = blob.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise RuleLoadError(f"{path.name}: not valid UTF-8") from exc
        try:
            spec = parse_rule_yaml(text)
        except RuleLoadError as exc:
            raise RuleLoadError(f"{path.name}: {exc}") from exc
        if spec.id in seen:
            raise RuleLoadError(f"{path.name}: duplicate rule id {spec.id}")
        seen.add(spec.id)
        loaded.append(LoadedRule(spec=spec, filename=path.name, source=text))
    return loaded


__all__ = [
    "Condition",
    "LoadedRule",
    "Mitre",
    "RuleLoadError",
    "RuleSpec",
    "Step",
    "load_rules",
    "parse_rule_yaml",
]
