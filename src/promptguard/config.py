"""Declarative guard configuration.

Policy lives in a YAML/JSON file rather than in code so that changing a
toxicity threshold or adding a blocked category is a config review, not a
deploy. ``GuardConfig.from_file`` is the only place that reads it, and every
field has a defensible default so an empty file still yields a working guard.

YAML is used when PyYAML is available; otherwise JSON files work unchanged.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from .policy.pii import DEFAULT_ENTITIES, RedactionMode
from .types import Action, Severity

try:
    import yaml as _yaml
except ImportError:  # pragma: no cover
    _yaml = None


@dataclass
class InputPolicy:
    """Controls applied to text on its way *into* the model."""

    detect_injection: bool = True
    detect_jailbreak: bool = True
    detect_secrets: bool = True
    detect_pii: bool = True
    pii_entities: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITIES))
    pii_mode: RedactionMode = "hash"
    redact_secrets: bool = True
    max_chars: int = 32_000
    block_threshold: float = 0.75
    flag_threshold: float = 0.4
    block_on_severity: Severity = Severity.CRITICAL
    allow_rules: list[str] = field(default_factory=list)


@dataclass
class OutputPolicy:
    """Controls applied to text on its way *out of* the model."""

    redact_pii: bool = True
    pii_entities: list[str] = field(default_factory=lambda: list(DEFAULT_ENTITIES))
    pii_mode: RedactionMode = "label"
    redact_secrets: bool = True
    check_toxicity: bool = True
    toxicity_thresholds: dict[str, float] = field(
        default_factory=lambda: {
            "harassment": 0.5,
            "hate": 0.4,
            "violence": 0.5,
            "self_harm": 0.4,
            "sexual": 0.6,
            "profanity": 0.8,
        }
    )
    check_schema: bool = False
    json_schema: dict[str, Any] | None = None
    block_threshold: float = 0.75
    flag_threshold: float = 0.4
    block_on_severity: Severity = Severity.CRITICAL
    allow_rules: list[str] = field(default_factory=list)


@dataclass
class ComplianceConfig:
    """Which control frameworks the audit log should annotate findings with."""

    frameworks: list[str] = field(default_factory=lambda: ["owasp_llm", "nist_ai_rmf"])
    audit_log_path: str | None = None
    log_payloads: bool = False
    hash_salt: str = "promptguard"
    retention_days: int = 90


@dataclass
class GuardConfig:
    name: str = "default"
    input: InputPolicy = field(default_factory=InputPolicy)
    output: OutputPolicy = field(default_factory=OutputPolicy)
    compliance: ComplianceConfig = field(default_factory=ComplianceConfig)
    fail_open: bool = False

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> GuardConfig:
        data = dict(data or {})
        return cls(
            name=data.get("name", "default"),
            input=_build(InputPolicy, data.get("input", {})),
            output=_build(OutputPolicy, data.get("output", {})),
            compliance=_build(ComplianceConfig, data.get("compliance", {})),
            fail_open=bool(data.get("fail_open", False)),
        )

    @classmethod
    def from_file(cls, path: str | Path) -> GuardConfig:
        raw = Path(path).read_text(encoding="utf-8")
        if Path(path).suffix in {".yaml", ".yml"}:
            if _yaml is None:
                raise RuntimeError(
                    "PyYAML is required to load YAML policies; "
                    "install promptguard[yaml] or use a .json policy file"
                )
            data = _yaml.safe_load(raw) or {}
        else:
            data = json.loads(raw)
        return cls.from_dict(data)

    @classmethod
    def strict(cls) -> GuardConfig:
        """A conservative preset for regulated or externally exposed surfaces."""
        cfg = cls(name="strict")
        cfg.input.block_threshold = 0.5
        cfg.input.flag_threshold = 0.25
        cfg.input.block_on_severity = Severity.HIGH
        cfg.output.block_threshold = 0.5
        cfg.output.block_on_severity = Severity.HIGH
        cfg.output.toxicity_thresholds = {k: 0.3 for k in cfg.output.toxicity_thresholds}
        cfg.compliance.log_payloads = False
        return cfg

    @classmethod
    def permissive(cls) -> GuardConfig:
        """Observe-and-log preset: nothing is blocked, everything is recorded."""
        cfg = cls(name="permissive")
        cfg.input.block_threshold = 1.1
        cfg.input.block_on_severity = Severity.CRITICAL
        cfg.output.block_threshold = 1.1
        cfg.output.redact_pii = False
        cfg.fail_open = True
        return cfg

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["input"]["block_on_severity"] = self.input.block_on_severity.value
        data["output"]["block_on_severity"] = self.output.block_on_severity.value
        return data


def _build(kind: type, values: dict[str, Any]):
    """Instantiate a policy dataclass from a dict, ignoring unknown keys."""
    known = {f.name for f in kind.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    kwargs: dict[str, Any] = {}
    for key, value in (values or {}).items():
        if key not in known:
            raise ValueError(f"unknown {kind.__name__} option: {key!r}")
        if key == "block_on_severity" and isinstance(value, str):
            value = Severity(value.lower())
        kwargs[key] = value
    return kind(**kwargs)


DEFAULT_ACTION_BY_NAME = {a.value: a for a in Action}
