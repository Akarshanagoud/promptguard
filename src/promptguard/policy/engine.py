"""Output policy engine.

The engine runs an ordered pipeline of stages over model output. Each stage
may rewrite the text, emit findings, or both, and the engine keeps the running
text so later stages see the already-redacted version — schema validation, for
example, should run against the text that will actually be returned.

Stages are ordinary callables, so an application can register its own:

    engine.add_stage("no_competitor_names", my_stage, position=0)
"""
from __future__ import annotations

import time
from collections.abc import Callable

from ..config import GuardConfig, OutputPolicy
from ..detectors import secrets
from ..types import Action, Finding, GuardResult, Severity
from . import pii, toxicity
from . import schema as schema_policy

Stage = Callable[[str, OutputPolicy], tuple[str, list[Finding]]]


def _stage_secrets(text: str, policy: OutputPolicy) -> tuple[str, list[Finding]]:
    if not policy.redact_secrets:
        return text, []
    return secrets.redact(text)


def _stage_pii(text: str, policy: OutputPolicy) -> tuple[str, list[Finding]]:
    if not policy.redact_pii:
        return text, pii.detect(text, policy.pii_entities)
    return pii.redact(text, entities=policy.pii_entities, mode=policy.pii_mode)


def _stage_toxicity(text: str, policy: OutputPolicy) -> tuple[str, list[Finding]]:
    if not policy.check_toxicity:
        return text, []
    return text, toxicity.detect(text, policy.toxicity_thresholds)


def _stage_schema(text: str, policy: OutputPolicy) -> tuple[str, list[Finding]]:
    if not policy.check_schema or not policy.json_schema:
        return text, []
    _, findings = schema_policy.validate(text, policy.json_schema)
    return text, findings


DEFAULT_STAGES: list[tuple[str, Stage]] = [
    ("secrets", _stage_secrets),
    ("pii", _stage_pii),
    ("toxicity", _stage_toxicity),
    ("schema", _stage_schema),
]


class PolicyEngine:
    """Applies the configured output policy to model responses."""

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self.stages: list[tuple[str, Stage]] = list(DEFAULT_STAGES)

    @property
    def policy(self) -> OutputPolicy:
        return self.config.output

    def add_stage(self, name: str, stage: Stage, position: int | None = None) -> None:
        """Insert a custom stage. Later stages see earlier stages' rewrites."""
        entry = (name, stage)
        if position is None:
            self.stages.append(entry)
        else:
            self.stages.insert(position, entry)

    def remove_stage(self, name: str) -> bool:
        before = len(self.stages)
        self.stages = [s for s in self.stages if s[0] != name]
        return len(self.stages) < before

    def apply(self, text: str) -> GuardResult:
        started = time.perf_counter()
        policy = self.policy
        working = text
        findings: list[Finding] = []

        for name, stage in self.stages:
            try:
                working, stage_findings = stage(working, policy)
            except Exception as exc:  # noqa: BLE001 - a bad stage must not 500 the app
                if not self.config.fail_open:
                    raise
                findings.append(
                    Finding(
                        rule_id="PG-OUT-900",
                        category="engine_error",
                        severity=Severity.LOW,
                        message=f"stage {name!r} failed and was skipped: {exc}",
                        score=0.0,
                        metadata={"stage": name},
                    )
                )
                continue
            findings.extend(stage_findings)

        allow = set(policy.allow_rules)
        findings = [f for f in findings if f.rule_id not in allow]

        remediated = _remediated_categories(policy)
        residual = [f for f in findings if f.category not in remediated]

        action = _decide(residual, _noisy_or(residual), policy, modified=working != text)

        return GuardResult(
            action=action,
            text=working,
            original=text,
            findings=findings,
            risk_score=_noisy_or(residual),
            detected_risk=_noisy_or(findings),
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )


def _remediated_categories(policy: OutputPolicy) -> set[str]:
    """Categories rewritten in place, which therefore do not gate the response.

    PII only counts as remediated when redaction is actually enabled: with
    ``redact_pii = False`` the engine merely reports it, and an unredacted
    identifier in model output is a real reason to block.
    """
    remediated: set[str] = set()
    if policy.redact_pii:
        remediated.add("pii")
    if policy.redact_secrets:
        remediated.add("secret")
    return remediated


def _noisy_or(findings: list[Finding]) -> float:
    if not findings:
        return 0.0
    inverse = 1.0
    for finding in findings:
        inverse *= 1.0 - min(max(finding.score, 0.0), 0.99)
    return round(1.0 - inverse, 4)


def _decide(
    findings: list[Finding], risk: float, policy: OutputPolicy, *, modified: bool
) -> Action:
    if findings and max(f.severity for f in findings) >= policy.block_on_severity:
        return Action.BLOCK
    if risk >= policy.block_threshold:
        return Action.BLOCK
    if modified:
        return Action.REDACT
    if risk >= policy.flag_threshold:
        return Action.FLAG
    return Action.ALLOW
