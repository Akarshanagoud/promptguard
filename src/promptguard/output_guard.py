"""Output guard: the caller-facing wrapper around the policy engine."""
from __future__ import annotations

from typing import Any

from .config import GuardConfig
from .policy import schema as schema_policy
from .policy.engine import PolicyEngine, Stage
from .types import Action, GuardrailViolation, GuardResult


class OutputGuard:
    """Validates and sanitizes model responses before they reach the user."""

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self.engine = PolicyEngine(self.config)

    def check(self, text: str) -> GuardResult:
        return self.engine.apply(text)

    def enforce(self, text: str) -> str:
        """Return the policy-compliant response, or raise on a block."""
        result = self.check(text)
        if result.action is Action.BLOCK:
            raise GuardrailViolation(result)
        return result.text

    def check_structured(
        self, text: str, json_schema: dict[str, Any]
    ) -> tuple[Any | None, GuardResult]:
        """Validate ``text`` against ``json_schema`` and run the full policy.

        Returns the parsed object alongside the guard result so a caller can
        act on structurally valid output even when the policy flagged it.
        """
        result = self.check(text)
        value, findings = schema_policy.validate(result.text, json_schema)
        if findings:
            result.findings.extend(findings)
            result.risk_score = max(result.risk_score, max(f.score for f in findings))
            if result.action is Action.ALLOW:
                result.action = Action.FLAG
        return value, result

    def add_stage(self, name: str, stage: Stage, position: int | None = None) -> None:
        self.engine.add_stage(name, stage, position)
