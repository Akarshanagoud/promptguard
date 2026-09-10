"""Core value types shared across input guards, output policies and audit."""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Ordered severity levels. Comparison is by rank, not string value."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]

    # All four comparisons are defined explicitly: this enum inherits ``str``,
    # so without them ``Severity.MEDIUM >= Severity.CRITICAL`` would silently
    # compare the strings and evaluate to True.
    def __lt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:  # type: ignore[override]
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_RANK = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class Action(str, Enum):
    """What the guard decided to do with the payload."""

    ALLOW = "allow"
    REDACT = "redact"
    FLAG = "flag"
    BLOCK = "block"


@dataclass(frozen=True)
class Finding:
    """A single thing a detector or policy noticed about the payload."""

    rule_id: str
    category: str
    severity: Severity
    message: str
    score: float = 0.0
    span: tuple[int, int] | None = None
    evidence: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.value,
            "message": self.message,
            "score": round(self.score, 4),
            "span": list(self.span) if self.span else None,
            "evidence": self.evidence,
            "metadata": self.metadata,
        }


@dataclass
class GuardResult:
    """Outcome of running a guard over one payload.

    ``text`` is the payload the caller should actually use downstream: for a
    redacting policy it is the rewritten string, otherwise the original.
    """

    action: Action
    text: str
    original: str
    findings: list[Finding] = field(default_factory=list)
    #: Risk that remains *after* remediation. This is what drives the decision:
    #: a credit card number that the guard already redacted is no longer a
    #: reason to block the request.
    risk_score: float = 0.0
    #: Risk implied by everything detected, before remediation. Reported for
    #: dashboards and trend analysis, never used for enforcement.
    detected_risk: float = 0.0
    elapsed_ms: float = 0.0
    created_at: float = field(default_factory=time.time)

    @property
    def allowed(self) -> bool:
        return self.action is not Action.BLOCK

    @property
    def modified(self) -> bool:
        return self.text != self.original

    @property
    def max_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max(f.severity for f in self.findings)

    def categories(self) -> list[str]:
        seen: dict[str, None] = {}
        for f in self.findings:
            seen.setdefault(f.category, None)
        return list(seen)

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action.value,
            "allowed": self.allowed,
            "modified": self.modified,
            "risk_score": round(self.risk_score, 4),
            "detected_risk": round(self.detected_risk, 4),
            "max_severity": self.max_severity.value,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "findings": [f.to_dict() for f in self.findings],
            "text": self.text,
        }


class GuardrailViolation(Exception):
    """Raised by the strict helpers when a payload is blocked."""

    def __init__(self, result: GuardResult) -> None:
        cats = ", ".join(result.categories()) or "policy"
        super().__init__(f"blocked by guardrail ({cats}), risk={result.risk_score:.2f}")
        self.result = result
