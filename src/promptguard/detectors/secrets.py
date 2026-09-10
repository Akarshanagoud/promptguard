"""Credential and secret detection for prompts and model output.

Two failure modes matter here and they point in opposite directions:

* a user pastes a live API key into a prompt, which then lands in a provider's
  logs and in your own trace store;
* a model echoes a credential it picked up from retrieved context.

Both are caught by the same rules, so this module is shared by the input guard
and the output policy engine.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass

from ..types import Finding, Severity


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    name: str
    regex: re.Pattern[str]
    severity: Severity
    min_entropy: float = 0.0


RULES: list[SecretRule] = [
    SecretRule(
        "PG-SEC-001", "aws_access_key_id",
        re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b"), Severity.CRITICAL,
    ),
    SecretRule(
        "PG-SEC-002", "aws_secret_access_key",
        re.compile(r"(?i)aws[_\-\s]*secret[_\-\s]*(?:access[_\-\s]*)?key\s*[:=]\s*"
                   r"['\"]?([A-Za-z0-9/+=]{40})['\"]?"),
        Severity.CRITICAL,
    ),
    SecretRule(
        "PG-SEC-003", "github_token",
        re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL,
    ),
    SecretRule(
        "PG-SEC-004", "slack_token",
        re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH,
    ),
    SecretRule(
        "PG-SEC-005", "private_key_block",
        re.compile(r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|PGP)?\s*PRIVATE KEY(?:\s+BLOCK)?-----"),
        Severity.CRITICAL,
    ),
    SecretRule(
        "PG-SEC-006", "jwt",
        re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"),
        Severity.HIGH,
    ),
    SecretRule(
        "PG-SEC-007", "google_api_key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), Severity.HIGH,
    ),
    SecretRule(
        "PG-SEC-008", "bearer_token",
        re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/-]{24,})\b"), Severity.HIGH, min_entropy=3.5,
    ),
    SecretRule(
        "PG-SEC-009", "generic_api_key",
        re.compile(r"(?i)\b(?:api[_\-\s]?key|apikey|secret|token|passwd|password)\s*[:=]\s*"
                   r"['\"]?([A-Za-z0-9_\-!@#$%^&*./+=]{16,})['\"]?"),
        Severity.HIGH, min_entropy=3.2,
    ),
    SecretRule(
        "PG-SEC-010", "database_url",
        re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://"
                   r"[^\s:@/]+:[^\s:@/]+@[^\s/]+"),
        Severity.CRITICAL,
    ),
    SecretRule(
        "PG-SEC-011", "stripe_key",
        re.compile(r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,}\b"), Severity.CRITICAL,
    ),
]

# Values that trip the generic rules but carry no risk.
_PLACEHOLDERS = re.compile(
    r"(?i)^(?:x{4,}|\*{4,}|\.{3,}|<[^>]+>|\{\{.*\}\}|\$\{.*\}|"
    r"your[_\-]?(?:api[_\-]?)?key|changeme|placeholder|example|redacted|dummy|"
    r"none|null|true|false|test{1,2}|sample|todo|fixme)[_\-]?\w*$"
)


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _captured(match: re.Match[str]) -> str:
    """The secret itself: the first capture group if the rule defines one."""
    if match.groups():
        return match.group(1) or match.group(0)
    return match.group(0)


def detect(text: str) -> list[Finding]:
    """Return one finding per distinct secret value found in ``text``."""
    findings: list[Finding] = []
    seen: set[str] = set()

    for rule in RULES:
        for match in rule.regex.finditer(text):
            value = _captured(match)
            if value in seen:
                continue
            if _PLACEHOLDERS.match(value.strip()):
                continue
            if rule.min_entropy and _entropy(value) < rule.min_entropy:
                continue
            seen.add(value)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="secret",
                    severity=rule.severity,
                    message=f"possible {rule.name.replace('_', ' ')} in payload",
                    score=0.95 if rule.severity is Severity.CRITICAL else 0.75,
                    span=match.span(),
                    evidence=mask(value),
                    metadata={"secret_type": rule.name, "entropy": round(_entropy(value), 2)},
                )
            )

    return findings


def mask(value: str, keep: int = 4) -> str:
    """Mask a secret for safe logging, keeping a short prefix for correlation."""
    if len(value) <= keep:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(len(value) - keep, 20)}"


def redact(text: str, replacement: str = "[REDACTED_SECRET]") -> tuple[str, list[Finding]]:
    """Strip every detected secret from ``text``.

    Spans are replaced right-to-left so earlier offsets stay valid.
    """
    findings = detect(text)
    if not findings:
        return text, []
    spans = sorted((f.span for f in findings if f.span), key=lambda s: s[0], reverse=True)
    out = text
    for start, end in spans:
        out = out[:start] + replacement + out[end:]
    return out, findings
