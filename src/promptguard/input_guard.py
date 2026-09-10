"""Input guard: everything that runs before text reaches the model."""
from __future__ import annotations

import time

from .config import GuardConfig, InputPolicy
from .detectors import injection, jailbreak, secrets
from .policy import pii
from .types import Action, Finding, GuardrailViolation, GuardResult, Severity


class InputGuard:
    """Validates and sanitizes prompts.

    The guard never raises on detection — it returns a decision. Callers that
    want exceptions use :meth:`enforce`. That split keeps the common path
    (log everything, block a little) free of exception handling.
    """

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()

    @property
    def policy(self) -> InputPolicy:
        return self.config.input

    def check(self, text: str, *, context: str = "user") -> GuardResult:
        """Run every enabled detector over ``text`` and decide an action.

        ``context`` distinguishes first-party user input from text that arrived
        via a retrieved document or tool result. Retrieved content is scored
        more harshly, since a document has no legitimate reason to issue
        instructions to the model.
        """
        started = time.perf_counter()
        policy = self.policy
        findings: list[Finding] = []
        working = text

        if len(text) > policy.max_chars:
            findings.append(
                Finding(
                    rule_id="PG-IN-001",
                    category="input_limit",
                    severity=Severity.MEDIUM,
                    message=f"input of {len(text)} chars exceeds limit of {policy.max_chars}",
                    score=0.5,
                    metadata={"length": len(text), "limit": policy.max_chars},
                )
            )
            working = working[: policy.max_chars]

        if policy.detect_injection:
            findings.extend(injection.detect(text))
        if policy.detect_jailbreak:
            findings.extend(jailbreak.detect(text))
        if policy.detect_secrets:
            secret_findings = secrets.detect(text)
            findings.extend(secret_findings)
            if secret_findings and policy.redact_secrets:
                working, _ = secrets.redact(working)
        if policy.detect_pii:
            working, pii_findings = pii.redact(
                working,
                entities=policy.pii_entities,
                mode=policy.pii_mode,
                salt=self.config.compliance.hash_salt,
            )
            findings.extend(pii_findings)

        findings = [f for f in findings if f.rule_id not in set(policy.allow_rules)]

        if context != "user":
            findings = [_escalate(f, context) for f in findings]

        remediated = _remediated_categories(policy)
        residual = [f for f in findings if f.category not in remediated]

        action = _decide(
            residual,
            risk_score(residual),
            block_threshold=policy.block_threshold,
            flag_threshold=policy.flag_threshold,
            block_on_severity=policy.block_on_severity,
            modified=working != text,
        )

        return GuardResult(
            action=action,
            text=working,
            original=text,
            findings=findings,
            risk_score=risk_score(residual),
            detected_risk=risk_score(findings),
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )

    def enforce(self, text: str, *, context: str = "user") -> str:
        """Return the sanitized prompt, or raise :class:`GuardrailViolation`."""
        result = self.check(text, context=context)
        if result.action is Action.BLOCK:
            raise GuardrailViolation(result)
        return result.text

    def check_messages(self, messages: list[dict[str, str]]) -> list[GuardResult]:
        """Guard a chat-style message list, one result per message.

        Non-user roles are checked as ``context="system"`` so an injected
        "assistant" turn is treated with the suspicion it deserves.
        """
        results = []
        for message in messages:
            role = message.get("role", "user")
            context = "user" if role == "user" else "system"
            results.append(self.check(message.get("content", ""), context=context))
        return results


def _escalate(finding: Finding, context: str) -> Finding:
    """Bump severity for signals arriving through non-user channels."""
    if finding.category not in {"prompt_injection", "jailbreak"}:
        return finding
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    index = min(order.index(finding.severity) + 1, len(order) - 1)
    return Finding(
        rule_id=finding.rule_id,
        category=finding.category,
        severity=order[index],
        message=f"{finding.message} (via {context} channel)",
        score=min(1.0, finding.score + 0.1),
        span=finding.span,
        evidence=finding.evidence,
        metadata={**finding.metadata, "channel": context, "escalated": True},
    )


def _remediated_categories(policy: InputPolicy) -> set[str]:
    """Categories the guard fixes in place, so they must not force a block.

    Blocking a request whose only problem was a phone number the guard already
    replaced would be punishing the user for something already handled — the
    finding still reaches the audit log, it just does not gate the request.
    """
    remediated: set[str] = set()
    if policy.detect_pii:
        remediated.add("pii")
    if policy.detect_secrets and policy.redact_secrets:
        remediated.add("secret")
    return remediated


def risk_score(findings: list[Finding]) -> float:
    """Combine finding scores with a noisy-or, so signals reinforce but saturate.

    A straight max under-reports a prompt that trips five medium rules; a sum
    over-reports and clips constantly. Noisy-or does neither.
    """
    if not findings:
        return 0.0
    inverse = 1.0
    for finding in findings:
        inverse *= 1.0 - min(max(finding.score, 0.0), 0.99)
    return round(1.0 - inverse, 4)


def _decide(
    findings: list[Finding],
    risk: float,
    *,
    block_threshold: float,
    flag_threshold: float,
    block_on_severity: Severity,
    modified: bool,
) -> Action:
    if findings and max(f.severity for f in findings) >= block_on_severity:
        return Action.BLOCK
    if risk >= block_threshold:
        return Action.BLOCK
    if modified:
        return Action.REDACT
    if risk >= flag_threshold:
        return Action.FLAG
    return Action.ALLOW
