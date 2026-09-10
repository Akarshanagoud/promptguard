"""PII detection and redaction.

Detection is validator-backed wherever the identifier has a checksum: a regex
that matches the *shape* of a credit card number produces a steady stream of
false positives on order IDs, so the Luhn check is applied before anything is
reported. The same goes for IBANs (mod-97) and US SSNs (structural rules from
the SSA's issuance scheme).

Redaction modes:
    ``mask``        keep the last 4 characters, star out the rest
    ``label``       replace with ``[EMAIL]``, ``[SSN]``, ...
    ``hash``        replace with a stable ``[EMAIL:9f2a1c]`` pseudonym so the
                    same value stays correlatable across a trace without
                    exposing the value itself
    ``remove``      delete outright
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from typing import Literal

from ..types import Finding, Severity

RedactionMode = Literal["mask", "label", "hash", "remove"]


@dataclass(frozen=True)
class PIIRule:
    rule_id: str
    entity: str
    regex: re.Pattern[str]
    severity: Severity
    validator: str | None = None


RULES: list[PIIRule] = [
    PIIRule(
        "PG-PII-001", "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        Severity.MEDIUM,
    ),
    PIIRule(
        "PG-PII-002", "PHONE",
        re.compile(r"(?<![\d-])(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})[\s.-]\d{3}[\s.-]\d{4}(?![\d-])"),
        Severity.MEDIUM,
    ),
    PIIRule(
        "PG-PII-003", "SSN",
        re.compile(r"\b(?!000|666|9\d\d)\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"),
        Severity.CRITICAL, validator="ssn",
    ),
    PIIRule(
        "PG-PII-004", "CREDIT_CARD",
        # Anchored on a final digit so the match never eats the trailing
        # separator, which would glue the replacement to the next word.
        re.compile(r"\b(?:\d[ -]?){12,18}\d\b"),
        Severity.CRITICAL, validator="luhn",
    ),
    PIIRule(
        "PG-PII-005", "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                   r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b"),
        Severity.LOW,
    ),
    PIIRule(
        "PG-PII-006", "IBAN",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        Severity.HIGH, validator="iban",
    ),
    PIIRule(
        "PG-PII-007", "DATE_OF_BIRTH",
        re.compile(r"(?i)\b(?:dob|date\s+of\s+birth|born)\s*[:=]?\s*"
                   r"(\d{1,2}[/-]\d{1,2}[/-]\d{2,4}|\d{4}-\d{2}-\d{2})"),
        Severity.HIGH,
    ),
    PIIRule(
        "PG-PII-008", "MRN",
        re.compile(r"(?i)\b(?:mrn|medical\s+record\s+(?:number|no\.?))\s*[:#=]?\s*([A-Z0-9-]{5,15})\b"),
        Severity.CRITICAL,
    ),
    PIIRule(
        "PG-PII-009", "US_PASSPORT",
        re.compile(r"(?i)\bpassport\s*(?:number|no\.?|#)?\s*[:=]?\s*([A-Z0-9]{6,9})\b"),
        Severity.HIGH,
    ),
    PIIRule(
        "PG-PII-010", "NPI",
        re.compile(r"(?i)\bnpi\s*[:#=]?\s*(\d{10})\b"),
        Severity.MEDIUM, validator="luhn_npi",
    ),
]

DEFAULT_ENTITIES = ["EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IBAN", "MRN", "DATE_OF_BIRTH"]


def luhn(digits: str) -> bool:
    """Standard mod-10 checksum used by payment cards."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13:
        return False
    total = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def valid_ssn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in {"000", "666"} or area.startswith("9"):
        return False
    if group == "00" or serial == "0000":
        return False
    # Repeated-digit strings are almost always test data, not real numbers.
    return len(set(digits)) > 1


def valid_iban(value: str) -> bool:
    compact = re.sub(r"\s", "", value).upper()
    if len(compact) < 15 or len(compact) > 34:
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        numeric = "".join(str(int(c, 36)) for c in rearranged)
    except ValueError:
        return False
    return int(numeric) % 97 == 1


def valid_npi(value: str) -> bool:
    """NPI uses Luhn over the number prefixed with the 80840 issuer id."""
    digits = re.sub(r"\D", "", value)
    return len(digits) == 10 and luhn("80840" + digits)


_VALIDATORS = {
    "luhn": lambda v: luhn(v),
    "ssn": valid_ssn,
    "iban": valid_iban,
    "luhn_npi": valid_npi,
}


def _captured(match: re.Match[str]) -> tuple[str, tuple[int, int]]:
    if match.groups() and match.group(1):
        return match.group(1), match.span(1)
    return match.group(0), match.span()


def detect(text: str, entities: list[str] | None = None) -> list[Finding]:
    """Find PII entities in ``text``, restricted to ``entities`` when given."""
    wanted = set(entities) if entities is not None else set(DEFAULT_ENTITIES)
    findings: list[Finding] = []
    claimed: list[tuple[int, int]] = []

    for rule in RULES:
        if rule.entity not in wanted:
            continue
        for match in rule.regex.finditer(text):
            value, span = _captured(match)
            if rule.validator and not _VALIDATORS[rule.validator](value):
                continue
            # A credit-card regex happily swallows a phone number; first rule
            # to claim a span wins, and rules are ordered most-specific-first.
            if any(span[0] < end and start < span[1] for start, end in claimed):
                continue
            claimed.append(span)
            findings.append(
                Finding(
                    rule_id=rule.rule_id,
                    category="pii",
                    severity=rule.severity,
                    message=f"{rule.entity.replace('_', ' ').lower()} detected",
                    score=0.9 if rule.validator else 0.7,
                    span=span,
                    evidence=mask_value(value),
                    metadata={"entity": rule.entity, "validated": bool(rule.validator)},
                )
            )

    findings.sort(key=lambda f: (f.span or (0, 0))[0])
    return findings


def mask_value(value: str, keep: int = 4) -> str:
    visible = value[-keep:] if len(value) > keep else ""
    return f"{'*' * max(len(value) - len(visible), 0)}{visible}"


def _pseudonym(entity: str, value: str, salt: str) -> str:
    digest = hashlib.sha256(f"{salt}:{entity}:{value}".encode()).hexdigest()[:6]
    return f"[{entity}:{digest}]"


def redact(
    text: str,
    entities: list[str] | None = None,
    mode: RedactionMode = "label",
    salt: str = "promptguard",
) -> tuple[str, list[Finding]]:
    """Return ``text`` with PII rewritten according to ``mode``, plus findings."""
    findings = detect(text, entities)
    if not findings:
        return text, []

    out = text
    for finding in sorted(findings, key=lambda f: (f.span or (0, 0))[0], reverse=True):
        if finding.span is None:
            continue
        start, end = finding.span
        entity = str(finding.metadata["entity"])
        original = text[start:end]
        if mode == "mask":
            replacement = mask_value(original)
        elif mode == "hash":
            replacement = _pseudonym(entity, original, salt)
        elif mode == "remove":
            replacement = ""
        else:
            replacement = f"[{entity}]"
        out = out[:start] + replacement + out[end:]

    return out, findings
