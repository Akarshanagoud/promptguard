"""Control-framework mapping.

A finding on its own tells an engineer what happened. A finding mapped to
OWASP LLM01 or NIST AI RMF MEASURE-2.7 tells an auditor the control exists and
fired. This module is the lookup table between the two, plus a report builder
that rolls a batch of results up into per-control coverage.

Framework references are stable identifiers, not quoted control text.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from .types import Finding, GuardResult


@dataclass(frozen=True)
class Control:
    framework: str
    control_id: str
    title: str


# OWASP Top 10 for LLM Applications (2025 revision identifiers).
OWASP_LLM = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM09": "Misinformation",
}

# NIST AI Risk Management Framework function/category identifiers.
NIST_AI_RMF = {
    "MEASURE-2.7": "AI system security and resilience are evaluated",
    "MEASURE-2.10": "Privacy risk of the AI system is examined",
    "MANAGE-2.2": "Mechanisms are in place to sustain AI system value",
    "GOVERN-1.2": "Trustworthy AI characteristics are integrated into policy",
}

# EU AI Act article references relevant to transparency and record-keeping.
EU_AI_ACT = {
    "Art.12": "Record-keeping and automatic logging",
    "Art.13": "Transparency and provision of information",
    "Art.15": "Accuracy, robustness and cybersecurity",
}

# Category -> controls. Keyed on Finding.category so new rules inherit mapping.
CATEGORY_CONTROLS: dict[str, list[Control]] = {
    "prompt_injection": [
        Control("owasp_llm", "LLM01", OWASP_LLM["LLM01"]),
        Control("nist_ai_rmf", "MEASURE-2.7", NIST_AI_RMF["MEASURE-2.7"]),
        Control("eu_ai_act", "Art.15", EU_AI_ACT["Art.15"]),
    ],
    "jailbreak": [
        Control("owasp_llm", "LLM01", OWASP_LLM["LLM01"]),
        Control("nist_ai_rmf", "MEASURE-2.7", NIST_AI_RMF["MEASURE-2.7"]),
    ],
    "pii": [
        Control("owasp_llm", "LLM02", OWASP_LLM["LLM02"]),
        Control("nist_ai_rmf", "MEASURE-2.10", NIST_AI_RMF["MEASURE-2.10"]),
        Control("eu_ai_act", "Art.13", EU_AI_ACT["Art.13"]),
    ],
    "secret": [
        Control("owasp_llm", "LLM02", OWASP_LLM["LLM02"]),
        Control("nist_ai_rmf", "MEASURE-2.10", NIST_AI_RMF["MEASURE-2.10"]),
    ],
    "toxicity": [
        Control("owasp_llm", "LLM05", OWASP_LLM["LLM05"]),
        Control("nist_ai_rmf", "GOVERN-1.2", NIST_AI_RMF["GOVERN-1.2"]),
    ],
    "schema": [
        Control("owasp_llm", "LLM05", OWASP_LLM["LLM05"]),
        Control("nist_ai_rmf", "MANAGE-2.2", NIST_AI_RMF["MANAGE-2.2"]),
    ],
    "input_limit": [
        Control("owasp_llm", "LLM06", OWASP_LLM["LLM06"]),
    ],
}


def controls_for(finding: Finding, frameworks: list[str] | None = None) -> list[Control]:
    """Controls a single finding provides evidence for."""
    controls = CATEGORY_CONTROLS.get(finding.category, [])
    if frameworks is None:
        return controls
    wanted = set(frameworks)
    return [c for c in controls if c.framework in wanted]


def annotate(finding: Finding, frameworks: list[str] | None = None) -> dict[str, Any]:
    """Finding as a dict, with its control mappings attached."""
    payload = finding.to_dict()
    payload["controls"] = [
        {"framework": c.framework, "control_id": c.control_id, "title": c.title}
        for c in controls_for(finding, frameworks)
    ]
    return payload


@dataclass
class ComplianceReport:
    total_requests: int = 0
    blocked: int = 0
    redacted: int = 0
    flagged: int = 0
    findings_by_category: dict[str, int] = field(default_factory=dict)
    controls_exercised: dict[str, int] = field(default_factory=dict)
    top_rules: list[tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_requests": self.total_requests,
            "blocked": self.blocked,
            "redacted": self.redacted,
            "flagged": self.flagged,
            "block_rate": round(self.blocked / self.total_requests, 4)
            if self.total_requests
            else 0.0,
            "findings_by_category": self.findings_by_category,
            "controls_exercised": self.controls_exercised,
            "top_rules": [{"rule_id": r, "count": c} for r, c in self.top_rules],
        }

    def render(self) -> str:
        lines = [
            f"Requests evaluated : {self.total_requests}",
            f"  blocked          : {self.blocked}",
            f"  redacted         : {self.redacted}",
            f"  flagged          : {self.flagged}",
            "",
            "Findings by category:",
        ]
        for category, count in sorted(self.findings_by_category.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {category:<20} {count}")
        lines += ["", "Controls exercised:"]
        for control, count in sorted(self.controls_exercised.items()):
            lines.append(f"  {control:<28} {count}")
        if self.top_rules:
            lines += ["", "Most frequent rules:"]
            for rule_id, count in self.top_rules:
                lines.append(f"  {rule_id:<16} {count}")
        return "\n".join(lines)


def build_report(
    results: list[GuardResult], frameworks: list[str] | None = None
) -> ComplianceReport:
    """Roll a batch of guard results into a control-coverage report."""
    report = ComplianceReport(total_requests=len(results))
    categories: Counter[str] = Counter()
    controls: Counter[str] = Counter()
    rules: Counter[str] = Counter()

    for result in results:
        if result.action.value == "block":
            report.blocked += 1
        elif result.action.value == "redact":
            report.redacted += 1
        elif result.action.value == "flag":
            report.flagged += 1

        for finding in result.findings:
            categories[finding.category] += 1
            rules[finding.rule_id] += 1
            for control in controls_for(finding, frameworks):
                controls[f"{control.framework}:{control.control_id}"] += 1

    report.findings_by_category = dict(categories)
    report.controls_exercised = dict(controls)
    report.top_rules = rules.most_common(10)
    return report
