"""Jailbreak pattern filtering.

Injection is about *hijacking* the instruction channel; jailbreaking is about
*eroding* the safety policy while leaving the instruction channel intact. They
overlap, but they fail differently and deserve separate scores — a support bot
may tolerate roleplay framing while never tolerating a system-prompt override.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..types import Finding, Severity


@dataclass(frozen=True)
class JailbreakPattern:
    rule_id: str
    regex: re.Pattern[str]
    severity: Severity
    weight: float
    technique: str
    message: str


def _j(
    rule_id: str, pattern: str, severity: Severity, weight: float, technique: str, message: str
) -> JailbreakPattern:
    return JailbreakPattern(
        rule_id, re.compile(pattern, re.IGNORECASE), severity, weight, technique, message
    )


PATTERNS: list[JailbreakPattern] = [
    # Persona split — "there are two of you, the other one has no rules"
    _j(
        "PG-JB-001",
        r"\b(dan|do\s+anything\s+now|developer\s+mode|dev\s+mode|jailbr[eo]ak|"
        r"unfiltered\s+mode|god\s*mode|sudo\s+mode)\b",
        Severity.HIGH,
        0.8,
        "persona_split",
        "references a known jailbreak persona or mode",
    ),
    _j(
        "PG-JB-002",
        r"\b(pretend|imagine|act\s+as\s+if|roleplay|role-play|simulate)\b[^.\n]{0,60}"
        r"\b(?:no\s+(?:\w+\s+){0,2}(?:restrictions|rules|filters|limits|guidelines|guardrails)"
        r"|without\s+(?:any\s+)?(?:\w+\s+){0,2}"
        r"(?:restrictions|rules|filters|limits|guidelines|guardrails|safeguards)"
        r"|unrestricted|uncensored)\b",
        Severity.HIGH,
        0.85,
        "persona_split",
        "requests a persona explicitly defined as having no restrictions",
    ),
    _j(
        "PG-JB-003",
        r"\byou\s+have\s+no\b[^.\n]{0,25}\b(restrictions|filters|guidelines|rules|"
        r"ethics|morals|limitations)\b",
        Severity.HIGH,
        0.8,
        "persona_split",
        "asserts the model has no safety constraints",
    ),
    # Policy negation
    _j(
        "PG-JB-010",
        r"\b(bypass|circumvent|get\s+around|work\s+around|override|turn\s+off|disable)\b"
        r"[^.\n]{0,30}\b(safety|filter|guardrail|content\s+polic|restriction|moderation|"
        r"censorship|alignment)\w*\b",
        Severity.CRITICAL,
        0.9,
        "policy_negation",
        "explicitly asks to bypass safety controls",
    ),
    _j(
        "PG-JB-011",
        r"\b(don'?t|do\s+not|never)\b[^.\n]{0,20}\b(refuse|decline|apolog|say\s+you\s+can'?t|"
        r"warn|lecture|moraliz)\w*\b",
        Severity.MEDIUM,
        0.6,
        "policy_negation",
        "pre-empts refusal behaviour",
    ),
    _j(
        "PG-JB-012",
        r"\b(answer|respond|reply|comply)\b[^.\n]{0,25}\b(no\s+matter\s+what|regardless\s+of|"
        r"even\s+if\s+(it'?s\s+)?(illegal|harmful|unethical|dangerous))\b",
        Severity.HIGH,
        0.8,
        "policy_negation",
        "demands compliance regardless of harm",
    ),
    # Fictional / hypothetical framing used as a wrapper
    _j(
        "PG-JB-020",
        r"\b(hypothetical|fictional|in\s+a\s+(story|novel|movie|game)|for\s+a\s+(novel|screenplay))\b"
        r"[^.\n]{0,80}\b(how\s+to\s+(make|build|synthesiz|hack|steal|kill)|step[-\s]by[-\s]step)\w*\b",
        Severity.HIGH,
        0.75,
        "fictional_framing",
        "fictional wrapper around an operational how-to request",
    ),
    _j(
        "PG-JB-021",
        r"\bmy\s+(dead\s+)?(grandmother|grandma|grandfather)\b[^.\n]{0,60}\b(used\s+to|would)\b",
        Severity.MEDIUM,
        0.65,
        "emotional_framing",
        "sentimental framing used to launder a restricted request",
    ),
    _j(
        "PG-JB-022",
        r"\b(this\s+is\s+(just\s+)?(a\s+test|for\s+research|educational|academic)|"
        r"i\s+am\s+a\s+(security\s+)?(researcher|professor|pentester))\b[^.\n]{0,60}"
        r"\b(so\s+you\s+can|therefore\s+you|which\s+means\s+you)\b",
        Severity.MEDIUM,
        0.6,
        "authority_framing",
        "claimed authority used to justify relaxed rules",
    ),
    # Output-shape coercion
    _j(
        "PG-JB-030",
        r"\b(start|begin)\s+(your\s+)?(response|reply|answer)\s+with\b[^.\n]{0,40}"
        r"\b(sure|certainly|absolutely|of\s+course|here'?s\s+how)\b",
        Severity.HIGH,
        0.75,
        "prefix_injection",
        "forces an affirmative response prefix (prefix-injection attack)",
    ),
    _j(
        "PG-JB-031",
        r"\brespond\s+(only\s+)?(in|with)\b[^.\n]{0,30}\b(base64|rot13|leetspeak|morse|"
        r"reversed?\s+text)\b",
        Severity.MEDIUM,
        0.6,
        "encoding_evasion",
        "requests an encoded response to evade output filters",
    ),
    _j(
        "PG-JB-032",
        r"\b(two|both)\s+(responses|answers|versions)\b[^.\n]{0,50}"
        r"\b(one\s+(normal|filtered|safe)|one\s+(unfiltered|uncensored|jailbroken))\b",
        Severity.HIGH,
        0.8,
        "dual_response",
        "requests a paired filtered/unfiltered response",
    ),
    # Token / continuation attacks
    _j(
        "PG-JB-040",
        r"\bcontinue\s+(the\s+)?(text|story|list)\b[^.\n]{0,40}\bdo\s+not\s+(stop|refuse|break)\b",
        Severity.MEDIUM,
        0.55,
        "continuation",
        "continuation framing with an explicit no-stop clause",
    ),
]

# Techniques that only count once the request also targets a harmful capability.
_HARM_TARGET = re.compile(
    r"\b(weapon|explosive|bomb|malware|ransomware|keylogger|botnet|exploit|"
    r"synthesi[sz]e|meth|fentanyl|poison|untraceable|launder|hack\s+into|"
    r"credit\s+card|ssn|counterfeit)\w*\b",
    re.IGNORECASE,
)


def detect(text: str) -> list[Finding]:
    """Return jailbreak signals, escalating when a harmful target is named."""
    findings: list[Finding] = []
    has_harm_target = bool(_HARM_TARGET.search(text))

    for pat in PATTERNS:
        match = pat.regex.search(text)
        if match is None:
            continue
        severity = pat.severity
        score = pat.weight
        if has_harm_target and severity is not Severity.CRITICAL:
            severity = Severity.CRITICAL if severity is Severity.HIGH else Severity.HIGH
            score = min(1.0, score + 0.15)
        findings.append(
            Finding(
                rule_id=pat.rule_id,
                category="jailbreak",
                severity=severity,
                message=pat.message,
                score=score,
                span=match.span(),
                evidence=_clip(match.group(0)),
                metadata={"technique": pat.technique, "harm_target": has_harm_target},
            )
        )

    # Several distinct techniques in one prompt is itself a strong signal: real
    # users rarely combine roleplay framing, policy negation and prefix forcing.
    techniques = {f.metadata["technique"] for f in findings}
    if len(techniques) >= 3:
        findings.append(
            Finding(
                rule_id="PG-JB-090",
                category="jailbreak",
                severity=Severity.CRITICAL,
                message=f"{len(techniques)} distinct jailbreak techniques combined in one prompt",
                score=0.95,
                evidence=", ".join(sorted(techniques)),
                metadata={"techniques": sorted(techniques)},
            )
        )

    return findings


def _clip(value: str, limit: int = 120) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"
