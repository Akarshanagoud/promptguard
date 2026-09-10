"""Prompt-injection detection.

The detector is deliberately dependency-free: every signal is a regex, a
structural check or a cheap statistical measure. That keeps it fast enough to
run inline on every request (single-digit milliseconds for typical prompts)
and makes each hit explainable, which matters more than raw recall when the
output feeds a compliance log.
"""
from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass

from ..types import Finding, Severity


@dataclass(frozen=True)
class Pattern:
    rule_id: str
    regex: re.Pattern[str]
    severity: Severity
    weight: float
    message: str


def _p(rule_id: str, pattern: str, severity: Severity, weight: float, message: str) -> Pattern:
    return Pattern(rule_id, re.compile(pattern, re.IGNORECASE), severity, weight, message)


# --- Direct instruction override -------------------------------------------
OVERRIDE_PATTERNS: list[Pattern] = [
    _p(
        "PG-INJ-001",
        r"\b(ignore|disregard|forget|discard)\b[^.\n]{0,40}\b(all\s+)?"
        r"(previous|prior|above|earlier|preceding|system|initial)\b[^.\n]{0,20}"
        r"\b(instruction|prompt|rule|direction|message|context)s?\b",
        Severity.HIGH,
        0.85,
        "instructs the model to discard prior instructions",
    ),
    _p(
        "PG-INJ-002",
        r"\b(new|updated|revised)\s+(instruction|rule|directive|system\s+prompt)s?\b\s*[:\-]",
        Severity.MEDIUM,
        0.55,
        "declares a replacement instruction set",
    ),
    _p(
        "PG-INJ-003",
        r"\byou\s+(are|will|must)\s+now\s+(a|an|the)?\s*\w+",
        Severity.MEDIUM,
        0.45,
        "attempts to reassign the model's role mid-conversation",
    ),
    _p(
        "PG-INJ-004",
        r"\b(from\s+now\s+on|starting\s+now|going\s+forward)\b[^.\n]{0,40}"
        r"\b(you|your)\b[^.\n]{0,40}\b(ignore|no\s+longer|stop|must|will)\b",
        Severity.MEDIUM,
        0.5,
        "sets a persistent behavioural override",
    ),
]

# --- System prompt / context exfiltration -----------------------------------
EXFIL_PATTERNS: list[Pattern] = [
    _p(
        "PG-INJ-010",
        r"\b(reveal|show|print|repeat|output|display|reproduce|tell\s+me)\b[^.\n]{0,30}"
        r"\b(your\s+)?(system\s+prompt|initial\s+prompt|instructions|system\s+message|"
        r"prompt\s+template|developer\s+message)\b",
        Severity.HIGH,
        0.8,
        "requests disclosure of the system prompt",
    ),
    _p(
        "PG-INJ-011",
        r"\brepeat\b[^.\n]{0,30}\b(everything|all|the\s+text)\b[^.\n]{0,30}"
        r"\b(above|before|verbatim)\b",
        Severity.MEDIUM,
        0.6,
        "requests verbatim replay of preceding context",
    ),
    _p(
        "PG-INJ-012",
        r"\bwhat\s+(were|are)\s+(your|the)\s+(original\s+)?(instructions|rules|guidelines)\b",
        Severity.MEDIUM,
        0.55,
        "probes for the configured instruction set",
    ),
    _p(
        "PG-INJ-013",
        r"\b(list|dump|enumerate)\b[^.\n]{0,25}\b(your\s+)?(tools|functions|api\s+keys|"
        r"credentials|env(ironment)?\s+variables)\b",
        Severity.HIGH,
        0.75,
        "probes for tool or credential inventory",
    ),
]

# --- Delimiter / role spoofing ----------------------------------------------
SPOOF_PATTERNS: list[Pattern] = [
    _p(
        "PG-INJ-020",
        r"<\s*/?\s*(system|assistant|user|im_start|im_end|s)\s*\|?\s*>",
        Severity.HIGH,
        0.7,
        "embeds chat-template control tags",
    ),
    _p(
        "PG-INJ-021",
        r"\|\s*(im_start|im_end|endoftext|start_header_id|end_header_id|eot_id)\s*\|",
        Severity.HIGH,
        0.75,
        "embeds model special tokens",
    ),
    _p(
        "PG-INJ-022",
        r"(?m)(?:^|<[^>]{0,12}>)\s*(system|assistant|developer)\s*:\s*\S",
        Severity.MEDIUM,
        0.5,
        "impersonates a privileged conversation role",
    ),
    _p(
        "PG-INJ-023",
        r"\[\s*(system|admin|root|developer)\s*\]",
        Severity.MEDIUM,
        0.45,
        "uses a privileged-role bracket marker",
    ),
]

# --- Indirect injection (payloads arriving via retrieved documents) ---------
INDIRECT_PATTERNS: list[Pattern] = [
    _p(
        "PG-INJ-030",
        r"\b(important|attention|note\s+to)\b[^.\n]{0,20}\b(ai|assistant|model|llm|agent)\b\s*[:\-,]",
        Severity.MEDIUM,
        0.5,
        "document addresses the model directly (indirect injection marker)",
    ),
    _p(
        "PG-INJ-031",
        r"\bif\s+you\s+are\s+(an?\s+)?(ai|llm|assistant|language\s+model)\b",
        Severity.MEDIUM,
        0.55,
        "conditional instruction targeting AI readers",
    ),
    _p(
        "PG-INJ-032",
        r"\b(send|post|forward|exfiltrate|upload)\b[^.\n]{0,30}\b(to|at)\b\s*"
        r"(https?://|www\.|[\w.-]+@[\w.-]+)",
        Severity.CRITICAL,
        0.9,
        "instructs the model to transmit data to an external endpoint",
    ),
    _p(
        "PG-INJ-033",
        r"!\[[^\]]*\]\(\s*https?://[^)]*\{\{[^)]*\)",
        Severity.HIGH,
        0.8,
        "markdown image with templated URL (data exfiltration vector)",
    ),
]

# --- Encoding / obfuscation --------------------------------------------------
ENCODING_PATTERNS: list[Pattern] = [
    _p(
        "PG-INJ-040",
        r"\b(?:(base64|rot13|hex|caesar)\s*(?:decode|decoded|encoded|:)"
        r"|(?:decode|decoding|decrypt)\b[^.\n]{0,20}\b(base64|rot13|hex|caesar))",
        Severity.MEDIUM,
        0.5,
        "asks the model to decode an obfuscated payload",
    ),
    _p(
        "PG-INJ-041",
        r"\b(execute|run|eval)\b[^.\n]{0,20}\b(the\s+)?(following|below|this)\b[^.\n]{0,20}"
        r"\b(code|command|script|payload)\b",
        Severity.HIGH,
        0.7,
        "asks the model to execute supplied code",
    ),
]

ALL_PATTERNS: list[Pattern] = (
    OVERRIDE_PATTERNS + EXFIL_PATTERNS + SPOOF_PATTERNS + INDIRECT_PATTERNS + ENCODING_PATTERNS
)

# Zero-width and bidi control characters used to hide text from human reviewers
# while leaving it fully visible to the tokenizer.
_INVISIBLE = re.compile(
    "[​-‏‪-‮⁠-⁤﻿᠎]"
)
_TAG_BLOCK = re.compile("[\U000e0000-\U000e007f]")
_BASE64_BLOB = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# "Please ignore the typo in my previous message" is the single most common
# false positive for the override rule: a user correcting themselves uses the
# same verb and the same object as an attacker overriding the system prompt.
# The signal is the *thing* being ignored — a typo is not an instruction — so
# these matches are downgraded rather than dropped: still logged, never blocked.
_BENIGN_CORRECTION = re.compile(
    r"(?i)\b(typo|typos|misspelling|spelling|autocorrect|formatting|"
    r"last\s+line|duplicate|double\s+post|wrong\s+attachment)\b"
)
_OVERRIDE_RULE_IDS = {p.rule_id for p in OVERRIDE_PATTERNS}


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def normalize(text: str) -> str:
    """Fold obfuscation tricks so patterns match the payload a model would see.

    Homoglyphs are collapsed via NFKC, invisible control characters are removed,
    and runs of separator punctuation (``i-g-n-o-r-e``) are closed up.
    """
    folded = unicodedata.normalize("NFKC", text)
    folded = _INVISIBLE.sub("", folded)
    folded = _TAG_BLOCK.sub("", folded)
    # Collapse single-character-plus-separator sequences of 4+ letters.
    folded = re.sub(
        r"\b(?:[A-Za-z][ .\-_*]){3,}[A-Za-z]\b",
        lambda m: re.sub(r"[ .\-_*]", "", m.group(0)),
        folded,
    )
    return folded


def detect(text: str) -> list[Finding]:
    """Return every injection signal present in ``text``.

    Patterns run against both the raw and normalized forms so an attacker
    cannot dodge a rule by inserting zero-width joiners. Spans are reported
    only when the raw text matched, since normalization shifts offsets.
    """
    findings: list[Finding] = []
    normalized = normalize(text)
    seen: set[str] = set()

    for variant, is_normalized in ((text, False), (normalized, True)):
        if is_normalized and normalized == text:
            continue
        for pat in ALL_PATTERNS:
            if pat.rule_id in seen:
                continue
            match = pat.regex.search(variant)
            if match is None:
                continue
            seen.add(pat.rule_id)
            severity, weight = pat.severity, pat.weight
            benign_context = pat.rule_id in _OVERRIDE_RULE_IDS and _BENIGN_CORRECTION.search(
                _sentence_around(variant, match.start())
            )
            if benign_context:
                severity, weight = Severity.LOW, 0.15
            findings.append(
                Finding(
                    rule_id=pat.rule_id,
                    category="prompt_injection",
                    severity=severity,
                    message=f"{pat.message} (self-correction context)"
                    if benign_context
                    else pat.message,
                    score=weight,
                    span=None if is_normalized else match.span(),
                    evidence=_clip(match.group(0)),
                    metadata={
                        "obfuscated": is_normalized,
                        "downgraded": bool(benign_context),
                    },
                )
            )

    findings.extend(_structural_signals(text))
    return findings


def _structural_signals(text: str) -> list[Finding]:
    out: list[Finding] = []

    hidden = _INVISIBLE.findall(text) + _TAG_BLOCK.findall(text)
    if hidden:
        out.append(
            Finding(
                rule_id="PG-INJ-050",
                category="prompt_injection",
                severity=Severity.HIGH,
                message=f"payload contains {len(hidden)} invisible control character(s)",
                score=0.7,
                evidence=f"{len(hidden)} hidden chars",
                metadata={"codepoints": sorted({hex(ord(c)) for c in hidden})[:10]},
            )
        )

    for blob in _BASE64_BLOB.findall(text)[:3]:
        entropy = _shannon_entropy(blob)
        if entropy > 4.5:
            out.append(
                Finding(
                    rule_id="PG-INJ-051",
                    category="prompt_injection",
                    severity=Severity.LOW,
                    message="high-entropy encoded blob embedded in prompt",
                    score=0.3,
                    evidence=_clip(blob),
                    metadata={"entropy": round(entropy, 2), "length": len(blob)},
                )
            )

    # A wall of blank lines is the classic way to push the real instructions out
    # of a reviewer's viewport before appending a replacement.
    if re.search(r"\n{12,}", text):
        out.append(
            Finding(
                rule_id="PG-INJ-052",
                category="prompt_injection",
                severity=Severity.LOW,
                message="large whitespace gap used to visually detach following text",
                score=0.25,
                evidence="12+ consecutive newlines",
            )
        )

    return out


def _clip(value: str, limit: int = 120) -> str:
    flat = " ".join(value.split())
    return flat if len(flat) <= limit else flat[: limit - 1] + "…"


def _sentence_around(text: str, index: int) -> str:
    """The sentence containing ``index``, used for local context checks."""
    start = max(text.rfind(".", 0, index), text.rfind("\n", 0, index)) + 1
    end_candidates = [i for i in (text.find(".", index), text.find("\n", index)) if i != -1]
    end = min(end_candidates) if end_candidates else len(text)
    return text[start:end]
