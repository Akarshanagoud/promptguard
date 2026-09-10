"""Lexicon-based toxicity scoring with a pluggable classifier hook.

This ships a transparent, offline, zero-dependency scorer rather than a model
download. That is a deliberate trade: it is weaker than a fine-tuned
classifier on subtle abuse, but it is auditable (every score decomposes into
named term hits), it runs in microseconds, and it never sends customer text to
a third party — which is usually the blocking objection in a compliance review.

When you do want a model, register one:

    from promptguard.policy import toxicity
    toxicity.register_scorer(my_detoxify_wrapper)

The wrapper takes ``str`` and returns ``dict[str, float]`` of category -> score
in ``[0, 1]``. Scores from the lexicon and the model are combined by taking the
maximum per category, so a registered model can only make the guard stricter.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from pathlib import Path

from ..types import Finding, Severity

Scorer = Callable[[str], dict[str, float]]

CATEGORIES = ("harassment", "hate", "violence", "self_harm", "sexual", "profanity")

# Weights are per-term severity contributions, not probabilities. A single
# high-weight term saturates its category; several mild ones accumulate.
_BUILTIN_LEXICON: dict[str, dict[str, float]] = {
    "harassment": {
        "idiot": 0.5, "moron": 0.5, "stupid": 0.35, "loser": 0.4, "pathetic": 0.4,
        "worthless": 0.55, "shut up": 0.45, "nobody likes you": 0.7,
        "you're trash": 0.7, "kill yourself": 1.0, "kys": 0.9,
    },
    "hate": {
        "subhuman": 0.9, "vermin": 0.7, "inferior race": 1.0, "ethnic cleansing": 1.0,
        "should be deported": 0.6, "don't belong here": 0.5,
    },
    "violence": {
        "kill you": 0.95, "murder": 0.7, "shoot up": 0.95, "beat you up": 0.8,
        "hunt you down": 0.9, "bomb": 0.6, "stab": 0.7, "torture": 0.8,
    },
    "self_harm": {
        "kill myself": 1.0, "end my life": 1.0, "suicide": 0.8, "self harm": 0.9,
        "cut myself": 0.9, "want to die": 0.85, "overdose": 0.7,
    },
    "sexual": {
        "explicit sex": 0.8, "porn": 0.6, "nsfw": 0.5,
    },
    "profanity": {
        "damn": 0.2, "hell": 0.15, "crap": 0.2, "bastard": 0.5, "asshole": 0.6,
    },
}

# Contexts where a term is being discussed rather than deployed. The scorer
# damps rather than zeroes these: quoting abuse is still worth flagging in a
# support transcript, just not worth blocking.
_MITIGATORS = re.compile(
    r"(?i)\b(?:the\s+word|term|called\s+(?:me|him|her|them)|quote[ds]?|"
    r"reported|allegedly|said\s+that|policy\s+(?:against|on)|prevent|report|"
    r"definition\s+of|do\s+not\s+say|shouldn'?t\s+say)\b"
)
_SUPPORT_CONTEXT = re.compile(
    r"(?i)\b(?:hotline|helpline|crisis|counsel(?:or|ling)|therapis|support\s+group|"
    r"if\s+you\s+are\s+struggling|reach\s+out\s+for\s+help)\w*\b"
)

_registered_scorers: list[Scorer] = []


def register_scorer(scorer: Scorer) -> None:
    """Add a model-backed scorer. Its scores are max-combined with the lexicon."""
    _registered_scorers.append(scorer)


def load_lexicon(path: str | Path) -> dict[str, dict[str, float]]:
    """Load a JSON lexicon of ``{category: {term: weight}}`` and merge it in."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    for category, terms in data.items():
        _BUILTIN_LEXICON.setdefault(category, {}).update(
            {str(k).lower(): float(v) for k, v in terms.items()}
        )
    return _BUILTIN_LEXICON


def _lexicon_scores(text: str) -> tuple[dict[str, float], dict[str, list[str]]]:
    lowered = text.lower()
    scores: dict[str, float] = {}
    hits: dict[str, list[str]] = {}

    damping = 0.45 if _MITIGATORS.search(text) else 1.0
    if _SUPPORT_CONTEXT.search(text):
        damping = min(damping, 0.3)

    for category, terms in _BUILTIN_LEXICON.items():
        total = 0.0
        matched: list[str] = []
        for term, weight in terms.items():
            pattern = r"\b" + re.escape(term).replace(r"\ ", r"\s+") + r"\b"
            count = len(re.findall(pattern, lowered))
            if count:
                matched.append(term)
                # Diminishing returns: repetition raises the score but the
                # first occurrence carries most of the signal.
                total += weight * (1 + 0.25 * (count - 1))
        if matched:
            scores[category] = min(1.0, total * damping)
            hits[category] = matched

    return scores, hits


def score(text: str) -> dict[str, float]:
    """Return category -> score in [0, 1] for ``text``."""
    scores, _ = _lexicon_scores(text)
    for scorer in _registered_scorers:
        try:
            model_scores = scorer(text)
        except Exception:  # a broken classifier must not take the guard down
            continue
        for category, value in model_scores.items():
            scores[category] = max(scores.get(category, 0.0), float(value))
    return scores


def _severity_for(value: float, threshold: float) -> Severity:
    if value >= min(0.95, threshold + 0.35):
        return Severity.CRITICAL
    if value >= threshold + 0.15:
        return Severity.HIGH
    if value >= threshold:
        return Severity.MEDIUM
    return Severity.LOW


def detect(text: str, thresholds: dict[str, float] | None = None) -> list[Finding]:
    """Return a finding per category whose score meets its threshold."""
    limits = {c: 0.5 for c in CATEGORIES}
    if thresholds:
        limits.update(thresholds)

    scores, hits = _lexicon_scores(text)
    for scorer in _registered_scorers:
        try:
            for category, value in scorer(text).items():
                scores[category] = max(scores.get(category, 0.0), float(value))
        except Exception:
            continue

    findings: list[Finding] = []
    for category, value in sorted(scores.items(), key=lambda kv: -kv[1]):
        threshold = limits.get(category, 0.5)
        if value < threshold:
            continue
        findings.append(
            Finding(
                rule_id=f"PG-TOX-{category.upper()}",
                category="toxicity",
                severity=_severity_for(value, threshold),
                message=f"{category.replace('_', ' ')} score {value:.2f} exceeds threshold {threshold:.2f}",
                score=value,
                evidence=", ".join(hits.get(category, [])[:5]),
                metadata={"toxicity_category": category, "threshold": threshold},
            )
        )
    return findings
