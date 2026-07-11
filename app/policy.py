from dataclasses import dataclass


@dataclass(frozen=True)
class PolicyDecision:
    risk_score: int
    risk_level: str
    action: str
    allowed: bool


def decide(score: int, has_secret: bool = False) -> PolicyDecision:
    score = max(0, min(score, 100))

    if score >= 90 or has_secret:
        return PolicyDecision(score, "critical", "review", False)
    if score >= 70:
        return PolicyDecision(score, "high", "block", False)
    if score >= 35:
        return PolicyDecision(score, "medium", "sanitize", True)
    return PolicyDecision(score, "low", "allow", True)
