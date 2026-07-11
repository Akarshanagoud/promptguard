import re
from collections.abc import Iterable

from app.policy import decide


DETECTION_RULES: dict[str, list[str]] = {
    "instruction_override": [
        r"\bignore\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        r"\bforget\s+(all\s+)?(previous|prior|above)\s+instructions\b",
        r"\boverride\s+(the\s+)?(system|developer)\s+(message|instructions?)\b",
        r"\byou\s+are\s+now\s+in\s+(admin|developer|root)\s+mode\b",
    ],
    "system_prompt_extraction": [
        r"\breveal\s+(your\s+)?(system|developer)\s+prompt\b",
        r"\bprint\s+(your\s+)?(system|developer)\s+(prompt|instructions?)\b",
        r"\bshow\s+me\s+(your\s+)?(hidden|internal)\s+(rules|instructions?)\b",
    ],
    "secret_exfiltration": [
        r"\b(show|print|send|dump|exfiltrate)\b.*\b(api\s*key|password|secret|token|credential)s?\b",
        r"\bcopy\b.*\b(env|environment)\s+variables\b",
        r"\breturn\b.*\b(private\s+key|session\s+cookie|database\s+url)\b",
    ],
    "policy_disable_attempt": [
        r"\bdisable\s+(safety|security|guardrails?|policy)\b",
        r"\bdo\s+not\s+(filter|block|refuse|warn)\b",
        r"\bwithout\s+logging\s+this\b",
    ],
    "hidden_instruction": [
        r"<!--.*?(ignore|override|reveal|exfiltrate).*?-->",
        r"<\s*system\s*>.*?<\s*/\s*system\s*>",
        r"\bbase64\s+decode\b.*\b(instructions?|prompt)\b",
    ],
}


SECRET_PATTERNS: dict[str, list[str]] = {
    "secret_detected": [
        r"\bsk-[A-Za-z0-9_-]{20,}\b",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"-----BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----",
        r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
        r"\bpostgres(ql)?://[^@\s]+:[^@\s]+@[^/\s]+/[^\s]+\b",
    ],
}


RULE_WEIGHTS = {
    "instruction_override": 35,
    "system_prompt_extraction": 35,
    "secret_exfiltration": 70,
    "policy_disable_attempt": 25,
    "hidden_instruction": 30,
    "secret_detected": 90,
}


def _matching_categories(content: str, rules: dict[str, Iterable[str]]) -> set[str]:
    findings: set[str] = set()
    for category, patterns in rules.items():
        for pattern in patterns:
            if re.search(pattern, content, re.IGNORECASE | re.DOTALL):
                findings.add(category)
                break
    return findings


def _score(categories: Iterable[str]) -> int:
    return min(sum(RULE_WEIGHTS.get(category, 0) for category in categories), 100)


def sanitize(content: str, categories: Iterable[str]) -> str:
    category_set = set(categories)
    if "secret_detected" in category_set:
        return "[Blocked content containing credentials or secrets]"
    if {"instruction_override", "system_prompt_extraction", "secret_exfiltration"} & category_set:
        return "[Blocked prompt injection attempt]"
    if category_set:
        return "[Sanitized suspicious instruction]"
    return content


def scan(content: str) -> dict[str, object]:
    categories = _matching_categories(content, DETECTION_RULES)
    secret_categories = _matching_categories(content, SECRET_PATTERNS)
    categories.update(secret_categories)

    score = _score(categories)
    decision = decide(score, has_secret=bool(secret_categories))
    sanitized = content if decision.action == "allow" else sanitize(content, categories)

    return {
        "allowed": decision.allowed,
        "risk_score": decision.risk_score,
        "risk_level": decision.risk_level,
        "categories": sorted(categories),
        "action": decision.action,
        "sanitized_content": sanitized,
    }
