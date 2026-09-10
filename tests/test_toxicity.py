"""Lexicon scoring, context damping and the pluggable classifier hook."""
from promptguard.policy import toxicity


def test_neutral_text_scores_nothing():
    assert toxicity.score("The meeting is at four o'clock.") == {}


def test_harassment_is_scored():
    scores = toxicity.score("you are a worthless idiot")
    assert scores.get("harassment", 0) > 0.5


def test_self_harm_is_scored():
    assert toxicity.score("I want to kill myself").get("self_harm", 0) > 0.8


def test_support_context_damps_self_harm_score():
    plain = toxicity.score("I want to die")["self_harm"]
    supportive = toxicity.score(
        "If you want to die, please call a crisis hotline and reach out for help"
    )["self_harm"]
    assert supportive < plain


def test_quoting_damps_the_score():
    direct = toxicity.score("you are pathetic")["harassment"]
    quoted = toxicity.score("the user reported that a colleague called them pathetic")["harassment"]
    assert quoted < direct


def test_threshold_controls_findings():
    text = "you are an idiot"
    assert toxicity.detect(text, {"harassment": 0.9}) == []
    assert toxicity.detect(text, {"harassment": 0.3})


def test_registered_scorer_can_only_tighten(monkeypatch):
    monkeypatch.setattr(toxicity, "_registered_scorers", [lambda _t: {"hate": 0.99}])
    findings = toxicity.detect("perfectly ordinary sentence", {"hate": 0.5})
    assert any(f.metadata["toxicity_category"] == "hate" for f in findings)


def test_broken_scorer_does_not_break_the_guard(monkeypatch):
    def boom(_text):
        raise RuntimeError("model unavailable")

    monkeypatch.setattr(toxicity, "_registered_scorers", [boom])
    assert toxicity.detect("hello there") == []


def test_finding_lists_matched_terms():
    findings = toxicity.detect("you are an idiot and a loser", {"harassment": 0.3})
    assert "idiot" in findings[0].evidence
