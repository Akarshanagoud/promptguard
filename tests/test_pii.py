"""PII validators, redaction modes and span handling."""
import pytest

from promptguard.policy import pii


def test_luhn_accepts_valid_card_and_rejects_random_digits():
    assert pii.luhn("4111111111111111")
    assert not pii.luhn("1234567890123456")


def test_credit_card_requires_luhn():
    assert pii.detect("card 4111 1111 1111 1111", ["CREDIT_CARD"])
    assert not pii.detect("order 1234 5678 9012 3456", ["CREDIT_CARD"])


def test_ssn_structural_rules():
    assert pii.valid_ssn("123-45-6789")
    assert not pii.valid_ssn("000-45-6789")
    assert not pii.valid_ssn("666-45-6789")
    assert not pii.valid_ssn("123-00-6789")
    assert not pii.valid_ssn("111-11-1111")


def test_iban_mod97():
    assert pii.valid_iban("GB82WEST12345698765432")
    assert not pii.valid_iban("GB82WEST12345698765433")


def test_npi_uses_prefixed_luhn():
    assert pii.valid_npi("1234567893")
    assert not pii.valid_npi("1234567890")


@pytest.mark.parametrize("mode,expected", [("label", "[EMAIL]"), ("remove", "")])
def test_redaction_modes(mode, expected):
    out, findings = pii.redact("mail me at a.b@c.com", ["EMAIL"], mode=mode)
    assert findings
    assert out == f"mail me at {expected}"


def test_hash_mode_is_stable_and_distinct():
    a, _ = pii.redact("x@y.com", ["EMAIL"], mode="hash")
    b, _ = pii.redact("x@y.com", ["EMAIL"], mode="hash")
    c, _ = pii.redact("z@y.com", ["EMAIL"], mode="hash")
    assert a == b
    assert a != c


def test_hash_mode_differs_with_salt():
    a, _ = pii.redact("x@y.com", ["EMAIL"], mode="hash", salt="one")
    b, _ = pii.redact("x@y.com", ["EMAIL"], mode="hash", salt="two")
    assert a != b


def test_multiple_entities_redacted_without_corrupting_offsets():
    text = "jane@acme.com called 415-555-0132 about SSN 123-45-6789"
    out, findings = pii.redact(text, ["EMAIL", "PHONE", "SSN"], mode="label")
    assert out == "[EMAIL] called [PHONE] about SSN [SSN]"
    assert len(findings) == 3


def test_overlapping_matches_resolved_once():
    findings = pii.detect("4111 1111 1111 1111", ["CREDIT_CARD", "PHONE"])
    assert len(findings) == 1


def test_clean_text_unchanged():
    out, findings = pii.redact("no personal data here")
    assert out == "no personal data here"
    assert findings == []
