"""Credential detection, placeholder suppression and redaction."""
from promptguard.detectors import secrets
from promptguard.types import Severity


def test_aws_key_is_critical():
    findings = secrets.detect("AKIAIOSFODNN7EXAMPLE")
    assert findings and findings[0].severity is Severity.CRITICAL


def test_github_token_detected():
    assert secrets.detect("token=ghp_" + "a" * 36)


def test_database_url_with_credentials():
    findings = secrets.detect("postgres://admin:hunter2@db.internal:5432/app")
    assert any(f.metadata["secret_type"] == "database_url" for f in findings)


def test_placeholders_are_ignored():
    assert not secrets.detect("api_key = 'your_api_key_here'")
    assert not secrets.detect("password: changeme")


def test_low_entropy_generic_values_ignored():
    assert not secrets.detect("password: aaaaaaaaaaaaaaaaaaaa")


def test_evidence_is_masked():
    finding = secrets.detect("AKIAIOSFODNN7EXAMPLE")[0]
    assert "IOSFODNN7EXAMPLE" not in finding.evidence
    assert finding.evidence.startswith("AKIA")


def test_redaction_removes_the_value():
    text = "use AKIAIOSFODNN7EXAMPLE for access"
    out, findings = secrets.redact(text)
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "[REDACTED_SECRET]" in out
    assert findings


def test_multiple_secrets_redacted():
    text = "AKIAIOSFODNN7EXAMPLE and ghp_" + "b" * 36
    out, findings = secrets.redact(text)
    assert len(findings) == 2
    assert "AKIA" not in out and "ghp_" not in out
