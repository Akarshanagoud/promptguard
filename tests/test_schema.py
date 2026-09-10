"""JSON extraction/repair and schema validation."""
from promptguard.policy import schema

PERSON = {
    "type": "object",
    "required": ["name", "age"],
    "properties": {
        "name": {"type": "string", "minLength": 1},
        "age": {"type": "integer", "minimum": 0, "maximum": 130},
        "role": {"type": "string", "enum": ["admin", "user"]},
    },
    "additionalProperties": False,
}


def test_clean_json_parses_without_repairs():
    value, repairs = schema.extract_json('{"name": "Ada", "age": 36}')
    assert value == {"name": "Ada", "age": 36}
    assert repairs == []


def test_markdown_fence_is_stripped():
    value, repairs = schema.extract_json('```json\n{"name": "Ada", "age": 36}\n```')
    assert value["name"] == "Ada"
    assert "stripped_markdown_fence" in repairs


def test_surrounding_prose_is_stripped():
    value, repairs = schema.extract_json('Sure! Here you go: {"name": "Ada", "age": 36} Hope that helps.')
    assert value["age"] == 36
    assert "stripped_surrounding_prose" in repairs


def test_trailing_comma_repaired():
    value, repairs = schema.extract_json('{"name": "Ada", "age": 36,}')
    assert value["name"] == "Ada"
    assert "removed_trailing_comma" in repairs


def test_nested_braces_survive_slicing():
    value, _ = schema.extract_json('note: {"a": {"b": [1, 2]}, "c": "}"} end')
    assert value == {"a": {"b": [1, 2]}, "c": "}"}


def test_unparseable_output_reports_finding():
    value, findings = schema.validate("I could not produce JSON, sorry.", PERSON)
    assert value is None
    assert any(f.rule_id == "PG-SCH-001" for f in findings)


def test_valid_payload_has_no_violations():
    value, findings = schema.validate('{"name": "Ada", "age": 36}', PERSON)
    assert value["name"] == "Ada"
    assert not [f for f in findings if f.rule_id == "PG-SCH-003"]


def test_missing_required_field_reported():
    _, findings = schema.validate('{"name": "Ada"}', PERSON)
    assert any("age" in f.message for f in findings)


def test_type_mismatch_reported():
    _, findings = schema.validate('{"name": "Ada", "age": "thirty"}', PERSON)
    assert any(f.rule_id == "PG-SCH-003" for f in findings)


def test_enum_violation_reported():
    _, findings = schema.validate('{"name": "Ada", "age": 3, "role": "root"}', PERSON)
    assert any("not one of" in f.message or "root" in f.message for f in findings)


def test_additional_properties_rejected():
    _, findings = schema.validate('{"name": "Ada", "age": 3, "extra": 1}', PERSON)
    assert any("extra" in f.message for f in findings)


def test_range_bounds_enforced():
    _, findings = schema.validate('{"name": "Ada", "age": 900}', PERSON)
    assert any(f.rule_id == "PG-SCH-003" for f in findings)


def test_boolean_is_not_an_integer():
    _, findings = schema.validate('{"name": "Ada", "age": true}', PERSON)
    assert any(f.rule_id == "PG-SCH-003" for f in findings)


def test_repair_is_reported_as_low_severity_finding():
    _, findings = schema.validate('```json\n{"name":"Ada","age":1}\n```', PERSON)
    assert any(f.rule_id == "PG-SCH-002" for f in findings)
