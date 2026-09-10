"""Structured-output schema compliance.

Model output that is *supposed* to be JSON fails in a small number of very
predictable ways: wrapped in a markdown fence, prefixed with "Sure, here's the
JSON:", trailing commas, single quotes, or a trailing prose paragraph. This
module repairs those mechanically before validating, because a retry against
the model costs a round trip and usually produces the same wrapper again.

Validation implements the subset of JSON Schema that actually gets used for
LLM structured output (types, required, enum, properties, items, ranges,
patterns, additionalProperties). If ``jsonschema`` is installed it is used
instead, so a full-featured schema still validates correctly.
"""
from __future__ import annotations

import json
import re
from typing import Any

from ..types import Finding, Severity

try:  # optional; the built-in validator covers the common subset without it
    import jsonschema as _jsonschema
except ImportError:  # pragma: no cover - exercised by environments without the extra
    _jsonschema = None


_FENCE = re.compile(r"```(?:json|JSON)?\s*(.*?)```", re.DOTALL)


def extract_json(text: str) -> tuple[Any | None, list[str]]:
    """Pull the first JSON value out of ``text``, repairing common wrappers.

    Returns ``(value, repairs)`` where ``repairs`` names each fix applied, so
    the caller can log that the model needed help rather than silently
    accepting malformed output.
    """
    repairs: list[str] = []
    candidate = text.strip()

    try:
        return json.loads(candidate), repairs
    except json.JSONDecodeError:
        pass

    fence = _FENCE.search(candidate)
    if fence:
        candidate = fence.group(1).strip()
        repairs.append("stripped_markdown_fence")
        try:
            return json.loads(candidate), repairs
        except json.JSONDecodeError:
            pass

    # Take the outermost balanced object or array, dropping surrounding prose.
    sliced = _balanced_slice(candidate)
    if sliced is not None and sliced != candidate:
        candidate = sliced
        repairs.append("stripped_surrounding_prose")
        try:
            return json.loads(candidate), repairs
        except json.JSONDecodeError:
            pass

    repaired = re.sub(r",\s*([}\]])", r"\1", candidate)
    if repaired != candidate:
        candidate = repaired
        repairs.append("removed_trailing_comma")
        try:
            return json.loads(candidate), repairs
        except json.JSONDecodeError:
            pass

    # Single-quoted keys/values are a Python-repr leak, not valid JSON.
    if "'" in candidate and '"' not in candidate:
        repaired = re.sub(r"'([^']*)'", r'"\1"', candidate)
        repairs.append("converted_single_quotes")
        try:
            return json.loads(repaired), repairs
        except json.JSONDecodeError:
            pass

    return None, repairs


def _balanced_slice(text: str) -> str | None:
    """Return the outermost balanced ``{...}`` or ``[...]`` region."""
    starts = [i for i, c in enumerate(text) if c in "{["]
    if not starts:
        return None
    start = starts[0]
    opener = text[start]
    closer = "}" if opener == "{" else "]"
    depth = 0
    in_string = False
    escaped = False
    for i in range(start, len(text)):
        ch = text[i]
        if escaped:
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == '"':
            in_string = not in_string
            continue
        if in_string:
            continue
        if ch == opener:
            depth += 1
        elif ch == closer:
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None


_TYPE_MAP: dict[str, tuple[type, ...]] = {
    "object": (dict,),
    "array": (list,),
    "string": (str,),
    "number": (int, float),
    "integer": (int,),
    "boolean": (bool,),
    "null": (type(None),),
}


def _validate_subset(value: Any, schema: dict[str, Any], path: str = "$") -> list[str]:
    """Minimal JSON Schema validator covering the LLM-output subset."""
    errors: list[str] = []

    expected = schema.get("type")
    if expected:
        types = [expected] if isinstance(expected, str) else list(expected)
        allowed: tuple[type, ...] = tuple(t for name in types for t in _TYPE_MAP.get(name, ()))
        # bool is a subclass of int; a boolean is not an acceptable integer here.
        if isinstance(value, bool) and "boolean" not in types:
            errors.append(f"{path}: expected {'/'.join(types)}, got boolean")
            return errors
        if allowed and not isinstance(value, allowed):
            errors.append(f"{path}: expected {'/'.join(types)}, got {type(value).__name__}")
            return errors

    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']}")

    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{path}: missing required property '{key}'")
        properties = schema.get("properties", {})
        for key, sub_schema in properties.items():
            if key in value:
                errors.extend(_validate_subset(value[key], sub_schema, f"{path}.{key}"))
        if schema.get("additionalProperties") is False:
            extra = sorted(set(value) - set(properties))
            for key in extra:
                errors.append(f"{path}: unexpected property '{key}'")

    if isinstance(value, list):
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(value):
                errors.extend(_validate_subset(item, item_schema, f"{path}[{i}]"))
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: expected at least {schema['minItems']} items, got {len(value)}")
        if "maxItems" in schema and len(value) > schema["maxItems"]:
            errors.append(f"{path}: expected at most {schema['maxItems']} items, got {len(value)}")

    if isinstance(value, str):
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than minLength {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than maxLength {schema['maxLength']}")
        pattern = schema.get("pattern")
        if pattern and not re.search(pattern, value):
            errors.append(f"{path}: does not match pattern {pattern!r}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} below minimum {schema['minimum']}")
        if "maximum" in schema and value > schema["maximum"]:
            errors.append(f"{path}: {value} above maximum {schema['maximum']}")

    return errors


def validate(text: str, schema: dict[str, Any]) -> tuple[Any | None, list[Finding]]:
    """Parse ``text`` as JSON and validate it against ``schema``.

    Returns the parsed value (``None`` when unparseable) and any findings.
    """
    value, repairs = extract_json(text)
    findings: list[Finding] = []

    if value is None:
        findings.append(
            Finding(
                rule_id="PG-SCH-001",
                category="schema",
                severity=Severity.HIGH,
                message="output is not parseable as JSON",
                score=1.0,
                evidence=text[:120],
                metadata={"repairs_attempted": repairs},
            )
        )
        return None, findings

    if repairs:
        findings.append(
            Finding(
                rule_id="PG-SCH-002",
                category="schema",
                severity=Severity.LOW,
                message=f"output required repair before parsing: {', '.join(repairs)}",
                score=0.3,
                metadata={"repairs": repairs},
            )
        )

    if _jsonschema is not None:
        validator = _jsonschema.Draft202012Validator(schema)
        errors = [
            f"${''.join(f'.{p}' if isinstance(p, str) else f'[{p}]' for p in e.absolute_path)}"
            f": {e.message}"
            for e in sorted(validator.iter_errors(value), key=lambda e: list(e.absolute_path))
        ]
    else:
        errors = _validate_subset(value, schema)

    for error in errors:
        findings.append(
            Finding(
                rule_id="PG-SCH-003",
                category="schema",
                severity=Severity.HIGH,
                message=f"schema violation: {error}",
                score=0.8,
                evidence=error,
                metadata={"validator": "jsonschema" if _jsonschema else "builtin"},
            )
        )

    return value, findings
