"""Optional FastAPI service exposing the guard over HTTP.

Run with::

    pip install "promptguard[server]"
    uvicorn promptguard.server:app --reload

Set ``PROMPTGUARD_CONFIG`` to a policy file path and ``PROMPTGUARD_AUDIT_LOG``
to a JSONL path to persist decisions.

The service is the sidecar deployment shape: applications in any language POST
their prompt and their model's response, and get back a decision plus the
sanitized text. Keeping it optional means the core library has no web
dependency.
"""
from __future__ import annotations

import os
from typing import Any

try:
    from fastapi import FastAPI, HTTPException
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover
    raise ImportError(
        "promptguard.server requires the server extra: pip install 'promptguard[server]'"
    ) from exc

from . import __version__
from .compliance import build_report
from .config import GuardConfig
from .guard import PromptGuard
from .types import GuardResult


def _build_guard() -> PromptGuard:
    config_path = os.getenv("PROMPTGUARD_CONFIG")
    config = GuardConfig.from_file(config_path) if config_path else GuardConfig()
    audit_path = os.getenv("PROMPTGUARD_AUDIT_LOG")
    if audit_path:
        config.compliance.audit_log_path = audit_path
    return PromptGuard(config)


guard = _build_guard()

app = FastAPI(
    title="PromptGuard",
    version=__version__,
    description="Input validation, output policy and compliance controls for LLM applications.",
)


class CheckRequest(BaseModel):
    text: str = Field(..., description="The payload to evaluate")
    channel: str = Field("user", description="user | retrieved | tool")
    request_id: str | None = None
    principal: str | None = Field(
        None, description="Caller identity; stored pseudonymized in the audit log"
    )


class StructuredRequest(BaseModel):
    text: str
    json_schema: dict[str, Any]
    request_id: str | None = None


class CheckResponse(BaseModel):
    action: str
    allowed: bool
    modified: bool
    risk_score: float
    max_severity: str
    elapsed_ms: float
    findings: list[dict[str, Any]]
    text: str


def _to_response(result: GuardResult) -> CheckResponse:
    return CheckResponse(**result.to_dict())


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "version": __version__,
        "policy": guard.config.name,
        "audit_log": guard.config.compliance.audit_log_path,
    }


@app.get("/policy")
def policy() -> dict[str, Any]:
    """The active policy, so callers can see what they are being held to."""
    return guard.config.to_dict()


@app.post("/v1/check/input", response_model=CheckResponse)
def check_input(request: CheckRequest) -> CheckResponse:
    result = guard.check_input(
        request.text,
        context=request.channel,
        request_id=request.request_id,
        principal=request.principal,
    )
    return _to_response(result)


@app.post("/v1/check/output", response_model=CheckResponse)
def check_output(request: CheckRequest) -> CheckResponse:
    result = guard.check_output(
        request.text, request_id=request.request_id, principal=request.principal
    )
    return _to_response(result)


@app.post("/v1/check/structured")
def check_structured(request: StructuredRequest) -> dict[str, Any]:
    value, result = guard.output.check_structured(request.text, request.json_schema)
    return {"valid": value is not None and not _schema_errors(result), "parsed": value,
            **result.to_dict()}


def _schema_errors(result: GuardResult) -> bool:
    return any(f.rule_id == "PG-SCH-003" for f in result.findings)


@app.get("/v1/audit/verify")
def verify_audit() -> dict[str, Any]:
    if guard.config.compliance.audit_log_path is None:
        raise HTTPException(status_code=409, detail="no audit log configured")
    ok, broken = guard.audit.verify_chain()
    return {"intact": ok, "broken_at": broken}


@app.get("/v1/audit/report")
def audit_report() -> dict[str, Any]:
    records = list(guard.audit.records())
    if not records:
        return {"records": 0}
    from collections import Counter

    actions: Counter[str] = Counter(r["action"] for r in records)
    controls: Counter[str] = Counter(
        f"{c['framework']}:{c['control_id']}"
        for r in records
        for f in r.get("findings", [])
        for c in f.get("controls", [])
    )
    return {"records": len(records), "actions": dict(actions), "controls": dict(controls)}


@app.post("/v1/report")
def batch_report(payloads: list[str]) -> dict[str, Any]:
    """Score a batch of payloads and return aggregate control coverage."""
    results = [guard.input.check(p) for p in payloads]
    return build_report(results, guard.config.compliance.frameworks).to_dict()
