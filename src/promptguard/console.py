"""Web console: playground, traffic dashboard, audit trail and rule catalog.

The console is a thin layer over the objects the library already exposes.
Every number it shows is computed from the guard's own audit records, so the
dashboard and the evidence trail cannot disagree.

Start it with ``promptguard ui`` (needs the ``server`` extra).
"""
from __future__ import annotations

import json
import random
import uuid
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, FastAPI, HTTPException
from fastapi.responses import RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .audit import GENESIS
from .config import GuardConfig
from .detectors import injection, jailbreak, secrets
from .guard import PromptGuard
from .policy import pii
from .types import Action, GuardResult

WEB_DIR = Path(__file__).parent / "web"
PRESETS: dict[str, Any] = {
    "default": GuardConfig,
    "strict": GuardConfig.strict,
    "permissive": GuardConfig.permissive,
}
CHANNELS = ("user", "retrieved", "tool")
REFUSAL = "This request was blocked by the configured safety policy."
# No model is attached to the console. When the playground is not given a
# response, this stand-in lets the output guard run on something realistic.
STAND_IN_REPLY = (
    "Thanks for reaching out. Our support team is available Saturday and Sunday "
    "from 9am to 5pm Eastern, and the help centre is open around the clock."
)


class TurnRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=40_000)
    response: str | None = Field(None, max_length=40_000)
    channel: str = "user"
    preset: str = "active"


class CheckBody(BaseModel):
    text: str = Field(..., min_length=1, max_length=40_000)
    stage: str = "input"
    channel: str = "user"
    preset: str = "active"


class SimulateRequest(BaseModel):
    count: int = Field(40, ge=1, le=500)


def _result(result: GuardResult) -> dict[str, Any]:
    payload = result.to_dict()
    payload["original"] = result.original
    return payload


def _percentile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round(q * (len(ordered) - 1))))
    return round(ordered[index], 3)


def _timeline(records: list[dict[str, Any]], max_windows: int = 30) -> dict[str, Any]:
    """Input decisions in consecutive windows of requests, oldest first.

    Windows of requests rather than clock buckets: a burst of traffic that
    lands inside one second still shows its decision mix as it evolves.
    """
    inputs = [r for r in records if r.get("stage") == "input"]
    if not inputs:
        return {"window": 0, "windows": []}
    size = max(5, -(-len(inputs) // max_windows))
    windows = []
    for start in range(0, len(inputs), size):
        chunk = inputs[start : start + size]
        counts = Counter(r["action"] for r in chunk)
        windows.append(
            {
                "first": start + 1,
                "last": start + len(chunk),
                "started": datetime.fromisoformat(chunk[0]["timestamp"]).timestamp(),
                **{action.value: counts.get(action.value, 0) for action in Action},
            }
        )
    return {"window": size, "windows": windows}


def rule_catalog() -> list[dict[str, str]]:
    """Every rule the guard can fire, in the same shape as ``promptguard rules``."""
    rows = [
        *(
            {"rule_id": p.rule_id, "category": "prompt_injection", "severity": p.severity.value, "detail": p.message}
            for p in injection.ALL_PATTERNS
        ),
        *(
            {"rule_id": p.rule_id, "category": "jailbreak", "severity": p.severity.value, "detail": p.message}
            for p in jailbreak.PATTERNS
        ),
        *(
            {"rule_id": r.rule_id, "category": "secret", "severity": r.severity.value, "detail": r.name}
            for r in secrets.RULES
        ),
        *(
            {"rule_id": r.rule_id, "category": "pii", "severity": r.severity.value, "detail": r.entity}
            for r in pii.RULES
        ),
    ]
    return sorted(rows, key=lambda r: r["rule_id"])


def _policy_summary(config: GuardConfig) -> dict[str, Any]:
    return {
        "name": config.name,
        "input_block_threshold": config.input.block_threshold,
        "input_flag_threshold": config.input.flag_threshold,
        "input_block_on_severity": config.input.block_on_severity.value,
        "output_block_threshold": config.output.block_threshold,
        "output_block_on_severity": config.output.block_on_severity.value,
        "redact_pii_in_output": config.output.redact_pii,
        "pii_mode_input": config.input.pii_mode,
        "fail_open": config.fail_open,
    }


class Console:
    """State behind the web console: one guard, one evidence trail."""

    def __init__(self, guard: PromptGuard) -> None:
        self.guard = guard
        self.samples = json.loads((WEB_DIR / "samples.json").read_text(encoding="utf-8"))
        self._guards: dict[str, PromptGuard] = {}
        self._rng = random.Random(7)

    def guard_for(self, preset: str) -> PromptGuard:
        if preset in ("", "active", self.guard.config.name):
            return self.guard
        if preset not in PRESETS:
            raise HTTPException(status_code=422, detail=f"unknown preset {preset!r}")
        if preset not in self._guards:
            other = PromptGuard(PRESETS[preset]())
            other.audit = self.guard.audit  # every preset writes to the same chain
            self._guards[preset] = other
        return self._guards[preset]

    def meta(self) -> dict[str, Any]:
        return {
            "version": __version__,
            "policy": self.guard.config.name,
            "presets": list(PRESETS),
            "channels": list(CHANNELS),
            "frameworks": self.guard.config.compliance.frameworks,
            "audit_log": self.guard.config.compliance.audit_log_path,
            "samples": self.samples,
        }

    def turn(self, body: TurnRequest) -> dict[str, Any]:
        _check_channel(body.channel)
        guard = self.guard_for(body.preset)
        request_id = str(uuid.uuid4())
        inbound = guard.check_input(body.prompt, context=body.channel, request_id=request_id)
        out: dict[str, Any] = {
            "request_id": request_id,
            "preset": guard.config.name,
            "input": _result(inbound),
            "output": None,
            "model_called": False,
            "model_response": None,
            "stand_in": False,
            "blocked_at": None,
            "served": None,
        }
        if inbound.action is Action.BLOCK:
            out.update(blocked_at="input", served=REFUSAL)
            return out
        reply = body.response or STAND_IN_REPLY
        outbound = guard.check_output(reply, request_id=request_id)
        blocked = outbound.action is Action.BLOCK
        out.update(
            output=_result(outbound),
            model_called=True,
            model_response=reply,
            stand_in=not body.response,
            blocked_at="output" if blocked else None,
            served=REFUSAL if blocked else outbound.text,
        )
        return out

    def check(self, body: CheckBody) -> dict[str, Any]:
        guard = self.guard_for(body.preset)
        if body.stage == "input":
            _check_channel(body.channel)
            return _result(guard.check_input(body.text, context=body.channel))
        if body.stage == "output":
            return _result(guard.check_output(body.text))
        raise HTTPException(status_code=422, detail="stage must be 'input' or 'output'")

    def simulate(self, count: int) -> dict[str, Any]:
        """Push a realistic mix of traffic through the guard: mostly benign, some hostile."""
        prompts = self.samples["prompts"]
        replies = self.samples["responses"]
        benign = [p for p in prompts if p["category"] == "benign"]
        hostile = [p for p in prompts if p["category"] != "benign"]
        decisions: Counter[str] = Counter()
        for _ in range(count):
            prompt = self._rng.choice(hostile if self._rng.random() < 0.3 else benign)
            request_id = str(uuid.uuid4())
            inbound = self.guard.check_input(prompt["text"], context=prompt["channel"], request_id=request_id)
            decisions[inbound.action.value] += 1
            if inbound.action is not Action.BLOCK:
                reply = self._rng.choice(replies) if self._rng.random() < 0.35 else replies[0]
                self.guard.check_output(reply["text"], request_id=request_id)
        return {"simulated": count, "input_decisions": dict(decisions)}

    def summary(self) -> dict[str, Any]:
        records = list(self.guard.audit.records())
        inputs = [r for r in records if r["stage"] == "input"]
        outputs = [r for r in records if r["stage"] == "output"]
        categories: Counter[str] = Counter()
        rules: Counter[str] = Counter()
        messages: dict[str, str] = {}
        controls: dict[str, Counter[str]] = defaultdict(Counter)
        titles: dict[str, str] = {}
        for record in records:
            for finding in record.get("findings", []):
                categories[finding["category"]] += 1
                rules[finding["rule_id"]] += 1
                messages.setdefault(finding["rule_id"], finding["message"])
                for control in finding.get("controls", []):
                    controls[control["framework"]][control["control_id"]] += 1
                    titles[f"{control['framework']}:{control['control_id']}"] = control["title"]
        latency = [r["elapsed_ms"] for r in records]
        return {
            "requests": len(inputs),
            "responses": len(outputs),
            "input_actions": dict(Counter(r["action"] for r in inputs)),
            "output_actions": dict(Counter(r["action"] for r in outputs)),
            "latency_ms": {
                "p50": _percentile(latency, 0.5),
                "p95": _percentile(latency, 0.95),
                "p99": _percentile(latency, 0.99),
            },
            "categories": dict(categories.most_common()),
            "top_rules": [
                {"rule_id": rule, "count": n, "message": messages[rule]} for rule, n in rules.most_common(8)
            ],
            "controls": [
                {"framework": fw, "control_id": cid, "title": titles[f"{fw}:{cid}"], "count": n}
                for fw, counter in sorted(controls.items())
                for cid, n in sorted(counter.items())
            ],
            "timeline": _timeline(records),
            "recent": [_slim(r) for r in reversed(records[-12:])],
        }

    def audit(self, limit: int) -> dict[str, Any]:
        records = list(self.guard.audit.records())
        intact, broken_at = self.guard.audit.verify_chain()
        return {
            "total": len(records),
            "intact": intact,
            "broken_at": broken_at,
            "head": records[-1]["record_hash"] if records else GENESIS,
            "persisted_to": self.guard.config.compliance.audit_log_path,
            "records": [_slim(r) for r in reversed(records[-limit:])],
        }

    def export(self) -> str:
        return "".join(
            json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in self.guard.audit.records()
        )

    def rules(self) -> dict[str, Any]:
        return {
            "rules": rule_catalog(),
            "active": _policy_summary(self.guard.config),
            "presets": [_policy_summary(factory()) for factory in PRESETS.values()],
        }


def _slim(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "event_id": record["event_id"],
        "timestamp": record["timestamp"],
        "stage": record["stage"],
        "request_id": record["request_id"],
        "channel": (record.get("context") or {}).get("channel"),
        "action": record["action"],
        "risk_score": record["risk_score"],
        "max_severity": record["max_severity"],
        "elapsed_ms": record["elapsed_ms"],
        "input_chars": record["input_chars"],
        "modified": record["modified"],
        "rules": [f["rule_id"] for f in record.get("findings", [])],
        "categories": sorted({f["category"] for f in record.get("findings", [])}),
        "payload_sha256": record["payload_sha256"],
        "prev_hash": record["prev_hash"],
        "record_hash": record["record_hash"],
    }


def _check_channel(channel: str) -> None:
    if channel not in CHANNELS:
        raise HTTPException(status_code=422, detail=f"channel must be one of {', '.join(CHANNELS)}")


def build_router(console: Console) -> APIRouter:
    router = APIRouter(prefix="/v1/ui", tags=["console"])

    @router.get("/meta")
    def meta() -> dict[str, Any]:
        return console.meta()

    @router.post("/turn")
    def turn(body: TurnRequest) -> dict[str, Any]:
        return console.turn(body)

    @router.post("/check")
    def check(body: CheckBody) -> dict[str, Any]:
        return console.check(body)

    @router.post("/simulate")
    def simulate(body: SimulateRequest) -> dict[str, Any]:
        return console.simulate(body.count)

    @router.get("/summary")
    def summary() -> dict[str, Any]:
        return console.summary()

    @router.get("/audit")
    def audit(limit: int = 200) -> dict[str, Any]:
        return console.audit(max(1, min(limit, 2000)))

    @router.get("/audit/export")
    def export() -> Response:
        return Response(
            console.export(),
            media_type="application/x-ndjson",
            headers={"content-disposition": "attachment; filename=promptguard-audit.jsonl"},
        )

    @router.get("/rules")
    def rules() -> dict[str, Any]:
        return console.rules()

    return router


def mount_console(app: FastAPI, guard: PromptGuard) -> Console:
    """Attach the console API, the static front end and a ``/`` redirect to ``app``."""
    console = Console(guard)
    app.include_router(build_router(console))
    app.mount("/ui", StaticFiles(directory=str(WEB_DIR), html=True), name="console")

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui/")

    return console
