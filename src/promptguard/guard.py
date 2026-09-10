"""The one object most applications need: input guard + output guard + audit."""
from __future__ import annotations

import uuid
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

from .audit import AuditLog
from .config import GuardConfig
from .input_guard import InputGuard
from .output_guard import OutputGuard
from .types import Action, GuardrailViolation, GuardResult


class PromptGuard:
    """Wraps a model call with input validation, output policy and audit.

    The point of the wrapper is that the audit record and the enforcement
    decision come from the same code path. A scan that runs beside the request
    and writes to a dashboard nobody reads is not a control; this makes the
    control and its evidence the same action.
    """

    def __init__(self, config: GuardConfig | None = None) -> None:
        self.config = config or GuardConfig()
        self.input = InputGuard(self.config)
        self.output = OutputGuard(self.config)
        self.audit = AuditLog(self.config.compliance)

    @classmethod
    def from_file(cls, path: str) -> PromptGuard:
        return cls(GuardConfig.from_file(path))

    @classmethod
    def strict(cls) -> PromptGuard:
        return cls(GuardConfig.strict())

    def check_input(
        self, text: str, *, context: str = "user", request_id: str | None = None,
        principal: str | None = None,
    ) -> GuardResult:
        result = self.input.check(text, context=context)
        self.audit.record(
            result, stage="input", request_id=request_id, principal=principal,
            extra={"channel": context},
        )
        return result

    def check_output(
        self, text: str, *, request_id: str | None = None, principal: str | None = None
    ) -> GuardResult:
        result = self.output.check(text)
        self.audit.record(result, stage="output", request_id=request_id, principal=principal)
        return result

    def run(
        self,
        prompt: str,
        model_fn: Callable[[str], str],
        *,
        request_id: str | None = None,
        principal: str | None = None,
        on_block: str | None = None,
    ) -> dict[str, Any]:
        """Guard a full turn: validate ``prompt``, call ``model_fn``, guard the reply.

        ``model_fn`` receives the *sanitized* prompt. If either side is blocked
        the model is not called (input) or its text is replaced with
        ``on_block`` (output), and both decisions land in the audit log under a
        shared ``request_id``.
        """
        request_id = request_id or str(uuid.uuid4())
        refusal = on_block or "This request was blocked by the configured safety policy."

        inbound = self.check_input(prompt, request_id=request_id, principal=principal)
        if inbound.action is Action.BLOCK:
            return {
                "request_id": request_id,
                "blocked_at": "input",
                "response": refusal,
                "input_result": inbound.to_dict(),
                "output_result": None,
            }

        raw_response = model_fn(inbound.text)

        outbound = self.check_output(raw_response, request_id=request_id, principal=principal)
        response = refusal if outbound.action is Action.BLOCK else outbound.text

        return {
            "request_id": request_id,
            "blocked_at": "output" if outbound.action is Action.BLOCK else None,
            "response": response,
            "input_result": inbound.to_dict(),
            "output_result": outbound.to_dict(),
        }

    @contextmanager
    def session(self, principal: str | None = None) -> Iterator[GuardSession]:
        """Group several turns under one request id for correlated auditing."""
        session = GuardSession(self, str(uuid.uuid4()), principal)
        try:
            yield session
        finally:
            session.closed = True


class GuardSession:
    """A correlated sequence of guarded turns."""

    def __init__(self, guard: PromptGuard, request_id: str, principal: str | None) -> None:
        self.guard = guard
        self.request_id = request_id
        self.principal = principal
        self.results: list[GuardResult] = []
        self.closed = False

    def check_input(self, text: str, *, context: str = "user") -> GuardResult:
        result = self.guard.check_input(
            text, context=context, request_id=self.request_id, principal=self.principal
        )
        self.results.append(result)
        return result

    def check_output(self, text: str) -> GuardResult:
        result = self.guard.check_output(
            text, request_id=self.request_id, principal=self.principal
        )
        self.results.append(result)
        return result

    def enforce_input(self, text: str, *, context: str = "user") -> str:
        result = self.check_input(text, context=context)
        if result.action is Action.BLOCK:
            raise GuardrailViolation(result)
        return result.text
