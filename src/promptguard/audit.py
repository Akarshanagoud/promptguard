"""Append-only audit logging.

Two properties matter for an audit trail that will be read by someone other
than its author:

* **No payload leakage by default.** ``log_payloads`` is off, and even when it
  is on, the *redacted* text is what gets written, never the original.
* **Tamper evidence.** Each record carries the SHA-256 of the previous record,
  so a deleted or edited line breaks the chain and :func:`verify_chain` says
  where. This is not a substitute for a WORM store, but it turns silent
  tampering into detectable tampering at zero infrastructure cost.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .compliance import annotate
from .config import ComplianceConfig
from .types import GuardResult

GENESIS = "0" * 64


class AuditLog:
    """JSON-lines audit sink with a hash chain over records."""

    def __init__(self, config: ComplianceConfig | None = None) -> None:
        self.config = config or ComplianceConfig()
        self.path = Path(self.config.audit_log_path) if self.config.audit_log_path else None
        self._lock = threading.Lock()
        self._last_hash = self._load_last_hash()
        self._buffer: list[dict[str, Any]] = []

    def _load_last_hash(self) -> str:
        if not self.path or not self.path.exists():
            return GENESIS
        last = GENESIS
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    last = _record_hash(json.loads(line))
        return last

    def record(
        self,
        result: GuardResult,
        *,
        stage: str,
        request_id: str | None = None,
        principal: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Append one guard decision to the log and return the written record."""
        entry: dict[str, Any] = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stage": stage,
            "request_id": request_id or str(uuid.uuid4()),
            "principal": _pseudonymize(principal, self.config.hash_salt) if principal else None,
            "action": result.action.value,
            "risk_score": round(result.risk_score, 4),
            "max_severity": result.max_severity.value,
            "elapsed_ms": round(result.elapsed_ms, 3),
            "input_chars": len(result.original),
            "modified": result.modified,
            "findings": [annotate(f, self.config.frameworks) for f in result.findings],
        }
        if extra:
            entry["context"] = extra
        if self.config.log_payloads:
            # The sanitized text only. The original is never persisted.
            entry["payload_redacted"] = result.text
        entry["payload_sha256"] = hashlib.sha256(result.original.encode("utf-8")).hexdigest()

        with self._lock:
            entry["prev_hash"] = self._last_hash
            self._last_hash = _record_hash(entry)
            entry["record_hash"] = self._last_hash
            self._write(entry)
        return entry

    def _write(self, entry: dict[str, Any]) -> None:
        line = json.dumps(entry, ensure_ascii=False, sort_keys=True)
        if self.path is None:
            self._buffer.append(entry)
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    def records(self) -> Iterator[dict[str, Any]]:
        """Iterate every record, from file when configured, else from memory."""
        if self.path is None:
            yield from self._buffer
            return
        if not self.path.exists():
            return
        with self.path.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line:
                    yield json.loads(line)

    def verify_chain(self) -> tuple[bool, str | None]:
        """Return ``(ok, first_broken_event_id)`` for the persisted chain."""
        prev = GENESIS
        for record in self.records():
            if record.get("prev_hash") != prev:
                return False, record.get("event_id")
            body = {k: v for k, v in record.items() if k != "record_hash"}
            if _record_hash(body) != record.get("record_hash"):
                return False, record.get("event_id")
            prev = record["record_hash"]
        return True, None

    def prune(self, retention_days: int | None = None) -> int:
        """Drop records older than the retention window. Returns rows removed.

        Pruning rewrites the chain from the surviving records so the remaining
        file still verifies; the pre-prune head hash is not preserved, which is
        the expected trade for a retention policy.
        """
        if self.path is None or not self.path.exists():
            return 0
        days = retention_days if retention_days is not None else self.config.retention_days
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86_400

        kept: list[dict[str, Any]] = []
        removed = 0
        for record in self.records():
            stamp = datetime.fromisoformat(record["timestamp"]).timestamp()
            if stamp < cutoff:
                removed += 1
            else:
                kept.append(record)

        prev = GENESIS
        with self.path.open("w", encoding="utf-8") as handle:
            for record in kept:
                record["prev_hash"] = prev
                record.pop("record_hash", None)
                prev = _record_hash(record)
                record["record_hash"] = prev
                handle.write(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n")
        self._last_hash = prev
        return removed


def _record_hash(entry: dict[str, Any]) -> str:
    body = {k: v for k, v in entry.items() if k != "record_hash"}
    return hashlib.sha256(
        json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8")
    ).hexdigest()


def _pseudonymize(value: str, salt: str) -> str:
    return "u_" + hashlib.sha256(f"{salt}:{value}".encode()).hexdigest()[:16]
