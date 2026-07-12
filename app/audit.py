import hashlib
import json
import os
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


def _db_path() -> str:
    return os.getenv("PROMPTGUARD_AUDIT_DB", "promptguard_audit.sqlite3")


def _connect() -> sqlite3.Connection:
    path = _db_path()
    if path != ":memory:":
        Path(path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            source TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            content_preview TEXT NOT NULL,
            allowed INTEGER NOT NULL,
            risk_score INTEGER NOT NULL,
            risk_level TEXT NOT NULL,
            categories TEXT NOT NULL,
            action TEXT NOT NULL
        )
        """
    )
    return conn


def _preview(content: str, limit: int = 160) -> str:
    clean = " ".join(content.split())
    return clean[:limit]


def record_scan(source: str, content: str, result: dict[str, Any]) -> None:
    digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
    with _connect() as conn:
        conn.execute(
            """
            INSERT INTO scans (
                created_at, source, content_hash, content_preview, allowed,
                risk_score, risk_level, categories, action
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                datetime.now(UTC).isoformat(),
                source,
                digest,
                _preview(content),
                int(bool(result["allowed"])),
                int(result["risk_score"]),
                str(result["risk_level"]),
                json.dumps(result["categories"]),
                str(result["action"]),
            ),
        )


def recent_scans(limit: int = 25) -> list[dict[str, Any]]:
    limit = max(1, min(limit, 100))
    with _connect() as conn:
        rows = conn.execute(
            """
            SELECT id, created_at, source, content_hash, content_preview,
                   allowed, risk_score, risk_level, categories, action
            FROM scans
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    records: list[dict[str, Any]] = []
    for row in rows:
        item = dict(row)
        item["allowed"] = bool(item["allowed"])
        item["categories"] = json.loads(item["categories"])
        records.append(item)
    return records
