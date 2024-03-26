from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone

from .contracts import AuditError


@dataclass(frozen=True)
class AuditEntry:
    sequence: int
    actor: str
    action: str
    resource: str
    decision: str
    occurred_at: str
    prev_hash: str = ""
    entry_hash: str = ""


class AuditChain:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_chain (
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                decision TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
        """)
        conn.commit()

    def append(self, actor: str, action: str, resource: str, decision: str) -> AuditEntry:
        if not actor or not action:
            raise AuditError("actor and action are required")
        row = self._conn.execute(
            "SELECT entry_hash FROM audit_chain ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        prev_hash = row[0] if row else "GENESIS"
        occurred_at = datetime.now(timezone.utc).isoformat()
        payload = json.dumps(
            {"actor": actor, "action": action, "resource": resource,
             "decision": decision, "occurred_at": occurred_at, "prev": prev_hash},
            sort_keys=True,
        )
        entry_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        cursor = self._conn.execute(
            "INSERT INTO audit_chain (actor, action, resource, decision, occurred_at, prev_hash, entry_hash) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (actor, action, resource, decision, occurred_at, prev_hash, entry_hash),
        )
        self._conn.commit()
        return AuditEntry(
            sequence=cursor.lastrowid,
            actor=actor,
            action=action,
            resource=resource,
            decision=decision,
            occurred_at=occurred_at,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

    def verify(self) -> tuple[bool, int | None]:
        rows = self._conn.execute(
            "SELECT sequence, actor, action, resource, decision, occurred_at, prev_hash, entry_hash "
            "FROM audit_chain ORDER BY sequence"
        ).fetchall()
        expected_prev = "GENESIS"
        for row in rows:
            sequence, actor, action, resource, decision, occurred_at, prev_hash, entry_hash = row
            if prev_hash != expected_prev:
                return False, sequence
            payload = json.dumps(
                {"actor": actor, "action": action, "resource": resource,
                 "decision": decision, "occurred_at": occurred_at, "prev": prev_hash},
                sort_keys=True,
            )
            recomputed = hashlib.sha256(payload.encode("utf-8")).hexdigest()
            if recomputed != entry_hash:
                return False, sequence
            expected_prev = entry_hash
        return True, None

    def entries(self, limit: int = 100) -> list[AuditEntry]:
        rows = self._conn.execute(
            "SELECT sequence, actor, action, resource, decision, occurred_at, prev_hash, entry_hash "
            "FROM audit_chain ORDER BY sequence DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [
            AuditEntry(*row)
            for row in reversed(rows)
        ]
