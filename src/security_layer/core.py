from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from typing import Any

from .audit import AuditChain, AuditEntry
from .contracts import AccessLevel, ANONYMOUS, Principal, SecurityError
from .masking import MaskingProfile, RowMasker
from .rbac import Permission, RbacEngine, create_principal_table, load_principal, upsert_principal


@dataclass(frozen=True)
class SecureQueryResult:
    rows: list[dict[str, Any]]
    columns: list[str]
    masked_columns: list[str]
    audit_entry: AuditEntry


class SecureDatabase:
    BOOTSTRAP_ID = "bootstrap"

    def __init__(self, path: str | None = None) -> None:
        self._conn = sqlite3.connect(path or ":memory:")
        self._conn.row_factory = sqlite3.Row
        self._rbac = RbacEngine()
        self._profile = MaskingProfile()
        self._audit = AuditChain(self._conn)
        create_principal_table(self._conn)
        upsert_principal(
            self._conn,
            Principal(user_id=self.BOOTSTRAP_ID, level=AccessLevel.SYSADMIN,
                      roles=frozenset({"admin"})),
        )

    @property
    def rbac(self) -> RbacEngine:
        return self._rbac

    @property
    def masking_profile(self) -> MaskingProfile:
        return self._profile

    def register_principal(self, principal: Principal) -> None:
        upsert_principal(self._conn, principal)

    def authenticate(self, user_id: str) -> Principal:
        principal = load_principal(self._conn, user_id)
        if principal is None:
            raise SecurityError(f"unknown principal: {user_id!r}")
        return principal

    def execute_secure(
        self,
        actor: str,
        sql: str,
        params: tuple[Any, ...] = (),
        resource: str = "tables",
        action: str = "read",
    ) -> SecureQueryResult:
        principal = self.authenticate(actor)
        self._rbac.authorize(principal, resource, action)
        cursor = self._conn.execute(sql, params)
        raw_rows = cursor.fetchall() if cursor.description else []
        columns = [d[0] for d in cursor.description] if cursor.description else []
        masker = RowMasker(self._profile)
        masked_out = masker.mask_rows(raw_rows, columns)
        masked_columns = sorted(
            {key for row in masked_out for key, value in row.items()
             if isinstance(value, str) and value.startswith("[") and value.endswith("]")}
        )
        decision = "allow"
        entry = self._audit.append(actor=actor, action=action, resource=resource, decision=decision)
        return SecureQueryResult(
            rows=masked_out,
            columns=columns,
            masked_columns=masked_columns,
            audit_entry=entry,
        )

    def execute_admin(
        self,
        actor: str,
        sql: str,
        params: tuple[Any, ...] = (),
    ) -> None:
        if actor == self.BOOTSTRAP_ID:
            self._conn.execute(sql, params)
            self._conn.commit()
            return
        principal = self.authenticate(actor)
        self._rbac.authorize(principal, "*", "*")
        self._conn.execute(sql, params)
        self._conn.commit()
        self._audit.append(actor=actor, action="execute", resource="schema", decision="allow")

    def audit_trail(self) -> AuditChain:
        return self._audit

    def close(self) -> None:
        self._conn.close()
