from __future__ import annotations

import sqlite3
from dataclasses import dataclass

from .contracts import AccessLevel, AuthorizationError, Principal


@dataclass(frozen=True)
class Permission:
    resource: str
    action: str


ROLE_PERMISSIONS: dict[str, frozenset[Permission]] = {
    "admin": frozenset({
        Permission("*", "*"),
    }),
    "data_admin": frozenset({
        Permission("tables", "read"),
        Permission("tables", "export"),
        Permission("reports", "read"),
    }),
    "analyst": frozenset({
        Permission("tables", "read"),
        Permission("reports", "read"),
        Permission("reports", "create"),
    }),
    "user": frozenset({
        Permission("reports", "read"),
    }),
}

LEVEL_CEILING: dict[str, int] = {
    "admin": 1,
    "data_admin": 2,
    "analyst": 3,
    "user": 4,
}


class RbacEngine:
    def __init__(self) -> None:
        self._role_permissions = dict(ROLE_PERMISSIONS)

    def register_role(self, role: str, permissions: set[Permission], min_level: int) -> None:
        self._role_permissions[role] = frozenset(permissions)
        LEVEL_CEILING[role] = min_level

    def authorize(self, principal: Principal, resource: str, action: str) -> None:
        if not principal.roles:
            raise AuthorizationError(f"{principal.user_id}: no roles assigned")
        for role in principal.roles:
            permissions = self._role_permissions.get(role)
            if permissions is None:
                raise AuthorizationError(f"unknown role: {role!r}")
            ceiling = LEVEL_CEILING.get(role, 5)
            if principal.level > ceiling:
                raise AuthorizationError(
                    f"{principal.user_id}: level {principal.level} exceeds role ceiling {ceiling}"
                )
            for granted in permissions:
                if (granted.resource == "*" or granted.resource == resource) and (
                    granted.action == "*" or granted.action == action
                ):
                    return
        raise AuthorizationError(f"{principal.user_id}: denied {action} on {resource}")

    def permissions_for(self, role: str) -> frozenset[Permission]:
        permissions = self._role_permissions.get(role)
        if permissions is None:
            raise AuthorizationError(f"unknown role: {role!r}")
        return permissions


def create_principal_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS principals (
            user_id TEXT PRIMARY KEY,
            level INTEGER NOT NULL CHECK (level BETWEEN 1 AND 5),
            roles TEXT NOT NULL
        )
    """)
    conn.commit()


def upsert_principal(conn: sqlite3.Connection, principal: Principal) -> None:
    conn.execute(
        "INSERT INTO principals (user_id, level, roles) VALUES (?, ?, ?) "
        "ON CONFLICT(user_id) DO UPDATE SET level=excluded.level, roles=excluded.roles",
        (principal.user_id, int(principal.level), ",".join(sorted(principal.roles))),
    )
    conn.commit()


def load_principal(conn: sqlite3.Connection, user_id: str) -> Principal | None:
    row = conn.execute(
        "SELECT user_id, level, roles FROM principals WHERE user_id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return None
    roles = frozenset(r for r in row[2].split(",") if r)
    return Principal(user_id=row[0], level=AccessLevel(row[1]), roles=roles)
