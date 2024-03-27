import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import pytest

from security_layer import (
    AccessLevel,
    AuthorizationError,
    Permission,
    SecureDatabase,
    SecurityError,
)


@pytest.fixture
def db():
    database = SecureDatabase()
    database.execute_admin(
        actor="bootstrap",
        sql="CREATE TABLE employees (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, email TEXT)",
    )
    database.execute_admin(
        actor="bootstrap",
        sql="INSERT INTO employees (name, phone, email) VALUES (?, ?, ?)",
        params=("Sara", "09121234567", "sara@corp.ir"),
    )
    return database


def make_db_with_users():
    database = SecureDatabase()
    database.execute_admin(
        actor="bootstrap",
        sql="CREATE TABLE t (id INTEGER, note TEXT)",
    )
    return database


def test_rbac_allows_analyst_read(db):
    from security_layer import Principal
    analyst = Principal(user_id="u1", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    db.register_principal(analyst)
    result = db.execute_secure("u1", "SELECT * FROM employees")
    assert result.rows[0]["name"] == "Sara"


def test_rbac_denies_user_write(db):
    from security_layer import Principal
    user = Principal(user_id="u2", level=AccessLevel.USER, roles=frozenset({"user"}))
    db.register_principal(user)
    with pytest.raises(AuthorizationError):
        db.execute_secure("u2", "SELECT * FROM employees", action="export")


def test_unknown_principal_rejected(db):
    with pytest.raises(SecurityError):
        db.execute_secure("ghost", "SELECT 1")


def test_level_ceiling_enforced():
    database = make_db_with_users()
    from security_layer import Principal
    overpowered = Principal(user_id="u3", level=AccessLevel.GUEST, roles=frozenset({"admin"}))
    database.register_principal(overpowered)
    with pytest.raises(AuthorizationError):
        database.execute_secure("u3", "SELECT * FROM t")


def test_pii_masked_in_results(db):
    from security_layer import Principal
    analyst = Principal(user_id="u4", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    db.register_principal(analyst)
    db.masking_profile.register(column="phone", kind="phone", mask_token="[PHONE]")
    result = db.execute_secure("u4", "SELECT name, phone FROM employees")
    assert result.rows[0]["phone"] == "[PHONE]"
    assert result.rows[0]["name"] == "Sara"


def test_free_text_scan_redacts_patterns(db):
    from security_layer import Principal
    analyst = Principal(user_id="u5", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    database = make_db_with_users()
    database.register_principal(analyst)
    database.execute_admin(
        actor="bootstrap",
        sql="INSERT INTO t (note) VALUES (?)",
        params=("call me at 09121112233 thanks",),
    )
    result = database.execute_secure("u5", "SELECT note FROM t")
    assert "[PHONE]" in result.rows[0]["note"]
    assert "09121112233" not in result.rows[0]["note"]


def test_audit_chain_verifies_after_writes(db):
    from security_layer import Principal
    analyst = Principal(user_id="u6", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    db.register_principal(analyst)
    db.execute_secure("u6", "SELECT * FROM employees")
    db.execute_secure("u6", "SELECT * FROM employees")
    ok, broken_at = db.audit_trail().verify()
    assert ok
    assert broken_at is None


def test_audit_detects_tampering(db):
    from security_layer import Principal
    analyst = Principal(user_id="u7", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    db.register_principal(analyst)
    db.execute_secure("u7", "SELECT * FROM employees")
    db._conn.execute("UPDATE audit_chain SET decision='deny' WHERE sequence=1")
    ok, broken_at = db.audit_trail().verify()
    assert not ok
    assert broken_at == 1


def test_audit_entries_ordered_newest_last(db):
    from security_layer import Principal
    analyst = Principal(user_id="u8", level=AccessLevel.ANALYST, roles=frozenset({"analyst"}))
    db.register_principal(analyst)
    db.execute_secure("u8", "SELECT * FROM employees")
    entries = db.audit_trail().entries(limit=10)
    sequences = [e.sequence for e in entries]
    assert sequences == sorted(sequences)


def test_custom_role_registration():
    engine_like_db = make_db_with_users()
    from security_layer import Principal
    engine_like_db.rbac.register_role(
        role="auditor",
        permissions={Permission("tables", "read")},
        min_level=2,
    )
    auditor = Principal(user_id="u9", level=AccessLevel.DATA_ADMIN, roles=frozenset({"auditor"}))
    engine_like_db.register_principal(auditor)
    result = engine_like_db.execute_secure("u9", "SELECT * FROM t")
    assert result.columns == ["id", "note"]
