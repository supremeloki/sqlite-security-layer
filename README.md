# sqlite-security-layer

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A security wrapper around SQLite: role-based access control, PII masking with free-text pattern redaction, and a tamper-evident SHA-256 audit chain — all inside one `SecureDatabase` facade.

## 🚀 Overview

SQLite is everywhere in prototypes and edge deployments, but it ships with zero access control. `sqlite-security-layer` adds the three controls every internal tool needs: **who** may do what (RBAC with level ceilings), **what leaves the door** (column-level masking + regex scanning for national IDs, phones, cards, emails, IBANs), and **who did what** (hash-chained audit log where any tampering breaks verification).

## ✨ Features

- **5-level access model:** `SYSADMIN(1) → GUEST(5)`; roles carry a ceiling — a GUEST with an admin role is still denied
- **Role → permission mapping:** wildcard support (`*` on resource/action), custom runtime registration
- **PII column masking:** register a column once; values are replaced at query time
- **Free-text redaction:** scans string cells for Iranian national IDs, mobile numbers, card numbers, emails, IBANs
- **Tamper-evident audit:** each entry hashes its content + predecessor's hash; `verify()` pinpoints the first broken sequence
- **Principal persistence:** principals stored in-database (`principals` table)
- **Zero dependencies** — stdlib `sqlite3`, `hashlib`, `re`

## 🚧 Structure

```
sqlite-security-layer/
├── src/security_layer/
│   ├── __init__.py
│   ├── audit.py
│   ├── contracts.py
│   ├── core.py
│   ├── masking.py
│   └── rbac.py
├── tests/
│   └── test_core.py
├── README.md
└── pyproject.toml
```

## 📦 Installation

```bash
git clone https://github.com/supremeloki/sqlite-security-layer.git
cd sqlite-security-layer
python -m venv .venv
.venv\Scripts\activate
pip install -e ".[dev]"
```

## 📋 Requirements

- Python 3.11+
- No runtime dependencies

## 🏃 Quick Start

```python
from security_layer import AccessLevel, Principal, SecureDatabase

db = SecureDatabase("app.db")

analyst = Principal(user_id="sara", level=AccessLevel.ANALYST,
                    roles=frozenset({"analyst"}))
db.register_principal(analyst)

db.masking_profile.register(column="phone", kind="phone", mask_token="[PHONE]")

result = db.execute_secure("sara", "SELECT name, phone FROM employees")
print(result.rows)
print(result.masked_columns)
print(result.audit_entry.sequence)

ok, broken_at = db.audit_trail().verify()
```

## 🔧 Error Handling

```text
SecurityError
├── AuthenticationError     # unknown principal
├── AuthorizationError      # missing role / ceiling exceeded / no grant
├── RlsViolationError       # reserved for row-level policies
├── AuditError              # malformed audit input
└── MaskingError            # unknown PII kind
```

## 🧪 Testing

```bash
pytest tests/ -v
```

## 📝 Code Quality

- Full type hints (`X | None` style), frozen contracts, IntEnum levels
- Zero comments — names carry the meaning
- `ruff` clean

## 📄 License

MIT — see [LICENSE](LICENSE).

## 👤 Author

**Kooroush Masoumi**

---

⭐ Star this repo if you find it useful!
