from __future__ import annotations

import re
from dataclasses import dataclass
from enum import IntEnum


class AccessLevel(IntEnum):
    SYSADMIN = 1
    DATA_ADMIN = 2
    ANALYST = 3
    USER = 4
    GUEST = 5


class SecurityError(Exception):
    pass


class AuthenticationError(SecurityError): ...
class AuthorizationError(SecurityError): ...
class RlsViolationError(SecurityError): ...
class AuditError(SecurityError): ...
class MaskingError(SecurityError): ...


@dataclass(frozen=True)
class Principal:
    user_id: str
    level: AccessLevel
    roles: frozenset[str]

    def has_role(self, role: str) -> bool:
        return role in self.roles


ANONYMOUS = Principal(user_id="anonymous", level=AccessLevel.GUEST, roles=frozenset())


NATIONAL_ID_PATTERN: re.Pattern[str] = re.compile(r"\b\d{10}\b")
PHONE_PATTERN: re.Pattern[str] = re.compile(r"\b09\d{9}\b")
CARD_PATTERN: re.Pattern[str] = re.compile(r"\b(?:\d[ -]?){13,19}\b")
EMAIL_PATTERN: re.Pattern[str] = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
IBAN_PATTERN: re.Pattern[str] = re.compile(r"\bIR\d{24}\b")


@dataclass(frozen=True)
class SensitiveColumn:
    column: str
    kind: str
    mask_token: str

    def mask_value(self, value: str) -> str:
        if not value:
            return value
        return self.mask_token
