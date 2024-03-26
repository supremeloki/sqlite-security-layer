from __future__ import annotations

import re
import sqlite3
from dataclasses import dataclass, field

from .contracts import (
    CARD_PATTERN,
    EMAIL_PATTERN,
    IBAN_PATTERN,
    MaskingError,
    NATIONAL_ID_PATTERN,
    PHONE_PATTERN,
    SensitiveColumn,
)


@dataclass
class MaskingProfile:
    columns: dict[str, SensitiveColumn] = field(default_factory=dict)

    def register(self, column: str, kind: str, mask_token: str) -> None:
        if kind not in {"national_id", "phone", "card", "email", "iban", "opaque"}:
            raise MaskingError(f"unknown pii kind: {kind!r}")
        self.columns[column] = SensitiveColumn(column=column, kind=kind, mask_token=mask_token)

    def for_column(self, column: str) -> SensitiveColumn | None:
        return self.columns.get(column)


PATTERNS: dict[str, re.Pattern[str]] = {
    "national_id": NATIONAL_ID_PATTERN,
    "phone": PHONE_PATTERN,
    "card": CARD_PATTERN,
    "email": EMAIL_PATTERN,
    "iban": IBAN_PATTERN,
}


class RowMasker:
    def __init__(self, profile: MaskingProfile, scan_free_text: bool = True) -> None:
        self._profile = profile
        self._scan = scan_free_text

    def mask_row(self, row: sqlite3.Row, columns: list[str]) -> dict[str, object]:
        masked: dict[str, object] = {}
        for column in columns:
            value = row[column]
            sensitive = self._profile.for_column(column)
            if sensitive is not None and isinstance(value, str):
                masked[column] = sensitive.mask_value(value)
                continue
            if self._scan and isinstance(value, str):
                masked[column] = self._scan_text(value)
                continue
            masked[column] = value
        return masked

    def mask_rows(self, rows: list[sqlite3.Row], columns: list[str]) -> list[dict[str, object]]:
        return [self.mask_row(row, columns) for row in rows]

    def _scan_text(self, text: str) -> str:
        result = text
        for kind, pattern in PATTERNS.items():
            sensitive = SensitiveColumn(
                column=f"<{kind}>", kind=kind, mask_token=self._token_for(kind)
            )
            result = pattern.sub(sensitive.mask_token, result)
        return result

    @staticmethod
    def _token_for(kind: str) -> str:
        tokens = {
            "national_id": "[NATIONAL-ID]",
            "phone": "[PHONE]",
            "card": "[CARD]",
            "email": "[EMAIL]",
            "iban": "[IBAN]",
        }
        return tokens[kind]
