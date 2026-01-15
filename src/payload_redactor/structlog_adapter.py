"""Structlog adapters for payload redaction."""

from __future__ import annotations

from typing import Any, Iterable

from payload_redactor.redaction import redact_sensitive_info


def redact_event_dict(
    _,
    __,
    event_dict: dict[str, Any],
    *,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Structlog processor that redacts sensitive data in event dictionaries.
    """
    return redact_sensitive_info(
        event_dict,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
