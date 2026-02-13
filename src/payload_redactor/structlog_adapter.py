"""Structlog adapters for payload redaction."""

from __future__ import annotations

from typing import Any, Iterable

from payload_redactor.redaction import Policy, _resolve_policy, redact_sensitive_info


def redact_event_dict(
    _,
    __,
    event_dict: dict[str, Any],
    *,
    policy: Policy | None = None,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Structlog processor that redacts sensitive data in event dictionaries.
    """
    resolved_kw, resolved_ex, resolved_kr = _resolve_policy(
        policy,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        key_replacements=key_replacements,
    )
    return redact_sensitive_info(
        event_dict,
        sensitive_keywords=resolved_kw,
        excluded_keywords=resolved_ex,
        replacement=replacement,
        key_replacements=resolved_kr,
    )
