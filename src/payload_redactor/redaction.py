"""Redact sensitive info from nested structures."""

from __future__ import annotations

import re
from typing import Any, Iterable


SENSITIVE_TERMS = ["token", "secret", "password", "key", "authorization"]
EXCLUDED_TERMS: list[str] = []


def _normalize_terms(terms: Iterable[str] | None, fallback: list[str]) -> list[str]:
    """Normalize terms to lowercase strings."""
    return [entry.lower() for entry in (terms or fallback)]


def _is_text_key(value: Any) -> bool:
    """Return True if the value is a string key."""
    return isinstance(value, str)


def is_sensitive_key(
    key: Any,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
) -> bool:
    """Check if the key contains a sensitive keyword."""
    if not _is_text_key(key):
        return False
    keywords = _normalize_terms(sensitive_keywords, SENSITIVE_TERMS)
    excludes = _normalize_terms(excluded_keywords, EXCLUDED_TERMS)
    lowered = key.lower()
    if any(blocked in lowered for blocked in excludes):
        return False
    return any(token in lowered for token in keywords)


def _mask_string(value: str, keywords: Iterable[str], replacement: str) -> str:
    """Mask keyword matches within a string."""
    return re.sub(
        r"\b(?:" + "|".join(keywords) + r")\b",
        replacement,
        value,
        flags=re.IGNORECASE,
    )


def _mask_pair(items: list) -> list | None:
    """Return list if it looks like a header/value pair; otherwise None."""
    if len(items) == 2 and _is_text_key(items[0]) and _is_text_key(items[1]):
        return items
    return None


def _apply_redaction(
    data: dict[str, Any] | list | str,
    keywords: list[str],
    excludes: list[str],
    replacement: str,
    key_replacements: dict[str, str],
) -> dict[str, Any] | list | str:
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            if is_sensitive_key(key, keywords, excludes):
                key_value = str(key).lower()
                sanitized[key] = key_replacements.get(key_value, replacement)
            else:
                sanitized[key] = _apply_redaction(
                    value, keywords, excludes, replacement, key_replacements
                )
        return sanitized
    if isinstance(data, list):
        pair = _mask_pair(data)
        if pair is not None and is_sensitive_key(pair[0], keywords, excludes):
            key_value = str(pair[0]).lower()
            return [pair[0], key_replacements.get(key_value, replacement)]
        return [
            _apply_redaction(item, keywords, excludes, replacement, key_replacements)
            for item in data
        ]
    if isinstance(data, str):
        return _mask_string(data, keywords, replacement)
    return data


def redact_sensitive_info(
    data: dict[str, Any] | list | str,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> dict[str, Any] | list | str:
    """
    Redact sensitive information from data based on keyword matching.

    Use key_replacements to override the replacement per key.
    """
    keywords = _normalize_terms(sensitive_keywords, SENSITIVE_TERMS)
    excludes = _normalize_terms(excluded_keywords, EXCLUDED_TERMS)
    replacements = {key.lower(): value for key, value in (key_replacements or {}).items()}

    try:
        return _apply_redaction(data, keywords, excludes, replacement, replacements)
    except Exception:
        return data


def redact_with(
    data: dict[str, Any] | list | str,
    replacement: str,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    key_replacements: dict[str, str] | None = None,
) -> dict[str, Any] | list | str:
    """Redact sensitive info with a custom replacement string."""
    keywords = _normalize_terms(sensitive_keywords, SENSITIVE_TERMS)
    excludes = _normalize_terms(excluded_keywords, EXCLUDED_TERMS)
    replacements = {key.lower(): value for key, value in (key_replacements or {}).items()}
    try:
        return _apply_redaction(data, keywords, excludes, replacement, replacements)
    except Exception:
        return data


def make_redactor(
    replacement: str = "[REDACTED]",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    key_replacements: dict[str, str] | None = None,
):
    """Return a redaction function with preset parameters."""
    keywords = _normalize_terms(sensitive_keywords, SENSITIVE_TERMS)
    excludes = _normalize_terms(excluded_keywords, EXCLUDED_TERMS)
    replacements = {key.lower(): value for key, value in (key_replacements or {}).items()}

    def _redactor(data: dict[str, Any] | list | str) -> dict[str, Any] | list | str:
        try:
            return _apply_redaction(data, keywords, excludes, replacement, replacements)
        except Exception:
            return data

    return _redactor
