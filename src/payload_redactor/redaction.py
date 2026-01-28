"""Redact sensitive info from nested structures."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Iterable, Pattern


SENSITIVE_TERMS = ["token", "secret", "password", "key", "authorization"]
EXCLUDED_TERMS: list[str] = []


@dataclass(frozen=True)
class Policy:
    """Configuration for redaction behavior."""

    sensitive_keywords: Iterable[str] | None = None
    excluded_keywords: Iterable[str] | None = None
    key_replacements: dict[str, str] | None = None
    string_rules: Iterable[str | Pattern[str]] | None = None
    header_patterns: Iterable[str | Pattern[str]] | None = None
    path_rules: Iterable[tuple[str, ...]] | None = None


def _normalize_terms(terms: Iterable[str] | None, fallback: list[str]) -> list[str]:
    """Normalize terms to lowercase strings."""
    return [entry.lower() for entry in (terms or fallback)]


def _normalize_path_rules(
    rules: Iterable[tuple[str, ...]] | None,
) -> list[tuple[str, ...]]:
    if not rules:
        return []
    normalized: list[tuple[str, ...]] = []
    for rule in rules:
        normalized.append(tuple(str(part).lower() for part in rule))
    return normalized


def _compile_patterns(
    rules: Iterable[str | Pattern[str]] | None,
) -> list[Pattern[str]]:
    if not rules:
        return []
    compiled: list[Pattern[str]] = []
    for rule in rules:
        if isinstance(rule, re.Pattern):
            compiled.append(rule)
        else:
            compiled.append(re.compile(rule, flags=re.IGNORECASE))
    return compiled


def _apply_string_rules(
    value: str, patterns: list[Pattern[str]], replacement: str
) -> str:
    sanitized = value
    for pattern in patterns:
        sanitized = pattern.sub(replacement, sanitized)
    return sanitized


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
    string_patterns: list[Pattern[str]],
    path_rules: list[tuple[str, ...]],
    path: tuple[str, ...],
) -> dict[str, Any] | list | str:
    if path_rules and path in path_rules:
        return replacement
    if isinstance(data, dict):
        sanitized: dict[str, Any] = {}
        for key, value in data.items():
            path_key = str(key).lower()
            next_path = path + (path_key,)
            if is_sensitive_key(key, keywords, excludes):
                key_value = str(key).lower()
                sanitized[key] = key_replacements.get(key_value, replacement)
            else:
                sanitized[key] = _apply_redaction(
                    value,
                    keywords,
                    excludes,
                    replacement,
                    key_replacements,
                    string_patterns,
                    path_rules,
                    next_path,
                )
        return sanitized
    if isinstance(data, list):
        pair = _mask_pair(data)
        if pair is not None and is_sensitive_key(pair[0], keywords, excludes):
            key_value = str(pair[0]).lower()
            return [pair[0], key_replacements.get(key_value, replacement)]
        sanitized_items: list[Any] = []
        for index, item in enumerate(data):
            next_path = path + (str(index),)
            sanitized_items.append(
                _apply_redaction(
                    item,
                    keywords,
                    excludes,
                    replacement,
                    key_replacements,
                    string_patterns,
                    path_rules,
                    next_path,
                )
            )
        return sanitized_items
    if isinstance(data, str):
        sanitized = _apply_string_rules(data, string_patterns, replacement)
        return _mask_string(sanitized, keywords, replacement)
    return data


def redact(
    data: dict[str, Any] | list | str,
    *,
    policy: Policy | None = None,
    replacement: str = "***",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    key_replacements: dict[str, str] | None = None,
    string_rules: Iterable[str | Pattern[str]] | None = None,
    header_patterns: Iterable[str | Pattern[str]] | None = None,
    path_rules: Iterable[tuple[str, ...]] | None = None,
) -> dict[str, Any] | list | str:
    """
    Redact sensitive information from data based on keyword and rule matching.
    """
    policy_sensitive = policy.sensitive_keywords if policy else None
    policy_excluded = policy.excluded_keywords if policy else None
    policy_key_replacements = policy.key_replacements if policy else None
    policy_string_rules = policy.string_rules if policy else None
    policy_header_patterns = policy.header_patterns if policy else None
    policy_path_rules = policy.path_rules if policy else None

    keywords = _normalize_terms(sensitive_keywords or policy_sensitive, SENSITIVE_TERMS)
    excludes = _normalize_terms(excluded_keywords or policy_excluded, EXCLUDED_TERMS)
    replacement_source = (
        key_replacements
        if key_replacements is not None
        else (policy_key_replacements or {})
    )
    replacements = {key.lower(): value for key, value in replacement_source.items()}
    string_patterns = _compile_patterns(string_rules or policy_string_rules)
    string_patterns += _compile_patterns(header_patterns or policy_header_patterns)
    normalized_paths = _normalize_path_rules(path_rules or policy_path_rules)

    try:
        return _apply_redaction(
            data,
            keywords,
            excludes,
            replacement,
            replacements,
            string_patterns,
            normalized_paths,
            (),
        )
    except Exception:
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
        return _apply_redaction(
            data, keywords, excludes, replacement, replacements, [], [], ()
        )
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
        return _apply_redaction(
            data, keywords, excludes, replacement, replacements, [], [], ()
        )
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
            return _apply_redaction(
                data, keywords, excludes, replacement, replacements, [], [], ()
            )
        except Exception:
            return data

    return _redactor
