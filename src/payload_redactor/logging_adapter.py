"""Python stdlib logging adapters for payload redaction.

This module is dependency-free (stdlib only) and provides a `logging.Filter`
that redacts `LogRecord` fields in-place.
"""

from __future__ import annotations

import logging
from typing import Any, Iterable

from payload_redactor.redaction import Policy, _resolve_policy, redact_sensitive_info


# Keep this conservative: only exclude well-known LogRecord attributes.
# Anything else is likely "extra" data provided by application code.
_LOG_RECORD_BUILTIN_KEYS: frozenset[str] = frozenset(
    {
        "name",
        "msg",
        "args",
        "levelname",
        "levelno",
        "pathname",
        "filename",
        "module",
        "exc_info",
        "exc_text",
        "stack_info",
        "lineno",
        "funcName",
        "created",
        "msecs",
        "relativeCreated",
        "thread",
        "threadName",
        "processName",
        "process",
        # Python 3.12+ may add this for asyncio tasks.
        "taskName",
    }
)


def _redact_value(
    value: Any,
    *,
    sensitive_keywords: Iterable[str] | None,
    excluded_keywords: Iterable[str] | None,
    replacement: str,
    key_replacements: dict[str, str] | None,
) -> Any:
    if isinstance(value, (dict, list, str)):
        return redact_sensitive_info(
            value,
            sensitive_keywords=sensitive_keywords,
            excluded_keywords=excluded_keywords,
            replacement=replacement,
            key_replacements=key_replacements,
        )
    return value


def redact_log_record(
    record: logging.LogRecord,
    *,
    policy: Policy | None = None,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> logging.LogRecord:
    """Redact a `logging.LogRecord` in-place and return it."""
    resolved_kw, resolved_ex, resolved_kr = _resolve_policy(
        policy,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        key_replacements=key_replacements,
    )
    kwargs: dict[str, Any] = dict(
        sensitive_keywords=resolved_kw,
        excluded_keywords=resolved_ex,
        replacement=replacement,
        key_replacements=resolved_kr,
    )

    record.msg = _redact_value(record.msg, **kwargs)

    args = record.args
    if isinstance(args, tuple):
        record.args = tuple(_redact_value(item, **kwargs) for item in args)
    elif isinstance(args, dict):
        record.args = redact_sensitive_info(
            args,
            sensitive_keywords=resolved_kw,
            excluded_keywords=resolved_ex,
            replacement=replacement,
            key_replacements=resolved_kr,
        )

    extras = {k: v for k, v in record.__dict__.items() if k not in _LOG_RECORD_BUILTIN_KEYS}
    if extras:
        redacted_extras = redact_sensitive_info(
            extras,
            sensitive_keywords=resolved_kw,
            excluded_keywords=resolved_ex,
            replacement=replacement,
            key_replacements=resolved_kr,
        )
        if isinstance(redacted_extras, dict):
            record.__dict__.update(redacted_extras)

    return record


class RedactingFilter(logging.Filter):
    """A `logging.Filter` that redacts `LogRecord` fields in-place."""

    def __init__(
        self,
        *,
        policy: Policy | None = None,
        sensitive_keywords: Iterable[str] | None = None,
        excluded_keywords: Iterable[str] | None = None,
        replacement: str = "[REDACTED]",
        key_replacements: dict[str, str] | None = None,
    ) -> None:
        super().__init__()
        self._policy = policy
        self._sensitive_keywords = sensitive_keywords
        self._excluded_keywords = excluded_keywords
        self._replacement = replacement
        self._key_replacements = key_replacements

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        redact_log_record(
            record,
            policy=self._policy,
            sensitive_keywords=self._sensitive_keywords,
            excluded_keywords=self._excluded_keywords,
            replacement=self._replacement,
            key_replacements=self._key_replacements,
        )
        return True


def make_redacting_filter(
    *,
    policy: Policy | None = None,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> logging.Filter:
    """Convenience factory for `RedactingFilter`."""
    return RedactingFilter(
        policy=policy,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
