"""Sentry adapter helpers for payload redaction."""

from __future__ import annotations

import json
from typing import Any, Iterable

from payload_redactor.redaction import redact_sensitive_info


def parse_message_from_json_to_dict(message: str | None) -> dict[str, Any]:
    """
    JSON-deserialize a log message or return {"event": message}.
    """
    default_result = {"event": message}
    if message is None:
        return default_result
    try:
        return json.loads(message.replace('"', '\\"').replace("'", '"'))
    except (TypeError, ValueError):
        return default_result


def _redact_event_extra(
    event: dict[str, Any],
    hint: dict[str, Any] | None,
    *,
    sensitive_keywords: Iterable[str] | None,
    excluded_keywords: Iterable[str] | None,
    replacement: str,
    key_replacements: dict[str, str] | None,
) -> None:
    log_record = hint.get("log_record") if isinstance(hint, dict) else None
    if log_record is None:
        return
    log_message = getattr(log_record, "msg", None)
    if log_message is None:
        return
    redacted_message = redact_sensitive_info(
        log_message,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
    extra = event.get("extra")
    if isinstance(extra, dict):
        if isinstance(redacted_message, dict):
            extra.update(redacted_message)
        else:
            extra.setdefault("message", redacted_message)


def _redact_breadcrumbs(
    event: dict[str, Any],
    *,
    sensitive_keywords: Iterable[str] | None,
    excluded_keywords: Iterable[str] | None,
    replacement: str,
    key_replacements: dict[str, str] | None,
) -> None:
    breadcrumbs = event.get("breadcrumbs")
    if not isinstance(breadcrumbs, dict):
        return
    breadcrumb_values = breadcrumbs.get("values")
    if not isinstance(breadcrumb_values, list):
        return
    for breadcrumb in breadcrumb_values:
        if not isinstance(breadcrumb, dict):
            continue
        if breadcrumb.get("type") == "log":
            log_message = breadcrumb.get("message")
            parsed_log_message = (
                parse_message_from_json_to_dict(log_message)
                if isinstance(log_message, str)
                else {"event": log_message}
            )
            redaction_target = parsed_log_message.get("event", log_message)
            breadcrumb["message"] = redact_sensitive_info(
                redaction_target,
                sensitive_keywords=sensitive_keywords,
                excluded_keywords=excluded_keywords,
                replacement=replacement,
                key_replacements=key_replacements,
            )


def _redact_exception_vars(
    event: dict[str, Any],
    *,
    sensitive_keywords: Iterable[str] | None,
    excluded_keywords: Iterable[str] | None,
    replacement: str,
    key_replacements: dict[str, str] | None,
) -> None:
    exception = event.get("exception")
    if not isinstance(exception, dict):
        return
    values = exception.get("values")
    if not isinstance(values, list):
        return
    for entry in values:
        if not isinstance(entry, dict):
            continue
        stacktrace = entry.get("stacktrace")
        if not isinstance(stacktrace, dict):
            continue
        frames = stacktrace.get("frames")
        if not isinstance(frames, list):
            continue
        for frame in frames:
            if not isinstance(frame, dict):
                continue
            if "vars" in frame:
                frame["vars"] = redact_sensitive_info(
                    frame["vars"],
                    sensitive_keywords=sensitive_keywords,
                    excluded_keywords=excluded_keywords,
                    replacement=replacement,
                    key_replacements=key_replacements,
                )


def _redact_request_headers(
    event: dict[str, Any],
    *,
    sensitive_keywords: Iterable[str] | None,
    excluded_keywords: Iterable[str] | None,
    replacement: str,
    key_replacements: dict[str, str] | None,
) -> None:
    request = event.get("request")
    if isinstance(request, dict) and "headers" in request:
        request["headers"] = redact_sensitive_info(
            request["headers"],
            sensitive_keywords=sensitive_keywords,
            excluded_keywords=excluded_keywords,
            replacement=replacement,
            key_replacements=key_replacements,
        )


def redact_sentry_before_send(
    event: dict[str, Any],
    hint: dict[str, Any] | None,
    *,
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    replacement: str = "[REDACTED]",
    key_replacements: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """
    Redact sensitive data for use with Sentry's before_send hook.
    """
    _redact_event_extra(
        event,
        hint,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
    _redact_breadcrumbs(
        event,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
    _redact_exception_vars(
        event,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
    _redact_request_headers(
        event,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        replacement=replacement,
        key_replacements=key_replacements,
    )
    return event
