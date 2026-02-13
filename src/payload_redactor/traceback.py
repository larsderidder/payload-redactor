"""Redact sensitive variable values from formatted traceback strings.

This module operates on the *text* output of ``traceback.format_exc()``,
``traceback.format_exception()``, or ``TracebackException.format()`` (with
``capture_locals=True``).  It matches lines that look like variable
assignments and redacts the value when the variable name contains a
sensitive keyword.

It also redacts sensitive-looking values embedded in exception messages
(e.g. ``ConnectionError: https://key@host/1``).

This stays within the library's key-based philosophy: it does not try to
detect PII in values, only reacts to variable/key names.
"""

from __future__ import annotations

import re
import sys
import traceback
from typing import Any, Iterable, Pattern

from payload_redactor.redaction import (
    EXCLUDED_TERMS,
    SENSITIVE_TERMS,
    Policy,
    _compile_patterns,
    _normalize_terms,
    _resolve_policy,
    is_sensitive_key,
)


# Matches lines like ``    password = 'super_secret'`` produced by
# ``TracebackException.format()`` with ``capture_locals=True``.
_LOCAL_VAR_RE = re.compile(
    r"^(?P<indent>\s+)(?P<name>[A-Za-z_]\w*)\s*=\s*(?P<value>.+)$",
    re.MULTILINE,
)


def redact_traceback(
    text: str,
    *,
    policy: Policy | None = None,
    replacement: str = "[REDACTED]",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    string_rules: Iterable[str | Pattern[str]] | None = None,
) -> str:
    """Redact sensitive variable assignments in a formatted traceback string.

    Lines matching ``name = value`` where *name* contains a sensitive keyword
    are replaced with ``name = <replacement>``.  Additional ``string_rules``
    are applied as regex substitutions over the entire text (useful for
    DSN patterns, bearer tokens, etc.).

    Parameters
    ----------
    text:
        The formatted traceback string.
    policy:
        Optional Policy for centralized configuration.
    replacement:
        Replacement token for redacted values.
    sensitive_keywords:
        Override the default sensitive keyword list.
    excluded_keywords:
        Keywords that should *not* trigger redaction.
    string_rules:
        Extra regex patterns applied to the full text.

    Returns
    -------
    str
        The traceback with sensitive locals redacted.
    """
    resolved_kw, resolved_ex, _ = _resolve_policy(
        policy,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
    )
    keywords = _normalize_terms(resolved_kw, SENSITIVE_TERMS)
    excludes = _normalize_terms(resolved_ex, EXCLUDED_TERMS)
    resolved_rules = string_rules or (policy.string_rules if policy else None)
    patterns = _compile_patterns(resolved_rules)

    def _replace_local(match: re.Match[str]) -> str:
        name = match.group("name")
        if is_sensitive_key(name, keywords, excludes):
            return f"{match.group('indent')}{name} = {replacement}"
        return match.group(0)

    result = _LOCAL_VAR_RE.sub(_replace_local, text)

    for pattern in patterns:
        result = pattern.sub(replacement, result)

    return result


def format_redacted_exception(
    exc: BaseException,
    *,
    policy: Policy | None = None,
    replacement: str = "[REDACTED]",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    string_rules: Iterable[str | Pattern[str]] | None = None,
    capture_locals: bool = True,
) -> str:
    """Format an exception with locals captured and then redact the output.

    This is a convenience wrapper around ``traceback.TracebackException`` with
    ``capture_locals=True`` followed by :func:`redact_traceback`.
    """
    tb_exc = traceback.TracebackException.from_exception(
        exc, capture_locals=capture_locals
    )
    text = "".join(tb_exc.format())
    return redact_traceback(
        text,
        policy=policy,
        replacement=replacement,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        string_rules=string_rules,
    )


def redacting_excepthook(
    exc_type: type[BaseException],
    exc_value: BaseException,
    exc_tb: Any,
    *,
    policy: Policy | None = None,
    replacement: str = "[REDACTED]",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    string_rules: Iterable[str | Pattern[str]] | None = None,
) -> None:
    """A ``sys.excepthook`` replacement that redacts locals in tracebacks.

    Usage::

        import sys
        from payload_redactor import redacting_excepthook

        sys.excepthook = redacting_excepthook
    """
    tb_exc = traceback.TracebackException(
        exc_type, exc_value, exc_tb, capture_locals=True
    )
    text = "".join(tb_exc.format())
    redacted = redact_traceback(
        text,
        policy=policy,
        replacement=replacement,
        sensitive_keywords=sensitive_keywords,
        excluded_keywords=excluded_keywords,
        string_rules=string_rules,
    )
    sys.stderr.write(redacted)


def install_excepthook(
    *,
    policy: Policy | None = None,
    replacement: str = "[REDACTED]",
    sensitive_keywords: Iterable[str] | None = None,
    excluded_keywords: Iterable[str] | None = None,
    string_rules: Iterable[str | Pattern[str]] | None = None,
) -> None:
    """Install :func:`redacting_excepthook` as ``sys.excepthook``.

    Call this once at startup to ensure all uncaught exceptions have their
    tracebacks redacted before being printed to stderr.

    Usage::

        from payload_redactor import install_excepthook

        install_excepthook()
    """
    def _hook(
        exc_type: type[BaseException],
        exc_value: BaseException,
        exc_tb: Any,
    ) -> None:
        redacting_excepthook(
            exc_type,
            exc_value,
            exc_tb,
            policy=policy,
            replacement=replacement,
            sensitive_keywords=sensitive_keywords,
            excluded_keywords=excluded_keywords,
            string_rules=string_rules,
        )

    sys.excepthook = _hook
