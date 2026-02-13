import sys
import textwrap
import traceback

from payload_redactor.traceback import (
    format_redacted_exception,
    install_excepthook,
    redact_traceback,
    redacting_excepthook,
)


def test_redacts_sensitive_local_variables():
    tb = textwrap.dedent("""\
        Traceback (most recent call last):
          File "app.py", line 10, in login
            raise AuthError("bad credentials")
            username = 'alice'
            password = 'super_secret'
            api_key = 'sk-12345'
            retries = 3
        AuthError: bad credentials
    """)
    redacted = redact_traceback(tb)
    assert "password = [REDACTED]" in redacted
    assert "api_key = [REDACTED]" in redacted
    assert "super_secret" not in redacted
    assert "sk-12345" not in redacted
    # Non-sensitive locals are untouched
    assert "username = 'alice'" in redacted
    assert "retries = 3" in redacted


def test_redacts_token_and_secret_variations():
    tb = textwrap.dedent("""\
        Traceback (most recent call last):
          File "app.py", line 5, in fetch
            raise ConnectionError("timeout")
            access_token = 'tok-abc'
            client_secret = 'cs-xyz'
            refresh_token_value = 'rt-123'
            timeout = 30
        ConnectionError: timeout
    """)
    redacted = redact_traceback(tb)
    assert "access_token = [REDACTED]" in redacted
    assert "client_secret = [REDACTED]" in redacted
    assert "refresh_token_value = [REDACTED]" in redacted
    assert "timeout = 30" in redacted


def test_custom_replacement():
    tb = "    password = 'secret'\n"
    redacted = redact_traceback(tb, replacement="***")
    assert "password = ***" in redacted


def test_custom_keywords():
    tb = "    email = 'alice@example.com'\n    password = 'secret'\n"
    redacted = redact_traceback(
        tb, sensitive_keywords=["email"], replacement="<GONE>"
    )
    assert "email = <GONE>" in redacted
    # password is NOT in custom keywords, so it stays
    assert "password = 'secret'" in redacted


def test_excluded_keywords():
    tb = "    api_key = 'sk-123'\n    public_key = 'pk-abc'\n"
    redacted = redact_traceback(
        tb, excluded_keywords=["public_key"], replacement="<REDACTED>"
    )
    assert "api_key = <REDACTED>" in redacted
    assert "public_key = 'pk-abc'" in redacted


def test_string_rules_applied():
    tb = textwrap.dedent("""\
        Traceback (most recent call last):
          File "app.py", line 3, in connect
            raise ConnectionError("https://user:pass@host/db")
            dsn = 'https://key@sentry.io/1'
        ConnectionError: https://user:pass@host/db
    """)
    redacted = redact_traceback(
        tb, string_rules=[r"https://\S+@\S+"]
    )
    assert "key@sentry" not in redacted
    assert "user:pass@host" not in redacted


def test_preserves_non_assignment_lines():
    tb = textwrap.dedent("""\
        Traceback (most recent call last):
          File "app.py", line 10, in login
            result = do_login(user, password)
        ValueError: invalid credentials
    """)
    redacted = redact_traceback(tb)
    # The source line `result = do_login(...)` should NOT be redacted
    # because `result` is not a sensitive keyword.
    assert "result = do_login(user, password)" in redacted
    assert "ValueError: invalid credentials" in redacted


def test_format_redacted_exception():
    try:
        password = "super_secret"  # noqa: F841
        api_key = "sk-12345"  # noqa: F841
        raise ValueError("something broke")
    except ValueError as exc:
        redacted = format_redacted_exception(exc)

    assert "super_secret" not in redacted
    assert "sk-12345" not in redacted
    assert "password = [REDACTED]" in redacted
    assert "api_key = [REDACTED]" in redacted
    assert "ValueError: something broke" in redacted


def test_format_redacted_exception_without_locals():
    try:
        password = "super_secret"  # noqa: F841
        raise ValueError("oops")
    except ValueError as exc:
        redacted = format_redacted_exception(exc, capture_locals=False)

    # Without capture_locals, there are no local var lines to redact,
    # but the function should still work and show the traceback.
    assert "ValueError: oops" in redacted


def test_redacting_excepthook_writes_to_stderr(capsys):
    try:
        password = "super_secret"  # noqa: F841
        raise ValueError("boom")
    except ValueError:
        exc_type, exc_value, exc_tb = sys.exc_info()
        redacting_excepthook(exc_type, exc_value, exc_tb)

    captured = capsys.readouterr()
    assert "super_secret" not in captured.err
    assert "password = [REDACTED]" in captured.err
    assert "ValueError: boom" in captured.err


def test_install_excepthook():
    original = sys.excepthook
    try:
        install_excepthook(replacement="<HIDDEN>")
        assert sys.excepthook is not original
    finally:
        sys.excepthook = original


def test_chained_exception():
    try:
        try:
            secret_key = "sk-original"  # noqa: F841
            raise ValueError("inner")
        except ValueError:
            auth_token = "tok-456"  # noqa: F841
            raise RuntimeError("outer") from ValueError("inner")
    except RuntimeError as exc:
        redacted = format_redacted_exception(exc)

    assert "sk-original" not in redacted
    assert "tok-456" not in redacted
    assert "secret_key = [REDACTED]" in redacted
    assert "auth_token = [REDACTED]" in redacted


def test_multiple_frames():
    def inner():
        db_password = "pg-secret"  # noqa: F841
        raise ValueError("inner error")

    def outer():
        authorization = "Bearer abc"  # noqa: F841
        inner()

    try:
        outer()
    except ValueError as exc:
        redacted = format_redacted_exception(exc)

    assert "pg-secret" not in redacted
    assert "Bearer abc" not in redacted
    assert "db_password = [REDACTED]" in redacted
    assert "authorization = [REDACTED]" in redacted
