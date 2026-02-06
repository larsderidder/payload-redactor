import logging

from payload_redactor.logging_adapter import redact_log_record


def _make_record(*, msg, args=(), level=logging.INFO) -> logging.LogRecord:
    return logging.LogRecord(
        name="test",
        level=level,
        pathname=__file__,
        lineno=1,
        msg=msg,
        args=args,
        exc_info=None,
    )


def test_redact_log_record_redacts_msg_dict() -> None:
    record = _make_record(msg={"password": "secret", "user": "alice"})
    redact_log_record(record)
    assert record.msg["password"] == "[REDACTED]"
    assert record.msg["user"] == "alice"


def test_redact_log_record_redacts_args_tuple_values() -> None:
    record = _make_record(msg="password=%s", args=("secret",))
    redact_log_record(record)
    assert record.args == ("[REDACTED]",)

    # logging.LogRecord normalizes `args` to a mapping when given a single dict-like
    # argument, so treat this as a dict case.
    record2 = _make_record(msg="payload=%(token)s", args=({"token": "t-123"},))
    redact_log_record(record2)
    assert record2.args["token"] == "[REDACTED]"


def test_redact_log_record_redacts_extra_fields_by_key() -> None:
    record = _make_record(msg="hello")
    record.password = "secret"
    record.meta = {"api_key": "k-1"}
    redact_log_record(record)
    assert record.password == "[REDACTED]"
    assert record.meta["api_key"] == "[REDACTED]"
