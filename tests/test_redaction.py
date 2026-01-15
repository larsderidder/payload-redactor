from payload_redactor import (
    make_redactor,
    redact_event_dict,
    redact_sensitive_info,
    redact_with,
)


def test_redacts_dict_keys():
    data = {"password": "secret", "user": "alice"}
    redacted = redact_sensitive_info(data)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["user"] == "alice"


def test_redacts_header_list_pair():
    data = ["authorization", "Bearer abc"]
    redacted = redact_sensitive_info(data)
    assert redacted[1] == "[REDACTED]"


def test_redact_with_replacement():
    data = {"token": "abc"}
    redacted = redact_with(data, replacement="<hidden>")
    assert redacted["token"] == "<hidden>"


def test_make_redactor():
    redactor = make_redactor(replacement="***")
    assert redactor({"secret": "x"})["secret"] == "***"


def test_redact_event_dict():
    payload = {"password": "secret", "user": "alice"}
    redacted = redact_event_dict(None, None, payload)
    assert redacted["password"] == "[REDACTED]"
    assert redacted["user"] == "alice"


def test_key_specific_replacements():
    payload = {"password": "secret", "token": "abc"}
    redacted = redact_sensitive_info(
        payload,
        replacement="<hidden>",
        key_replacements={"password": "***"},
    )
    assert redacted["password"] == "***"
    assert redacted["token"] == "<hidden>"
