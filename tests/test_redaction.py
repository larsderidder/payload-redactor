from payload_redactor import (
    Policy,
    get_default_sensitive_keywords,
    make_redactor,
    redact,
    redact_event_dict,
    redact_sensitive_info,
    redact_sentry_before_send,
    redact_with,
)


def test_get_default_sensitive_keywords():
    keywords = get_default_sensitive_keywords()
    assert isinstance(keywords, list)
    assert "password" in keywords
    assert "token" in keywords
    # Ensure it returns a copy, not the original
    keywords.append("custom")
    assert "custom" not in get_default_sensitive_keywords()


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


def test_redact_policy_rules():
    policy = Policy(
        key_replacements={"password": "***"},
        string_rules=[r"Bearer\s+\S+"],
        path_rules=[("user", "email")],
    )
    payload = {
        "user": {"email": "alice@example.com", "name": "alice"},
        "auth": "Bearer abc",
        "password": "secret",
    }
    redacted = redact(payload, policy=policy, replacement="[REDACTED]")
    assert redacted["user"]["email"] == "[REDACTED]"
    assert redacted["auth"] == "[REDACTED]"
    assert redacted["password"] == "***"


def test_redact_sentry_before_send():
    class DummyRecord:
        def __init__(self, msg, name="app"):
            self.msg = msg
            self.name = name

    event = {
        "extra": {"exception": "Traceback line\nValueError: bad"},
        "logentry": {},
        "breadcrumbs": {"values": [{"type": "log", "message": "{'event': 'password'}"}]},
        "request": {"headers": {"authorization": "Bearer abc"}},
    }
    hint = {"log_record": DummyRecord({"event": "oops", "password": "secret"})}

    redacted = redact_sentry_before_send(event, hint)

    assert redacted["extra"]["password"] == "[REDACTED]"
    assert redacted["request"]["headers"]["authorization"] == "[REDACTED]"
    assert redacted["breadcrumbs"]["values"][0]["message"] == "[REDACTED]"
