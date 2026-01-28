# payload-redactor

Pure-function helpers for redacting sensitive data in structured payloads.
Deterministic key-based payload redaction (not PII detection).
Designed as a small, composable core rather than a framework-centric solution.

## Install

Install from PyPI:

```bash
python -m pip install payload-redactor
```

## Usage

```python
from payload_redactor import make_redactor, redact, redact_with

payload = {"password": "secret", "user": "alice"}
print(redact(payload))
print(redact(payload, replacement="<hidden>"))

redactor = make_redactor(replacement="###")
print(redactor(payload))
```

Output:

```text
{'password': '***', 'user': 'alice'}
{'password': '<hidden>', 'user': 'alice'}
{'password': '###', 'user': 'alice'}
```

Custom replacement per key:

```python
from payload_redactor import redact

payload = {"password": "secret", "token": "abc"}
redacted = redact(
    payload,
    replacement="<hidden>",
    key_replacements={"password": "***"},
)
```

Output:

```text
{'password': '***', 'token': '<hidden>'}
```

## Examples

Dict/list payload (10 lines):

```python
from payload_redactor import redact
payload = {
    "user": "alice",
    "password": "secret",
    "headers": ["authorization", "Bearer abc"],
    "nested": {"token": "t-123"},
}
redacted = redact(payload)
print(redacted["password"], redacted["headers"][1])
print(redacted["nested"]["token"])
```

Output:

```text
*** ***
***
```

Structured logging event dict (10 lines):

```python
from payload_redactor import redact_event_dict
event_dict = {
    "event": "user login",
    "user_id": 123,
    "password": "secret",
    "meta": {"api_key": "k-1"},
}
redacted = redact_event_dict(None, None, event_dict)
print(redacted["password"])
print(redacted["meta"]["api_key"])
```

Output:

```text
[REDACTED]
[REDACTED]
```

String redaction behavior (10 lines):

```python
from payload_redactor import redact
message = "password=secret token=abc"
print(redact(message))
message = "no secrets here"
print(redact(message))
message = "authorization bearer abc"
print(redact(message))
message = "tokenization is not a match"
print(redact(message))
print(redact("dsn=https://key@host/1"))
```

Output:

```text
***=*** ***=abc
no secrets here
*** bearer abc
tokenization is not a match
dsn=https://***@host/1
```

## Policy configuration

```python
from payload_redactor import Policy, redact

policy = Policy(
    sensitive_keywords=["password", "token"],
    key_replacements={"password": "***"},
    string_rules=[r"Bearer\s+\S+"],
    path_rules=[("user", "email")],
)
payload = {"user": {"email": "alice@example.com"}, "auth": "Bearer abc"}
print(redact(payload, policy=policy, replacement="[REDACTED]"))
```

Output:

```text
{'user': {'email': '[REDACTED]'}, 'auth': '[REDACTED]'}
```

## Non-goals

- This does not detect PII entities; it redacts based on keys/patterns.
- This does not classify data or infer sensitivity from values.

## Guarantees

- Deterministic output for the same input and configuration.
- No mutation of input dict/list/string payloads.
- No dependencies in the core redaction module.
- Type preservation for dict/list/string inputs; other types are returned as-is.

## Common gotchas

Authorization headers and cookie jars often arrive as pairs or dicts:

```python
from payload_redactor import redact
headers = ["authorization", "Bearer abc"]
cookies = {"cookie": "session=secret; csrftoken=abc"}
print(redact(headers))
print(redact(cookies))
```

Output:

```text
['authorization', '***']
{'cookie': 'session=***; csrftoken=abc'}
```

JWTs and DSNs are not detected unless the key matches:

```python
from payload_redactor import redact
payload = {"token": "jwt-value", "dsn": "https://key@host/1"}
redacted = redact(payload, sensitive_keywords=["token", "dsn"])
print(redacted["token"], redacted["dsn"])
```

Output:

```text
*** ***
```

## Structlog adapter (optional)

Install with the extra:

```bash
python -m pip install .[structlog]
```

```python
import logging
import logging.config

import structlog

from payload_redactor import redact_event_dict


shared_processors = [
    structlog.stdlib.add_logger_name,
    structlog.stdlib.add_log_level,
    structlog.processors.TimeStamper(fmt="iso"),
    structlog.processors.UnicodeDecoder(),
]

logging.config.dictConfig(
    {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "console": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.dev.ConsoleRenderer(colors=True),
                "foreign_pre_chain": shared_processors,
            },
            "json": {
                "()": structlog.stdlib.ProcessorFormatter,
                "processor": structlog.processors.JSONRenderer(sort_keys=True),
                "foreign_pre_chain": shared_processors,
            },
        },
        "handlers": {
            "default": {
                "level": "DEBUG",
                "class": "logging.StreamHandler",
                "formatter": "json",
            }
        },
        "loggers": {"": {"handlers": ["default"], "level": "INFO"}},
    }
)

structlog.configure(
    processors=[
        redact_event_dict,
        *shared_processors,
        structlog.stdlib.ProcessorFormatter.wrap_for_formatter,  # type: ignore
    ],
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

logger = structlog.get_logger("app")
logger.info("user login", user_id=123, password="secret")
```

Output (JSON formatter):

```text
{"event": "user login", "level": "info", "logger": "app", "password": "[REDACTED]", "timestamp": "2024-01-01T12:00:00Z", "user_id": 123}
```

## Sentry adapter (optional)

Install with the extra:

```bash
python -m pip install .[sentry]
```

```python
import sentry_sdk

from payload_redactor import redact_sentry_before_send

sentry_sdk.init(
    dsn="https://examplePublicKey@o0.ingest.sentry.io/0",
    before_send=redact_sentry_before_send,
)
```

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
pytest
```
