# payload-redactor

Pure-function helpers for redacting sensitive data in structured payloads.
Designed as a small, composable core rather than a framework-centric solution.

## Install

Install from PyPI:

```bash
python -m pip install payload-redactor
```

## Usage

```python
from payload_redactor import make_redactor, redact_sensitive_info, redact_with

payload = {"password": "secret", "user": "alice"}
print(redact_sensitive_info(payload))
print(redact_with(payload, replacement="<hidden>"))

redactor = make_redactor(replacement="***")
print(redactor(payload))
```

Output:

```text
{'password': '[REDACTED]', 'user': 'alice'}
{'password': '<hidden>', 'user': 'alice'}
{'password': '***', 'user': 'alice'}
```

Custom replacement per key:

```python
from payload_redactor import redact_sensitive_info

payload = {"password": "secret", "token": "abc"}
redacted = redact_sensitive_info(
    payload,
    replacement="<hidden>",
    key_replacements={"password": "***"},
)
```

Output:

```text
{'password': '***', 'token': '<hidden>'}
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

## Development

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -U pip
python -m pip install -e ".[dev]"
pytest
```
