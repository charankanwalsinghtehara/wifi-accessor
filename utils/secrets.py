from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

_SECRET_KEY = re.compile(r'(?:password|passphrase|psk|secret|token|api[_-]?key|credential)', re.I)
_INLINE_SECRET = re.compile(
    r'(?i)\b(password|passphrase|psk|secret|token|api[_-]?key|credential)(\s*[:=]\s*)'
    r'("[^"]*"|\'[^\']*\'|[^\s,;]+)'
)


def redact_secrets(value: Any) -> Any:
    """Redact secret-valued fields and common inline key/value forms."""
    if isinstance(value, Mapping):
        return {
            key: '[REDACTED]' if _SECRET_KEY.search(str(key)) else redact_secrets(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_secrets(item) for item in value)
    if isinstance(value, str):
        return _INLINE_SECRET.sub(r'\1\2[REDACTED]', value)
    return value
