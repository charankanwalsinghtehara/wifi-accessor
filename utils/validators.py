from __future__ import annotations

from typing import Any, Dict

def normalize_target(target: str) -> str:
    if not target:
        return ''
    return target.strip()

def ensure_dict(value: Dict[str, Any] | None) -> Dict[str, Any]:
    return value or {}
