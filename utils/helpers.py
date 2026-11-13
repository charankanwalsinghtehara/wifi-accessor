from __future__ import annotations

from typing import Any, Dict

def safe_get(mapping: Dict[str, Any], key: str, default: Any = None) -> Any:
    return mapping.get(key, default)
