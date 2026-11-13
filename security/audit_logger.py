from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from utils.secrets import redact_secrets


class AuditLogger:
    def __init__(self, log_path: str = 'logs/audit.log') -> None:
        self.log_path = Path(log_path)

    def log(self, event: str, details: dict) -> None:
        payload = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'event': event,
            'details': redact_secrets(details),
        }
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open('a', encoding='utf-8') as handle:
            handle.write(json.dumps(payload) + '\n')
