from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


class AssessmentDatabase:
    def __init__(self, database_path: str = 'data/cybersentinel.db') -> None:
        self.database_path = Path(database_path)
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.initialize()

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        """Create a short-lived connection for the calling Streamlit worker thread."""
        connection = sqlite3.connect(self.database_path, timeout=30)
        try:
            connection.row_factory = sqlite3.Row
            connection.execute('PRAGMA busy_timeout = 30000')
            yield connection
        finally:
            connection.close()

    def initialize(self) -> None:
        with self._connection() as connection:
            connection.execute('PRAGMA journal_mode = WAL')
            connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS assessments (
                    id TEXT PRIMARY KEY,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    agent TEXT,
                    status TEXT NOT NULL,
                    summary TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
                '''
            )
            connection.execute(
                '''
                CREATE TABLE IF NOT EXISTS findings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    assessment_id TEXT NOT NULL,
                    title TEXT,
                    severity TEXT,
                    status TEXT,
                    evidence TEXT,
                    FOREIGN KEY(assessment_id) REFERENCES assessments(id)
                )
                '''
            )
            connection.commit()

    def save_assessment(self, record: dict) -> None:
        with self._connection() as connection:
            with connection:
                connection.execute(
                    'INSERT INTO assessments (id, category, target, agent, status, summary) VALUES (?, ?, ?, ?, ?, ?)',
                    (
                        record['assessment_id'],
                        record['category'],
                        record['target'],
                        record.get('agent'),
                        record.get('status', 'pending'),
                        record.get('summary'),
                    ),
                )
                for finding in record.get('findings', []):
                    connection.execute(
                        'INSERT INTO findings (assessment_id, title, severity, status, evidence) VALUES (?, ?, ?, ?, ?)',
                        (
                            record['assessment_id'],
                            finding.get('title'),
                            finding.get('severity'),
                            finding.get('status'),
                            finding.get('evidence'),
                        ),
                    )

    def list_assessments(self) -> list[dict]:
        with self._connection() as connection:
            rows = connection.execute(
                'SELECT id, category, target, agent, status, summary, created_at FROM assessments ORDER BY created_at DESC'
            ).fetchall()
            return [dict(row) for row in rows]
