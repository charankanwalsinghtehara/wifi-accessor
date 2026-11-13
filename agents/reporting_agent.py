from __future__ import annotations

import html
import json
from datetime import datetime, timezone
from typing import Any, Iterable

from utils.secrets import redact_secrets


class ReportingAgent:
    """Build timestamped JSON and HTML assessment reports without credentials."""

    def build_report(
        self,
        assessment_id: str,
        scope: str,
        findings: list[dict[str, Any]],
        network_metadata: dict[str, Any] | None = None,
        summary: str = '',
        sensitive_values: Iterable[str] = (),
    ) -> dict[str, Any]:
        report = redact_secrets({
            'assessment_id': assessment_id,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'scope': scope,
            'summary': summary,
            'network_metadata': network_metadata or {},
            'findings': findings,
        })
        secret_values = tuple(
            value for value in sensitive_values if isinstance(value, str) and value
        )
        report = self._remove_sensitive_values(report, secret_values)
        json_report = json.dumps(report, indent=2, ensure_ascii=False)
        html_report = self._html(report)
        return {'data': report, 'json': json_report, 'html': html_report}

    @classmethod
    def _remove_sensitive_values(cls, value: Any, secrets: tuple[str, ...]) -> Any:
        if isinstance(value, dict):
            return {
                key: cls._remove_sensitive_values(item, secrets)
                for key, item in value.items()
            }
        if isinstance(value, list):
            return [cls._remove_sensitive_values(item, secrets) for item in value]
        if isinstance(value, str):
            for secret in secrets:
                value = value.replace(secret, '[REDACTED]')
            return value
        return value

    @staticmethod
    def _html(report: dict[str, Any]) -> str:
        metadata = html.escape(json.dumps(report['network_metadata'], indent=2, ensure_ascii=False))
        rows = []
        for finding in report['findings']:
            rows.append(
                '<tr>'
                f"<td>{html.escape(str(finding.get('severity', '')))}</td>"
                f"<td>{html.escape(str(finding.get('title', '')))}</td>"
                f"<td>{html.escape(str(finding.get('description', '')))}</td>"
                f"<td>{html.escape(str(finding.get('evidence', '')))}</td>"
                f"<td>{html.escape(str(finding.get('remediation', '')))}</td>"
                '</tr>'
            )
        findings_html = ''.join(rows) or '<tr><td colspan="5">No findings.</td></tr>'
        return (
            '<!doctype html><html lang="en"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width, initial-scale=1">'
            f'<title>CyberSentinel assessment {html.escape(str(report["assessment_id"]))}</title>'
            '<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#17212b}'
            'table{border-collapse:collapse;width:100%}td,th{border:1px solid #ccd3da;padding:.6rem;text-align:left}'
            'th{background:#edf2f6}pre{white-space:pre-wrap;background:#f4f6f8;padding:1rem}</style></head><body>'
            '<h1>CyberSentinel AI Wi-Fi assessment</h1>'
            f'<p><strong>Assessment:</strong> {html.escape(str(report["assessment_id"]))}</p>'
            f'<p><strong>Timestamp:</strong> {html.escape(str(report["timestamp"]))}</p>'
            f'<p><strong>Scope:</strong> {html.escape(str(report["scope"]))}</p>'
            f'<p>{html.escape(str(report["summary"]))}</p>'
            '<h2>Network metadata</h2>'
            f'<pre>{metadata}</pre><h2>Findings and remediation</h2>'
            '<table><thead><tr><th>Severity</th><th>Finding</th><th>Details</th><th>Evidence</th><th>Remediation</th></tr></thead>'
            f'<tbody>{findings_html}</tbody></table></body></html>'
        )
