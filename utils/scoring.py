from __future__ import annotations

from typing import Iterable

SEVERITY_WEIGHT = {'Critical': 25, 'High': 15, 'Medium': 8, 'Low': 3, 'Informational': 1}

def compute_risk_score(findings: Iterable[dict]) -> int:
    total = 0
    for finding in findings:
        total += SEVERITY_WEIGHT.get(finding.get('severity', 'Informational'), 1)
    return min(total, 100)
