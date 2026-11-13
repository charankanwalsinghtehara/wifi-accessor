from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class Finding:
    title: str
    description: str
    severity: str
    status: str = 'Potential finding'
    affected_asset: Optional[str] = None
    evidence: Optional[str] = None
    testing_methodology: Optional[str] = None
    confidence: Optional[str] = None
    impact: Optional[str] = None
    remediation: Optional[str] = None

@dataclass
class Assessment:
    assessment_id: str
    category: str
    target: str
    agent: str
    status: str = 'pending'
    findings: List[Finding] = field(default_factory=list)
    summary: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
