from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from security.authorization import AuthorizationPolicy
from security.scope_validator import ScopeValidator

@dataclass
class InfrastructureAgent:
    authorization_policy: AuthorizationPolicy = None
    scope_validator: ScopeValidator = None

    def __post_init__(self) -> None:
        if self.authorization_policy is None:
            self.authorization_policy = AuthorizationPolicy()
        if self.scope_validator is None:
            self.scope_validator = ScopeValidator()

    def execute(self, request: Any) -> Dict[str, Any]:
        target = request.target
        authorization = self.authorization_policy.validate_authorization(
            request.category or 'infrastructure', target, request.authorization, request.details
        )
        scope_ok = self.scope_validator.validate_scope(
            request.category or 'infrastructure', target, request.details, request.authorization
        )
        if not authorization['authorized'] or not scope_ok:
            return {'status': 'blocked', 'summary': 'Website/network assessment blocked outside the authorized scope.', 'findings': []}
        findings: List[Dict[str, Any]] = [{'title': 'Safe reconnaissance review', 'severity': 'Low', 'status': 'Informational observation', 'description': 'The system completed a non-destructive reconnaissance check with safe, authorized scanning only.', 'affected_asset': target, 'evidence': 'Simulated host and service metadata generated under demo authorization rules.', 'testing_methodology': 'Authorized scope validation + non-destructive reconnaissance simulation.', 'confidence': 'High', 'impact': 'Limited operational impact with no intrusive testing.', 'remediation': 'Confirm the approved asset scope before running active discovery.'}]
        return {'status': 'demo', 'summary': 'Infrastructure assessment executed in demo mode with clearly labeled simulated evidence.', 'findings': findings}
