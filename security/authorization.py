from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from config import ALLOWED_DOMAINS, ALLOWED_CIDRS
from security.scope_validator import ScopeValidator

@dataclass
class AuthorizationDecision:
    authorized: bool
    reason: str
    passed_checks: List[str]

class AuthorizationPolicy:
    def __init__(self) -> None:
        self.allowed_domains = ALLOWED_DOMAINS
        self.allowed_cidrs = ALLOWED_CIDRS
        self.scope_validator = ScopeValidator()

    def validate_authorization(self, category: str, target: str, authorization: Dict[str, Any], details: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(authorization, dict) or authorization.get('authorized') is not True:
            return {'authorized': False, 'reason': 'Authorization not confirmed. A human-approved scope is required before assessment execution.'}
        if not isinstance(category, str) or not isinstance(target, str) or not isinstance(details, dict):
            return {'authorized': False, 'reason': 'Assessment category, target, and details must have valid structured types.'}

        if category.lower() == 'wifi':
            operation = details.get('operation', 'review')
            if operation not in {'discover', 'review', 'password_audit', 'recover_saved_password'}:
                return {'authorized': False, 'reason': 'Unsupported Wi-Fi assessment operation.'}
            if not isinstance(target, str) or not target.strip():
                return {'authorized': False, 'reason': 'A local interface or explicitly scoped Wi-Fi target is required.'}
            return {'authorized': True, 'reason': 'Wireless authorization verified in lab context.'}

        if category.lower() in {'website', 'network', 'infrastructure'}:
            if self.scope_validator.is_domain(target):
                is_allowed = self.scope_validator.is_allowed_domain(target)
                if not is_allowed:
                    return {'authorized': False, 'reason': f'Domain {target} is outside the approved assessment scope.'}
            elif self.scope_validator.is_cidr_target(target):
                is_allowed = self.scope_validator.is_allowed_cidr(target)
                if not is_allowed:
                    return {'authorized': False, 'reason': f'IP range {target} is outside the approved assessment scope.'}
            elif self.scope_validator.is_ip_address(target):
                if not self.scope_validator.validate_scope(category, target, details):
                    return {'authorized': False, 'reason': f'IP address {target} is outside the approved assessment scope.'}
            else:
                return {'authorized': False, 'reason': 'The target must be an authorized domain or IP range.'}
            return {'authorized': True, 'reason': 'Website and network authorization confirmed.'}

        return {'authorized': False, 'reason': 'Unsupported assessment category.'}
