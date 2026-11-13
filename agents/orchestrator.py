from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

from security.audit_logger import AuditLogger
from security.authorization import AuthorizationPolicy
from security.scope_validator import ScopeValidator
from utils.validators import normalize_target

@dataclass
class AssessmentRequest:
    category: str
    target: str
    authorization: Dict[str, Any] = field(default_factory=dict)
    details: Dict[str, Any] = field(default_factory=dict)
    assessment_id: Optional[str] = None

class MasterOrchestrator:
    def __init__(
        self,
        authorization_policy: AuthorizationPolicy | None = None,
        scope_validator: ScopeValidator | None = None,
        audit_logger: AuditLogger | None = None,
    ) -> None:
        self.authorization_policy = authorization_policy or AuthorizationPolicy()
        self.scope_validator = scope_validator or ScopeValidator()
        self.audit_logger = audit_logger or AuditLogger()

    def plan_assessment(self, request: AssessmentRequest) -> Dict[str, Any]:
        if not isinstance(request, AssessmentRequest):
            assessment_id = str(uuid.uuid4())
            self.audit_logger.log('assessment_blocked', {
                'assessment_id': assessment_id,
                'reason': 'Assessment request has an invalid type.',
            })
            return {
                'assessment_id': assessment_id,
                'category': '',
                'target': '',
                'status': 'blocked',
                'reason': 'Assessment request has an invalid type.',
                'agent': None,
                'plan': [{'step': 'request validation', 'status': 'blocked'}],
            }
        assessment_id = (
            request.assessment_id
            if isinstance(request.assessment_id, str)
            and request.assessment_id
            and len(request.assessment_id) <= 128
            else str(uuid.uuid4())
        )
        if (
            not isinstance(request.category, str)
            or not request.category.strip()
            or not isinstance(request.target, str)
            or not request.target.strip()
            or len(request.target) > 255
            or len(request.category) > 32
            or not isinstance(request.details, dict)
            or not isinstance(request.authorization, dict)
            or (
                request.assessment_id is not None
                and (
                    not isinstance(request.assessment_id, str)
                    or not request.assessment_id
                    or len(request.assessment_id) > 128
                )
            )
        ):
            self.audit_logger.log('assessment_blocked', {
                'assessment_id': assessment_id,
                'reason': 'Assessment request fields are invalid.',
            })
            return {
                'assessment_id': assessment_id,
                'category': request.category if isinstance(request.category, str) else '',
                'target': request.target if isinstance(request.target, str) else '',
                'status': 'blocked',
                'reason': 'Assessment request fields are invalid.',
                'agent': None,
                'plan': [
                    {'step': 'request validation', 'status': 'blocked'},
                    {'step': 'authorization validation', 'status': 'not run'},
                    {'step': 'scope validation', 'status': 'not run'},
                    {'step': 'tool execution', 'status': 'not run'},
                ],
            }
        normalized_target = normalize_target(request.target)
        risk_checks = self.authorization_policy.validate_authorization(
            category=request.category,
            target=normalized_target,
            authorization=request.authorization,
            details=request.details,
        )
        approved = risk_checks['authorized']
        if not approved:
            self.audit_logger.log('assessment_blocked', {
                'assessment_id': assessment_id,
                'category': request.category,
                'target': normalized_target,
                'reason': risk_checks['reason'],
            })
            return {
                'assessment_id': assessment_id, 'category': request.category,
                'target': normalized_target, 'status': 'blocked',
                'reason': risk_checks['reason'], 'agent': None,
                'plan': [
                    {'step': 'authorization validation', 'status': 'blocked'},
                    {'step': 'scope validation', 'status': 'not run'},
                    {'step': 'tool execution', 'status': 'not run'},
                ],
            }

        scope_status = self.scope_validator.validate_scope(
            request.category, normalized_target, request.details, request.authorization
        )
        if not scope_status:
            self.audit_logger.log('assessment_blocked', {
                'assessment_id': assessment_id,
                'category': request.category,
                'target': normalized_target,
                'reason': 'Target scope validation failed.',
            })
            return {
                'assessment_id': assessment_id, 'category': request.category,
                'target': normalized_target, 'status': 'blocked',
                'reason': 'Target scope validation failed.',
                'agent': None,
                'plan': [
                    {'step': 'authorization validation', 'status': 'passed'},
                    {'step': 'scope validation', 'status': 'blocked'},
                    {'step': 'tool execution', 'status': 'not run'},
                ],
            }

        agent_name = self._select_agent(request.category)
        plan = [
            {'step': 'authorization validation', 'status': 'passed'},
            {'step': 'scope validation', 'status': 'passed'},
            {'step': 'authorized tool selection', 'status': 'ready'},
            {'step': 'finding normalization', 'status': 'ready'},
        ]

        self.audit_logger.log('assessment_authorized', {
            'assessment_id': assessment_id,
            'category': request.category,
            'target': normalized_target,
            'operation': request.details.get('operation', 'review'),
        })
        return {
            'assessment_id': assessment_id, 'category': request.category,
            'target': normalized_target, 'status': 'ready',
            'reason': 'Authorization and scope validation passed.',
            'agent': agent_name, 'plan': plan,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }

    def execute_assessment(self, request: AssessmentRequest) -> Dict[str, Any]:
        from workflows.assessment_graph import run_assessment

        return run_assessment(request, orchestrator=self)

    def execute_planned_assessment(
        self, request: AssessmentRequest, plan: Dict[str, Any]
    ) -> Dict[str, Any]:
        if (
            plan.get('status') != 'ready'
            or not isinstance(request.category, str)
            or not isinstance(request.target, str)
            or plan.get('target') != normalize_target(request.target)
        ):
            return {
                **plan,
                'status': 'blocked',
                'findings': [],
                'summary': 'Assessment blocked because its validated plan is missing or does not match the request.',
            }

        authorization = self.authorization_policy.validate_authorization(
            request.category, normalize_target(request.target), request.authorization, request.details
        )
        in_scope = authorization['authorized'] and self.scope_validator.validate_scope(
            request.category,
            normalize_target(request.target),
            request.details,
            request.authorization,
        )
        if not in_scope:
            self.audit_logger.log('assessment_blocked', {
                'assessment_id': plan.get('assessment_id'),
                'category': request.category,
                'target': request.target,
                'reason': 'Authorization or scope changed before execution.',
            })
            return {
                **plan,
                'status': 'blocked',
                'findings': [],
                'summary': 'Assessment blocked because authorization or scope did not pass execution-time validation.',
            }

        if not request.assessment_id:
            request.assessment_id = plan['assessment_id']
        category = request.category.lower()
        if category == 'wifi':
            from agents.wifi_agent import WirelessSecurityAgent
            output = WirelessSecurityAgent(
                authorization_policy=self.authorization_policy,
                scope_validator=self.scope_validator,
            ).execute(request)
        elif category in {'website', 'network', 'infrastructure'}:
            from agents.infrastructure_agent import InfrastructureAgent
            output = InfrastructureAgent(
                authorization_policy=self.authorization_policy,
                scope_validator=self.scope_validator,
            ).execute(request)
        else:
            output = {
                'status': 'blocked',
                'findings': [],
                'summary': 'No specialized handler is registered for this category.',
            }

        status = output.get('status', 'failed')
        normalized = {
            'assessment_id': plan['assessment_id'],
            'category': request.category,
            'target': plan['target'],
            'status': 'completed' if status == 'completed' else status,
            'agent': plan['agent'],
            'plan': plan['plan'],
            'findings': output.get('findings', []),
            'summary': output.get('summary', 'Assessment did not complete successfully.'),
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        for field in ('networks', 'report', 'password_audit', 'credential', 'ai_commentary', 'llm_status'):
            if field in output:
                normalized[field] = output[field]
        self.audit_logger.log('assessment_execution', {
            'assessment_id': plan['assessment_id'],
            'category': request.category,
            'target': plan['target'],
            'status': normalized['status'],
            'finding_count': len(normalized['findings']),
        })
        return normalized

    @staticmethod
    def _select_agent(category: str) -> str:
        category_map = {'wifi': 'WirelessSecurityAgent', 'website': 'WebsiteAndNetworkAgent', 'network': 'WebsiteAndNetworkAgent', 'infrastructure': 'WebsiteAndNetworkAgent'}
        return category_map.get(category.lower(), 'MasterOrchestrator')
