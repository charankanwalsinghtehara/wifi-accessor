from __future__ import annotations

import uuid
from typing import Any

from agents.llm import LLMUnavailableError, assessment_commentary
from agents.password_audit_agent import PasswordAuditAgent
from agents.reporting_agent import ReportingAgent
from agents.saved_wifi_agent import SavedWifiRecoveryAgent
from agents.wifi_security_analysis_agent import WifiSecurityAnalysisAgent
from networking.linux_wifi import LinuxWifiProvider
from security.authorization import AuthorizationPolicy
from security.scope_validator import ScopeValidator


class WirelessSecurityAgent:
    def __init__(
        self,
        authorization_policy: AuthorizationPolicy | None = None,
        scope_validator: ScopeValidator | None = None,
        wifi_provider: LinuxWifiProvider | None = None,
    ) -> None:
        self.authorization_policy = authorization_policy or AuthorizationPolicy()
        self.scope_validator = scope_validator or ScopeValidator()
        self.wifi_provider = wifi_provider or LinuxWifiProvider()
        self.security_agent = WifiSecurityAnalysisAgent()
        self.password_agent = PasswordAuditAgent()
        self.recovery_agent = SavedWifiRecoveryAgent(provider=self.wifi_provider)
        self.reporting_agent = ReportingAgent()

    def execute(self, request: Any) -> dict[str, Any]:
        target = request.target
        details = request.details
        operation = details.get('operation', 'review')
        authorization = request.authorization
        decision = self.authorization_policy.validate_authorization(
            'wifi', target, authorization, details
        )
        if not decision['authorized'] or not self.scope_validator.validate_scope(
            'wifi', target, details, authorization
        ):
            return {
                'status': 'blocked',
                'summary': 'Wi-Fi assessment blocked because authorization or target scope was not validated.',
                'findings': [],
            }

        networks: list[dict[str, Any]] = []
        findings: list[dict[str, Any]] = []
        summary = ''
        credential: str | None = None
        password_audit: dict[str, Any] | None = None

        if operation == 'discover':
            discovered = self.wifi_provider.discover(details['interface'])
            networks = [network.to_dict() for network in discovered]
            for network in networks:
                findings.extend(self.security_agent.analyze(network))
            summary = f'Discovered {len(networks)} nearby wireless network(s) using local Linux metadata.'
        elif operation == 'password_audit':
            password_audit = self.password_agent.evaluate(
                details.get('password', ''), str(details.get('ssid', ''))
            )
            severity = {'Strong': 'Informational', 'Moderate': 'Medium', 'Weak': 'High'}[
                password_audit['rating']
            ]
            findings.append({
                'title': 'Owner-supplied Wi-Fi passphrase strength',
                'severity': severity,
                'status': 'Locally audited',
                'description': f"Strength rating: {password_audit['rating']}.",
                'affected_asset': target,
                'evidence': (
                    f"Length: {password_audit['length']} characters; "
                    f"character classes: {password_audit['character_classes']}; "
                    f"issues: {len(password_audit['issues'])}. The passphrase itself is not recorded."
                ),
                'confidence': 'Medium',
                'remediation': ' '.join(password_audit['recommendations']),
            })
            summary = f"Local passphrase audit rating: {password_audit['rating']}."
        elif operation == 'recover_saved_password':
            recovered = self.recovery_agent.recover(
                details['connection_uuid'], details.get('confirm_recovery') is True
            )
            credential = recovered['password']
            summary = 'Retrieved a saved passphrase through the current user’s authorized NetworkManager profile.'
            networks = [{'connection_name': recovered['connection_name']}]
        else:
            network = {
                'ssid': str(details.get('ssid', target)),
                'bssid': str(details.get('bssid') or ''),
                'security': str(details.get('security') or details.get('security_mode') or 'Unknown'),
                'channel': details.get('channel'),
                'frequency_mhz': details.get('frequency_mhz'),
                'signal_percent': details.get('signal_percent'),
                'wps_exposed': details.get('wps_exposed'),
            }
            networks = [network]
            findings = self.security_agent.analyze(network)
            summary = f'Completed a local security configuration analysis for {network["ssid"]}.'

        assessment_id = request.assessment_id or str(uuid.uuid4())
        report_networks = networks
        if operation == 'password_audit':
            report_networks = [{'ssid': target, 'audit_metrics': {
                'rating': password_audit['rating'] if password_audit else 'Unknown',
                'length': password_audit['length'] if password_audit else 0,
                'issues': password_audit['issues'] if password_audit else [],
            }}]
        report = self.reporting_agent.build_report(
            assessment_id=assessment_id,
            scope=target,
            findings=findings,
            network_metadata={'networks': report_networks, 'operation': operation},
            summary=summary,
            sensitive_values=(
                details.get('password', ''),
                credential or '',
            ),
        )
        result: dict[str, Any] = {
            'status': 'completed',
            'summary': summary,
            'findings': findings,
            'networks': networks,
            'report': report,
        }
        if password_audit is not None:
            result['password_audit'] = password_audit
        if credential is not None:
            result['credential'] = credential

        if operation not in {'password_audit', 'recover_saved_password'}:
            try:
                commentary = assessment_commentary(findings)
            except LLMUnavailableError:
                result['llm_status'] = 'unavailable; deterministic assessment completed'
            else:
                if commentary:
                    result['ai_commentary'] = commentary
                    result['llm_status'] = 'optional commentary; findings remain evidence-based'
        return result
