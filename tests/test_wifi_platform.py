from __future__ import annotations

import getpass
import json
import subprocess

import pytest

from agents.orchestrator import AssessmentRequest, MasterOrchestrator
from agents.password_audit_agent import PasswordAuditAgent
from agents.reporting_agent import ReportingAgent
from agents.saved_wifi_agent import SavedWifiRecoveryAgent
from networking.linux_wifi import (
    LinuxWifiProvider,
    WifiDiscoveryError,
    WifiNetwork,
    classify_security,
    parse_iw_scan,
    parse_nmcli_networks,
    split_nmcli_row,
)
from security.audit_logger import AuditLogger
from security.execution_policy import ExecutionPolicy
from security.scope_validator import ScopeValidator
from utils.secrets import redact_secrets
from workflows.assessment_graph import run_assessment


def test_nmcli_parser_handles_escaped_ssid_and_bssid() -> None:
    output = r'Office\:Lab:AA\:BB\:CC\:DD\:EE\:FF:6:2437:82:WPA2' + '\n'
    networks = parse_nmcli_networks(output)

    assert len(networks) == 1
    assert networks[0].ssid == 'Office:Lab'
    assert networks[0].bssid == 'AA:BB:CC:DD:EE:FF'
    assert networks[0].channel == 6
    assert networks[0].signal_percent == 82
    assert networks[0].security == 'WPA2'
    assert split_nmcli_row(r'one\:two:three') == ['one:two', 'three']


@pytest.mark.parametrize(
    ('value', 'expected'),
    [
        ('', 'Open'),
        ('--', 'Open'),
        ('WEP', 'WEP'),
        ('WPA', 'WPA'),
        ('WPA WPA2', 'WPA/WPA2'),
        ('WPA2 802.1X', 'WPA2'),
        ('WPA3 SAE', 'WPA3'),
        ('WPA2 WPA3 SAE PSK', 'WPA2/WPA3'),
    ],
)
def test_classifies_wifi_security(value: str, expected: str) -> None:
    assert classify_security(value) == expected


def test_iw_scan_parser_extracts_signal_security_and_wps() -> None:
    output = '''BSS aa:bb:cc:dd:ee:ff(on wlan0)
        freq: 5180
        signal: -48.00 dBm
        SSID: Sample
        RSN:
            Authentication suites: SAE PSK
        WPS: Version 1.0
'''
    networks = parse_iw_scan(output)

    assert len(networks) == 1
    assert networks[0].security == 'WPA2/WPA3'
    assert networks[0].channel == 36
    assert networks[0].signal_percent == 100
    assert networks[0].wps_exposed is True


def test_linux_provider_uses_mocked_networkmanager_output(tmp_path, monkeypatch) -> None:
    wireless = tmp_path / 'wlan0' / 'wireless'
    wireless.mkdir(parents=True)

    def fake_which(name: str) -> str | None:
        return f'/usr/bin/{name}' if name == 'nmcli' else None

    def fake_runner(executable: str, args: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        if args[-2:] == ['device', 'status']:
            return subprocess.CompletedProcess(args, 0, 'wlan0:wifi\n', '')
        if 'wifi' in args and 'list' in args:
            return subprocess.CompletedProcess(
                args, 0,
                r'Lab\:Network:AA\:BB\:CC\:DD\:EE\:FF:11:2462:91:WPA3' + '\n',
                '',
            )
        raise AssertionError(f'Unexpected allowlisted command: {executable} {args}')

    monkeypatch.setattr('networking.linux_wifi.platform.system', lambda: 'Linux')
    monkeypatch.setattr('networking.linux_wifi.shutil.which', fake_which)
    provider = LinuxWifiProvider(sysfs_root=tmp_path, command_runner=fake_runner)

    networks = provider.discover('wlan0')
    assert networks[0].ssid == 'Lab:Network'
    assert networks[0].security == 'WPA3'
    assert networks[0].channel == 11


def test_linux_provider_reports_permission_failure_without_shell_fallback(tmp_path, monkeypatch) -> None:
    wireless = tmp_path / 'wlan0' / 'wireless'
    wireless.mkdir(parents=True)
    monkeypatch.setattr('networking.linux_wifi.platform.system', lambda: 'Linux')
    monkeypatch.setattr(
        'networking.linux_wifi.shutil.which',
        lambda name: '/usr/bin/nmcli' if name == 'nmcli' else None,
    )

    def denied(_executable: str, args: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        if args[-2:] == ['device', 'status']:
            return subprocess.CompletedProcess(args, 0, 'wlan0:wifi\n', '')
        return subprocess.CompletedProcess(args, 10, '', 'Error: Not authorized')

    provider = LinuxWifiProvider(sysfs_root=tmp_path, command_runner=denied)
    with pytest.raises(WifiDiscoveryError, match='denied'):
        provider.discover('wlan0')


def test_saved_profile_listing_uses_supported_metadata_and_excludes_other_users(monkeypatch) -> None:
    current_uuid = '00000000-0000-0000-0000-000000000001'
    system_uuid = '00000000-0000-0000-0000-000000000002'
    other_uuid = '00000000-0000-0000-0000-000000000003'
    profiles = (
        f'{current_uuid}:My Wi-Fi:802-11-wireless\n'
        f'{system_uuid}:Shared Wi-Fi:802-11-wireless\n'
        f'{other_uuid}:Other User Wi-Fi:802-11-wireless\n'
        '00000000-0000-0000-0000-000000000004:Wired:802-3-ethernet\n'
    )

    def fake_runner(_executable: str, args: list[str], **_kwargs) -> subprocess.CompletedProcess[str]:
        if args == ['--terse', '--escape', 'yes', '--fields', 'UUID,NAME,TYPE', 'connection', 'show']:
            return subprocess.CompletedProcess(args, 0, profiles, '')
        if args[-1] == current_uuid:
            return subprocess.CompletedProcess(args, 0, f'user:{getpass.getuser()}:\n', '')
        if args[-1] == system_uuid:
            return subprocess.CompletedProcess(args, 0, '\n', '')
        if args[-1] == other_uuid:
            return subprocess.CompletedProcess(args, 0, 'user:bob:\n', '')
        raise AssertionError(f'Unexpected command arguments: {args}')

    monkeypatch.setattr('networking.linux_wifi.platform.system', lambda: 'Linux')
    monkeypatch.setattr('networking.linux_wifi.shutil.which', lambda _name: '/usr/bin/nmcli')
    provider = LinuxWifiProvider(command_runner=fake_runner)

    connections = provider.list_saved_wireless_connections()
    assert connections == [
        {'uuid': current_uuid, 'name': 'My Wi-Fi', 'access': 'Current user'},
        {
            'uuid': system_uuid,
            'name': 'Shared Wi-Fi',
            'access': 'All users (NetworkManager controlled)',
        },
    ]


def test_execution_policy_allows_only_fixed_wifi_command_shapes() -> None:
    policy = ExecutionPolicy()
    scan_args = [
        '--terse', '--escape', 'yes', '--fields',
        'SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY',
        'device', 'wifi', 'list', 'ifname', 'wlan0', '--rescan', 'yes',
    ]

    assert policy.validate_command('nmcli', scan_args)
    assert not policy.validate_command('nmcli', ['device', 'wifi', 'list', 'ifname', 'wlan0;id'])
    assert not policy.validate_command('iw', ['dev', 'wlan0', 'scan', ';', 'id'])
    assert not policy.is_allowed('sh')
    assert not policy.is_allowed('nmap')


def test_wifi_authorization_and_scope_fail_closed(tmp_path) -> None:
    orchestrator = MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl')))
    unauthorized = AssessmentRequest(
        category='wifi',
        target='wlan0',
        details={'operation': 'discover', 'interface': 'wlan0', 'scope_target': 'wlan0'},
    )
    mismatch = AssessmentRequest(
        category='wifi',
        target='wlan0',
        authorization={'authorized': True},
        details={'operation': 'discover', 'interface': 'wlan1', 'scope_target': 'wlan1'},
    )

    assert orchestrator.plan_assessment(unauthorized)['status'] == 'blocked'
    decision = orchestrator.plan_assessment(mismatch)
    assert decision['status'] == 'blocked'
    assert decision['plan'][1]['status'] == 'blocked'
    assert decision['plan'][2]['status'] == 'not run'


def test_wifi_scope_does_not_accept_free_form_authorization_text() -> None:
    validator = ScopeValidator()
    assert not validator.validate_scope(
        'wifi',
        'HomeNet',
        {'ssid': 'HomeNet', 'scope_target': 'HomeNet', 'notes': 'authorized lab'},
        {'authorized': False},
    )
    assert not validator.validate_scope(
        'wifi',
        'HomeNet',
        {'ssid': 'HomeNet', 'scope_target': 'HomeNet', 'bssid': 'not-a-bssid'},
        {'authorized': True},
    )


def test_scope_rejects_broader_cidr_than_allowed_range() -> None:
    validator = ScopeValidator()
    assert validator.validate_scope('network', '10.0.0.0/24', {}) is True
    assert validator.validate_scope('network', '10.0.0.0/8', {}) is False
    assert validator.validate_scope('website', 'evil-example.com', {}) is False


def test_scope_handles_cross_family_and_invalid_cidr_configuration() -> None:
    validator = ScopeValidator()
    validator.allowed_cidrs = ['not-a-network', '10.0.0.0/24']
    assert validator.is_allowed_cidr('2001:db8::/64') is False
    assert validator.validate_scope('network', '2001:db8::1', {}) is False


def test_password_audit_never_returns_or_logs_plaintext() -> None:
    secret = 'Correct-Horse-Battery-8'
    result = PasswordAuditAgent().evaluate(secret, 'HomeNet')

    assert result['rating'] == 'Strong'
    assert secret not in repr(result)
    assert result['length'] == len(secret)


def test_secret_redaction_handles_keys_and_inline_values(tmp_path) -> None:
    payload = {
        'password': 'sensitive-value',
        'nested': {'message': 'psk=sensitive-value and token:abc123'},
        'safe': 'ordinary event',
    }
    redacted = redact_secrets(payload)
    assert 'sensitive-value' not in json.dumps(redacted)
    assert '[REDACTED]' in json.dumps(redacted)

    logger = AuditLogger(str(tmp_path / 'audit.jsonl'))
    logger.log('test', payload)
    assert 'sensitive-value' not in (tmp_path / 'audit.jsonl').read_text(encoding='utf-8')


class _FakeWifiProvider:
    def discover(self, _interface: str) -> list[WifiNetwork]:
        return [WifiNetwork('TestNet', 'AA:BB:CC:DD:EE:FF', 1, 2412, 75, 'WPA2')]


def test_langgraph_executes_authorized_discovery_with_mock_provider(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr('agents.wifi_agent.LinuxWifiProvider', lambda: _FakeWifiProvider())
    request = AssessmentRequest(
        category='wifi',
        target='wlan0',
        authorization={'authorized': True},
        details={'operation': 'discover', 'interface': 'wlan0', 'scope_target': 'wlan0'},
    )

    result = run_assessment(
        request,
        MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl'))),
    )
    assert result['status'] == 'completed'
    assert result['networks'][0]['ssid'] == 'TestNet'
    assert result['findings']
    assert result['report']['data']['scope'] == 'wlan0'
    assert result['report']['data']['assessment_id'] == result['assessment_id']


def test_langgraph_does_not_run_tools_when_authorization_fails(tmp_path, monkeypatch) -> None:
    def forbidden_provider():
        raise AssertionError('The Wi-Fi provider must not be constructed for a blocked request.')

    monkeypatch.setattr('agents.wifi_agent.LinuxWifiProvider', forbidden_provider)
    request = AssessmentRequest(
        category='wifi',
        target='wlan0',
        authorization={'authorized': False},
        details={'operation': 'discover', 'interface': 'wlan0', 'scope_target': 'wlan0'},
    )
    result = run_assessment(
        request,
        MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl'))),
    )

    assert result['status'] == 'blocked'
    assert result['findings'] == []


def test_langgraph_blocks_malformed_request_without_tool_execution(tmp_path, monkeypatch) -> None:
    def forbidden_provider():
        raise AssertionError('Malformed requests must not construct or invoke an agent.')

    monkeypatch.setattr('agents.wifi_agent.LinuxWifiProvider', forbidden_provider)
    result = run_assessment(
        None,
        MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl'))),
    )

    assert result['status'] == 'blocked'
    assert result['findings'] == []


def test_saved_password_requires_confirmation_and_profile_scope() -> None:
    class FakeProvider:
        def list_saved_wireless_connections(self) -> list[dict[str, str]]:
            return [{'uuid': '00000000-0000-0000-0000-000000000001', 'name': 'Mine'}]

    class ForbiddenPolicy:
        def run(self, *_args, **_kwargs):
            raise AssertionError('No command should run without the confirmation check.')

    agent = SavedWifiRecoveryAgent(provider=FakeProvider(), policy=ForbiddenPolicy())
    with pytest.raises(PermissionError, match='confirmation'):
        agent.recover('00000000-0000-0000-0000-000000000001', confirm=False)
    with pytest.raises(ValueError, match='belonging to this user'):
        agent.recover('00000000-0000-0000-0000-000000000002', confirm=True)


def test_saved_password_recovery_uses_user_scoped_profile_and_os_permissions(monkeypatch) -> None:
    uuid = '00000000-0000-0000-0000-000000000001'
    secret = 'synthetic-only-test-key'

    class FakeProvider:
        def list_saved_wireless_connections(self) -> list[dict[str, str]]:
            return [{'uuid': uuid, 'name': 'My Router'}]

    class FakePolicy:
        def run(self, executable: str, args: list[str]):
            assert executable == 'nmcli'
            assert uuid in args
            return subprocess.CompletedProcess(args, 0, secret + '\n', '')

    monkeypatch.setattr('agents.saved_wifi_agent.platform.system', lambda: 'Linux')
    monkeypatch.setattr('agents.saved_wifi_agent.os.path.exists', lambda _path: True)
    monkeypatch.setattr('agents.saved_wifi_agent.os.geteuid', lambda: 1000)
    result = SavedWifiRecoveryAgent(provider=FakeProvider(), policy=FakePolicy()).recover(uuid, True)

    assert result['connection_name'] == 'My Router'
    assert result['password'] == secret


def test_report_contains_json_and_escaped_html_without_secrets() -> None:
    report = ReportingAgent().build_report(
        'assessment-1',
        'TestNet',
        [{'title': '<script>alert(1)</script>', 'severity': 'High', 'description': 'Review config'}],
        {'ssid': 'TestNet'},
        'contains-secret',
        sensitive_values=['contains-secret'],
    )

    assert 'contains-secret' not in report['json']
    assert 'contains-secret' not in report['html']
    assert '<script>' not in report['html']
    assert '&lt;script&gt;' in report['html']
    assert 'Review config' in report['html']
    assert json.loads(report['json'])['scope'] == 'TestNet'


def test_workflow_surfaces_discovery_errors(tmp_path, monkeypatch) -> None:
    class BrokenProvider:
        def discover(self, _interface: str) -> list[WifiNetwork]:
            raise WifiDiscoveryError('No supported Wi-Fi discovery utility is installed.')

    monkeypatch.setattr('agents.wifi_agent.LinuxWifiProvider', lambda: BrokenProvider())
    request = AssessmentRequest(
        category='wifi',
        target='wlan0',
        authorization={'authorized': True},
        details={'operation': 'discover', 'interface': 'wlan0', 'scope_target': 'wlan0'},
    )
    with pytest.raises(WifiDiscoveryError, match='No supported'):
        run_assessment(
            request,
            MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl'))),
        )


def test_execution_revalidates_plan_before_agent_creation(tmp_path, monkeypatch) -> None:
    def forbidden_provider():
        raise AssertionError('A forged ready plan must not reach agent construction.')

    monkeypatch.setattr('agents.wifi_agent.LinuxWifiProvider', forbidden_provider)
    request = AssessmentRequest(
        category='wifi',
        target='wlan0',
        authorization={'authorized': False},
        details={'operation': 'discover', 'interface': 'wlan0', 'scope_target': 'wlan0'},
    )
    result = MasterOrchestrator(
        audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl'))
    ).execute_planned_assessment(
        request,
        {'status': 'ready', 'target': 'wlan0', 'assessment_id': 'assessment-1', 'agent': 'Wi-Fi'},
    )

    assert result['status'] == 'blocked'
