from security.audit_logger import AuditLogger
from agents.orchestrator import AssessmentRequest, MasterOrchestrator
from agents.wifi_training import run_wifi_recovery_training


def _orchestrator(tmp_path) -> MasterOrchestrator:
    return MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl')))


def test_master_orchestrator_generates_plan(tmp_path) -> None:
    orchestrator = _orchestrator(tmp_path)
    request = AssessmentRequest(category='wifi', target='LabWiFi-Alpha', authorization={'authorized': True}, details={'ssid': 'LabWiFi-Alpha', 'lab_mode': True})
    plan = orchestrator.plan_assessment(request)
    assert plan['status'] == 'ready'
    assert plan['agent'] == 'WirelessSecurityAgent'

def test_execute_assessment_completes_wifi_configuration_analysis(tmp_path) -> None:
    orchestrator = _orchestrator(tmp_path)
    request = AssessmentRequest(category='wifi', target='LabWiFi-Alpha', authorization={'authorized': True}, details={'ssid': 'LabWiFi-Alpha', 'lab_mode': True})
    result = orchestrator.execute_assessment(request)
    assert result['status'] == 'completed'
    assert len(result['findings']) >= 1

def test_wifi_training_only_discloses_a_planted_mock_credential() -> None:
    result = run_wifi_recovery_training('  Training-Network  ')

    assert result['status'] == 'simulated'
    assert 'Training-Network' in result['agents'][0]['result']
    assert 'SSID alone does not reveal a real Wi-Fi password' in result['summary']
    assert result['simulated_credential'] == 'DEMO_ONLY_NOT_A_WIFI_PASSWORD_123'
    assert result['simulated_credential'] in result['agents'][2]['result']
    assert 'not derived from the SSID' in result['agents'][2]['result']
    assert result['agents'][3]['agent'] == 'Safety Auditor'

def test_wifi_training_rejects_empty_ssid() -> None:
    try:
        run_wifi_recovery_training('  ')
    except ValueError as exc:
        assert 'Enter an SSID' in str(exc)
    else:
        raise AssertionError('Expected empty SSID to be rejected')
