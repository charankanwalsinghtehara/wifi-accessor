from security.audit_logger import AuditLogger
from agents.orchestrator import AssessmentRequest, MasterOrchestrator


def _orchestrator(tmp_path) -> MasterOrchestrator:
    return MasterOrchestrator(audit_logger=AuditLogger(str(tmp_path / 'audit.jsonl')))


def test_authorization_rejected_without_approval(tmp_path) -> None:
    orchestrator = _orchestrator(tmp_path)
    request = AssessmentRequest(category='website', target='example.com', authorization={'authorized': False}, details={})
    result = orchestrator.plan_assessment(request)
    assert result['status'] == 'blocked'

def test_authorization_accepts_approved_domain(tmp_path) -> None:
    orchestrator = _orchestrator(tmp_path)
    request = AssessmentRequest(category='website', target='example.com', authorization={'authorized': True}, details={})
    result = orchestrator.plan_assessment(request)
    assert result['status'] == 'ready'
