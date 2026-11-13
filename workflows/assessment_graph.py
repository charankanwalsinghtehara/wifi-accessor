from __future__ import annotations

from typing import Any, TypedDict

from langgraph.graph import END, StateGraph

from agents.orchestrator import AssessmentRequest, MasterOrchestrator


class AssessmentState(TypedDict, total=False):
    request: AssessmentRequest
    plan: dict[str, Any]
    result: dict[str, Any]
    validation_error: str


def validate_request(state: AssessmentState) -> dict[str, Any]:
    request = state.get('request')
    if not isinstance(request, AssessmentRequest):
        return {'validation_error': 'A valid structured assessment request is required.'}
    if (
        not isinstance(request.category, str)
        or not request.category.strip()
        or not isinstance(request.target, str)
        or not request.target.strip()
        or not isinstance(request.details, dict)
        or not isinstance(request.authorization, dict)
    ):
        return {'validation_error': 'Category, target, and structured assessment details are required.'}
    return {}


def select_agent(state: AssessmentState, orchestrator: MasterOrchestrator) -> dict[str, Any]:
    if state.get('validation_error'):
        return {}
    return {'plan': orchestrator.plan_assessment(state['request'])}


def execute_agent(state: AssessmentState, orchestrator: MasterOrchestrator) -> dict[str, Any]:
    return {'result': orchestrator.execute_planned_assessment(state['request'], state['plan'])}


def finalize_blocked(state: AssessmentState) -> dict[str, Any]:
    plan = state.get('plan', {})
    request = state.get('request')
    return {'result': {
        **plan,
        'status': 'blocked',
        'category': request.category if isinstance(request, AssessmentRequest) else '',
        'target': request.target if isinstance(request, AssessmentRequest) else '',
        'findings': [],
        'summary': state.get('validation_error') or plan.get(
            'reason', 'Assessment blocked by authorization or scope policy.'
        ),
    }}


def build_assessment_graph(orchestrator: MasterOrchestrator | None = None) -> StateGraph:
    active_orchestrator = orchestrator or MasterOrchestrator()
    workflow = StateGraph(AssessmentState)
    workflow.add_node('validate_request', validate_request)
    workflow.add_node('select_agent', lambda state: select_agent(state, active_orchestrator))
    workflow.add_node('execute_agent', lambda state: execute_agent(state, active_orchestrator))
    workflow.add_node('finalize_blocked', finalize_blocked)
    workflow.set_entry_point('validate_request')
    workflow.add_edge('validate_request', 'select_agent')
    workflow.add_conditional_edges(
        'select_agent',
        lambda state: 'finalize_blocked' if state.get('validation_error') or state.get('plan', {}).get('status') != 'ready' else 'execute_agent',
        {'finalize_blocked': 'finalize_blocked', 'execute_agent': 'execute_agent'},
    )
    workflow.add_edge('execute_agent', END)
    workflow.add_edge('finalize_blocked', END)
    return workflow


def run_assessment(
    request: AssessmentRequest, orchestrator: MasterOrchestrator | None = None
) -> dict[str, Any]:
    workflow = build_assessment_graph(orchestrator)
    app = workflow.compile()
    result = app.invoke({'request': request})
    return result.get(
        'result',
        {'status': 'failed', 'summary': 'Assessment workflow did not produce a result.', 'findings': []},
    )
