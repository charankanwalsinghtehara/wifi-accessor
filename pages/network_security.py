from __future__ import annotations

import streamlit as st

from agents.orchestrator import AssessmentRequest, MasterOrchestrator

def render_network_security() -> None:
    st.title('Network Security')
    target = st.text_input('Authorized IP or CIDR', value='10.0.0.0/24')
    approved = st.checkbox('I have explicit authorization for this target', value=False)
    port_scan = st.checkbox('Approved host discovery and port scan', value=False)
    lab_only = st.checkbox('Restrict testing to isolated lab targets', value=True)

    if st.button('Run approved network assessment'):
        request = AssessmentRequest(category='network', target=target, authorization={'authorized': approved}, details={'approved': approved, 'port_scan': port_scan, 'lab_mode': lab_only})
        result = MasterOrchestrator().execute_assessment(request)
        st.session_state['latest_assessment'] = result
        if result.get('status') == 'blocked':
            st.error(result.get('summary', 'Network assessment blocked by authorization policy.'))
        elif result.get('status') == 'completed':
            st.success(result.get('summary', 'Network assessment complete.'))
        else:
            st.warning(result.get('summary', 'Network assessment did not complete successfully.'))
        if result.get('findings'):
            st.dataframe(result['findings'], use_container_width=True)
