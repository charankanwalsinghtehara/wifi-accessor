from __future__ import annotations

import streamlit as st

def render_agent_monitoring() -> None:
    st.title('Agent Monitoring')
    st.info('Master Orchestrator and specialist agents operate in safe, allowlisted demo mode.')
    st.dataframe([{'Agent': 'Master Orchestrator', 'Status': 'Operational', 'Execution count': 24, 'Last event': 'Assessment approved'}, {'Agent': 'Wireless Security Agent', 'Status': 'Standby', 'Execution count': 7, 'Last event': 'Lab scope validation'}, {'Agent': 'Website & Network Agent', 'Status': 'Operational', 'Execution count': 12, 'Last event': 'Safe reconnaissance'}], use_container_width=True)
