from __future__ import annotations

import streamlit as st
import plotly.express as px

def render_dashboard() -> None:
    st.title('Executive Dashboard')
    col1, col2, col3, col4 = st.columns(4)
    col1.metric('Overall security score', '82/100')
    col2.metric('Total assessments', '128')
    col3.metric('Critical findings', '3')
    col4.metric('Low findings', '18')

    chart_data = {'Severity': ['Critical', 'High', 'Medium', 'Low', 'Informational'], 'Findings': [3, 9, 22, 18, 34]}
    st.plotly_chart(px.bar(chart_data, x='Severity', y='Findings', color='Severity', title='Risk distribution'), use_container_width=True)

    st.subheader('Recent assessments')
    st.dataframe([{'Timestamp': '2026-11-09 10:30', 'Target': 'example.com', 'Category': 'Website', 'Status': 'Complete'}, {'Timestamp': '2026-11-09 09:50', 'Target': '10.0.0.0/24', 'Category': 'Network', 'Status': 'Complete'}, {'Timestamp': '2026-11-09 08:45', 'Target': 'LabWiFi-Alpha', 'Category': 'Wi-Fi', 'Status': 'Simulated'}], use_container_width=True)

    st.subheader('Agent activity')
    st.dataframe([{'Agent': 'Master Orchestrator', 'Status': 'Operational', 'Last update': '2 min ago'}, {'Agent': 'Wireless Security Agent', 'Status': 'Standby', 'Last update': '9 min ago'}, {'Agent': 'Website & Network Agent', 'Status': 'Operational', 'Last update': '3 min ago'}], use_container_width=True)
