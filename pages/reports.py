from __future__ import annotations

import streamlit as st


def render_reports() -> None:
    st.title('Reports')
    result = st.session_state.get('wifi_latest_result') or st.session_state.get('wifi_discovery_result')
    if not result or not result.get('report'):
        st.info('Run an authorized Wi-Fi assessment to create a report.')
        return
    report = result['report']
    st.subheader(result.get('summary', 'Wi-Fi assessment report'))
    st.json(report['data'])
    first, second = st.columns(2)
    first.download_button(
        'Download JSON report',
        data=report['json'],
        file_name=f"cybersentinel-{result['assessment_id']}.json",
        mime='application/json',
    )
    second.download_button(
        'Download HTML report',
        data=report['html'],
        file_name=f"cybersentinel-{result['assessment_id']}.html",
        mime='text/html',
    )
