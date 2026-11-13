from __future__ import annotations

from typing import Any

import streamlit as st

from agents.orchestrator import AssessmentRequest
from agents.saved_wifi_agent import SavedWifiRecoveryAgent
from agents.wifi_training import run_wifi_recovery_training
from database.db import AssessmentDatabase
from networking.linux_wifi import LinuxWifiProvider, WifiDiscoveryError
from workflows.assessment_graph import run_assessment


def _assessment_database() -> AssessmentDatabase:
    return AssessmentDatabase()


def _render_findings(result: dict[str, Any]) -> None:
    if result.get('findings'):
        st.dataframe(result['findings'], use_container_width=True, hide_index=True)
    if result.get('password_audit'):
        audit = result['password_audit']
        left, middle, right = st.columns(3)
        left.metric('Passphrase rating', audit['rating'])
        middle.metric('Characters', audit['length'])
        right.metric('Character classes', audit['character_classes'])
        if audit['issues']:
            st.warning('\n'.join(f'• {issue}' for issue in audit['issues']))
        for recommendation in audit['recommendations']:
            st.markdown(f'- {recommendation}')
    if result.get('ai_commentary'):
        st.info(f"Optional AI commentary (not a finding): {result['ai_commentary']}")
    if result.get('llm_status'):
        st.caption(f"LLM: {result['llm_status']}")


def _render_report_downloads(result: dict[str, Any]) -> None:
    report = result.get('report')
    if not report:
        return
    first, second = st.columns(2)
    first.download_button(
        'Download JSON report',
        data=report['json'],
        file_name=f"cybersentinel-{result['assessment_id']}.json",
        mime='application/json',
        key=f"json-{result['assessment_id']}",
    )
    second.download_button(
        'Download HTML report',
        data=report['html'],
        file_name=f"cybersentinel-{result['assessment_id']}.html",
        mime='text/html',
        key=f"html-{result['assessment_id']}",
    )


def _save_assessment(result: dict[str, Any]) -> None:
    _assessment_database().save_assessment({
        'assessment_id': result['assessment_id'],
        'category': result['category'],
        'target': result['target'],
        'agent': result.get('agent'),
        'status': result['status'],
        'summary': result.get('summary', ''),
        'findings': result.get('findings', []),
    })


def _execute_wifi_request(
    target: str,
    operation: str,
    details: dict[str, Any],
    authorized: bool,
) -> dict[str, Any]:
    request = AssessmentRequest(
        category='wifi',
        target=target,
        authorization={'authorized': authorized},
        details={**details, 'operation': operation, 'scope_target': target},
    )
    result = run_assessment(request)
    if result.get('status') == 'completed':
        _save_assessment(result)
    return result


def _password_audit_callback() -> None:
    password = st.session_state.get('wifi_owner_password', '')
    st.session_state.pop('wifi_password_audit_result', None)
    try:
        result = _execute_wifi_request(
            st.session_state.get('wifi_audit_ssid', ''),
            'password_audit',
            {
                'ssid': st.session_state.get('wifi_audit_ssid', ''),
                'password': password,
                'lab_mode': True,
            },
            st.session_state.get('wifi_password_authorized') is True,
        )
    except (ValueError, PermissionError, WifiDiscoveryError) as exc:
        st.session_state['wifi_password_audit_error'] = str(exc)
    else:
        if result.get('status') == 'completed':
            st.session_state['wifi_password_audit_error'] = ''
            st.session_state['wifi_password_audit_result'] = result
        else:
            st.session_state['wifi_password_audit_error'] = result.get(
                'summary', 'Passphrase audit was blocked by authorization or scope policy.'
            )
    finally:
        st.session_state['wifi_owner_password'] = ''


def render_wifi_security() -> None:
    st.title('Wi-Fi Security Assessment')
    st.markdown(
        'Local Linux discovery and defensive configuration review. No monitor mode, packet capture, '
        'password guessing, WPS probing, or arbitrary shell commands are used.'
    )
    st.markdown(
        '<style>.wifi-card{padding:1rem;border:1px solid #293849;border-radius:12px;background:#111b26}'
        '.wifi-muted{color:#93a4b8}</style>',
        unsafe_allow_html=True,
    )

    authorized = st.checkbox(
        'I am authorized to assess the selected network or this local wireless adapter.',
        value=False,
        key='wifi_assessment_authorized',
    )
    provider = LinuxWifiProvider()
    if authorized:
        try:
            environment = provider.environment()
        except WifiDiscoveryError as exc:
            st.error(str(exc))
            environment = {'platform': 'Unknown', 'distribution': 'Unavailable', 'utilities': [], 'interfaces': []}
    else:
        environment = {'platform': 'Linux', 'distribution': 'Authorization required', 'utilities': [], 'interfaces': []}

    col1, col2, col3 = st.columns(3)
    col1.metric('Operating system', environment['platform'])
    col2.metric('Distribution', environment['distribution'])
    col3.metric('Wireless interfaces', len(environment['interfaces']))
    st.caption(
        'Available utilities: '
        + (', '.join(environment['utilities']) if environment['utilities'] else 'not queried')
    )
    if not authorized:
        st.info('Confirm authorization above to enumerate wireless adapters and enable assessment actions.')

    discovery_tab, password_tab, saved_tab, history_tab, training_tab = st.tabs(
        ['Discovery & review', 'Password audit', 'Saved profiles', 'Assessment history', 'Training']
    )

    with discovery_tab:
        interface_names = [item['name'] for item in environment['interfaces']]
        if not interface_names:
            st.info('No supported wireless interface was detected. Ordinary discovery does not require monitor mode or root.')
        else:
            selected_interface = st.selectbox('Wireless interface', interface_names, key='wifi_interface')
            st.caption('Network discovery uses NetworkManager when available, with `iw` as a fallback.')
            if st.button('Discover nearby networks', type='primary', disabled=not authorized):
                try:
                    result = _execute_wifi_request(
                        selected_interface,
                        'discover',
                        {'interface': selected_interface},
                        authorized,
                    )
                except (ValueError, PermissionError, WifiDiscoveryError) as exc:
                    st.error(str(exc))
                else:
                    st.session_state['wifi_discovery_result'] = result
                    st.session_state.pop('wifi_selected_network', None)

        result = st.session_state.get('wifi_discovery_result')
        if result:
            if result.get('status') != 'completed':
                st.error(result.get('summary', 'Discovery did not complete successfully.'))
            else:
                st.success(result['summary'])
                networks = result.get('networks', [])
                if networks:
                    st.dataframe(networks, use_container_width=True, hide_index=True)
                    choices = {
                        f"{network.get('ssid') or '(hidden)'} — {network.get('bssid', '')}": network
                        for network in networks
                    }
                    selected_label = st.selectbox('Network to review', list(choices), key='wifi_review_choice')
                    selected_network = choices[selected_label]
                    st.session_state['wifi_selected_network'] = selected_network
                    if st.button(
                        'Analyze selected network',
                        disabled=not authorized,
                        key='wifi_analyze_network',
                    ):
                        try:
                            assessment = _execute_wifi_request(
                                selected_network.get('ssid') or selected_network.get('bssid', ''),
                                'review',
                                selected_network,
                                authorized,
                            )
                        except (ValueError, PermissionError, WifiDiscoveryError) as exc:
                            st.error(str(exc))
                        else:
                            st.session_state['wifi_latest_result'] = assessment
                            if assessment.get('status') == 'completed':
                                st.success(assessment['summary'])
                            else:
                                st.error(assessment.get(
                                    'summary', 'Assessment blocked by authorization or scope policy.'
                                ))
                else:
                    st.info('No nearby networks were returned by the available Linux wireless interface.')
                _render_findings(result)
                _render_report_downloads(result)

        latest = st.session_state.get('wifi_latest_result')
        if latest:
            st.subheader('Latest assessment')
            st.write(latest['summary'])
            _render_findings(latest)
            _render_report_downloads(latest)

    with password_tab:
        st.subheader('Owner-supplied passphrase strength audit')
        st.caption(
            'Evaluation happens locally. The passphrase is not sent to an LLM, included in reports, '
            'or written to the audit log. The input is cleared after submission.'
        )
        st.text_input('Network SSID', key='wifi_audit_ssid')
        st.text_input('Owner-provided Wi-Fi passphrase', type='password', key='wifi_owner_password')
        st.checkbox(
            'I own or am explicitly authorized to audit this passphrase.',
            value=False,
            key='wifi_password_authorized',
        )
        st.button(
            'Audit passphrase locally',
            type='primary',
            disabled=not st.session_state.get('wifi_password_authorized', False),
            on_click=_password_audit_callback,
        )
        if st.session_state.get('wifi_password_audit_error'):
            st.error(st.session_state['wifi_password_audit_error'])
        audit_result = st.session_state.get('wifi_password_audit_result')
        if audit_result:
            st.success(audit_result['summary'])
            _render_findings(audit_result)
            _render_report_downloads(audit_result)

    with saved_tab:
        st.subheader('Current user’s saved NetworkManager profiles')
        st.warning(
            'Profiles restricted to this user and system-wide profiles managed by NetworkManager '
            'are listed. Profiles restricted to other users are excluded. NetworkManager/OS '
            'permissions are honored; the application never elevates privileges.'
        )
        recovery_agent = SavedWifiRecoveryAgent(provider=provider)
        if authorized:
            try:
                connections = recovery_agent.list_connections()
            except (ValueError, PermissionError, WifiDiscoveryError) as exc:
                st.info(str(exc))
                connections = []
        else:
            connections = []
            st.info('Confirm authorization above before listing saved connection metadata.')
        if connections:
            connection_labels = {
                f"{item['name']} — {item['access']}": item for item in connections
            }
            selected_label = st.selectbox('Saved connection', list(connection_labels), key='wifi_saved_connection')
            confirm = st.checkbox(
                'I own or am authorized to access this profile and want to request its saved key.',
                value=False,
                key='wifi_recovery_confirm',
            )
            if st.button(
                'Retrieve saved key',
                disabled=not (authorized and confirm),
                type='primary',
            ):
                try:
                    result = _execute_wifi_request(
                        connection_labels[selected_label]['uuid'],
                        'recover_saved_password',
                        {
                            'connection_uuid': connection_labels[selected_label]['uuid'],
                            'confirm_recovery': confirm,
                        },
                        authorized,
                    )
                except (ValueError, PermissionError, WifiDiscoveryError) as exc:
                    st.error(str(exc))
                else:
                    if result.get('status') == 'completed' and result.get('credential'):
                        st.success('The saved key was retrieved for this request only; it was not stored in history or the report.')
                        st.code(result['credential'], language=None)
                    else:
                        st.error(result.get('summary', 'Saved key retrieval was blocked.'))
        else:
            st.caption('No eligible saved wireless profiles are available to this account.')

    with history_tab:
        st.subheader('Wi-Fi assessment history')
        try:
            history = [
                item for item in _assessment_database().list_assessments()
                if item['category'].lower() == 'wifi'
            ]
        except OSError as exc:
            st.error(f'Assessment history could not be loaded: {exc}')
            history = []
        if history:
            st.dataframe(history, use_container_width=True, hide_index=True)
        else:
            st.info('No completed Wi-Fi assessments have been saved yet.')

    with training_tab:
        st.subheader('Offline training simulation')
        st.info(
            'Training only: this legacy example displays a planted demo value. It is not a real or '
            'recovered password and is separate from live assessments.'
        )
        with st.expander('Open offline simulation'):
            training_ssid = st.text_input('Training label', value='LabWiFi-Alpha')
            if st.button('Run simulated training chain'):
                try:
                    result = run_wifi_recovery_training(training_ssid)
                except ValueError as exc:
                    st.error(str(exc))
                else:
                    st.success(result['summary'])
                    st.warning('DEMO-ONLY VALUE — not a real or usable Wi-Fi password')
                    st.code(result['simulated_credential'])
                    st.dataframe(result['agents'], use_container_width=True, hide_index=True)
