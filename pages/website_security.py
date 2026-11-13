from __future__ import annotations

import streamlit as st

PORT_REFERENCE = [
    {
        'Port': 80,
        'Service': 'HTTP',
        'Typical use': 'Unencrypted web traffic',
        'Defensive note': 'Redirect to HTTPS; avoid sending sensitive data over HTTP.',
    },
    {
        'Port': 443,
        'Service': 'HTTPS',
        'Typical use': 'Encrypted web traffic',
        'Defensive note': 'Use current TLS settings and renew certificates on time.',
    },
    {
        'Port': 8080,
        'Service': 'Alternate HTTP',
        'Typical use': 'Development or proxy service',
        'Defensive note': 'Restrict access; do not expose development consoles publicly.',
    },
    {
        'Port': 8443,
        'Service': 'Alternate HTTPS',
        'Typical use': 'Alternate secure web service',
        'Defensive note': 'Apply the same TLS, authentication, and patching controls as 443.',
    },
    {
        'Port': 22,
        'Service': 'SSH',
        'Typical use': 'Remote administration (not a web port)',
        'Defensive note': 'Limit to trusted admin networks and use key-based authentication.',
    },
    {
        'Port': 3306,
        'Service': 'MySQL',
        'Typical use': 'Database (not a web port)',
        'Defensive note': 'Keep private; allow connections only from required application hosts.',
    },
]

SIMULATION_SCENARIOS = {
    'Unexpected service exposure': (
        'A mock report flags an administrative or development service as internet-reachable. '
        'Review firewall rules and disable services that are not required.'
    ),
    'TLS configuration review': (
        'A mock report represents outdated or incomplete HTTPS configuration. '
        'Use supported TLS versions, valid certificates, and secure cipher settings.'
    ),
    'Authentication resilience review': (
        'A mock report represents missing rate limits or weak account protections. '
        'Use MFA, rate limiting, secure password storage, and monitoring.'
    ),
}

def render_website_security() -> None:
    st.title('Website Security')
    st.info(
        'This page is an offline reference and simulation. The ports below are common service '
        'defaults, not ports discovered on a website. No target is contacted and no scan runs.'
    )

    st.subheader('Common service ports')
    st.dataframe(PORT_REFERENCE, use_container_width=True, hide_index=True)
    st.caption(
        'A port number alone does not confirm that a service is running or exposed. Actual '
        'exposure depends on the host, firewall, service configuration, and network path.'
    )

    st.subheader('Defensive checks')
    st.markdown(
        '- Inventory approved web-facing services and close unused ports at the host and firewall.\n'
        '- Enforce HTTPS, maintain TLS certificates, and configure current TLS versions.\n'
        '- Keep frameworks and server software patched; remove default pages and test consoles.\n'
        '- Apply authentication, MFA, rate limits, secure cookies, and least privilege.\n'
        '- Review security headers, access logs, backups, and incident-response procedures.'
    )

    st.subheader('Non-executable offensive-perspective simulations')
    st.caption(
        'These are threat-model examples only. They do not probe a host, send requests, or '
        'provide exploit or credential-attack steps.'
    )
    scenario = st.selectbox('Choose a mock scenario', list(SIMULATION_SCENARIOS))
    if st.button('Show simulated finding'):
        st.warning(f'SIMULATED ONLY — {scenario}')
        st.write(SIMULATION_SCENARIOS[scenario])
