from __future__ import annotations

from typing import Any, Dict, List


def run_wifi_recovery_training(ssid: str) -> Dict[str, Any]:
    """Simulate an agent credential-discovery chain using mock data only."""
    normalized_ssid = ssid.strip()
    if not normalized_ssid:
        raise ValueError('Enter an SSID to start the training simulation.')

    mock_credential = 'DEMO_ONLY_NOT_A_WIFI_PASSWORD_123'
    agents: List[Dict[str, str]] = [
        {
            'agent': 'Training Coordinator',
            'status': 'Complete',
            'result': f'Created an offline scenario labeled “{normalized_ssid}”. The SSID is used only as a label.',
        },
        {
            'agent': 'Reconnaissance Simulator',
            'status': 'Complete',
            'result': 'Returned synthetic network metadata from the bundled mock scenario; no wireless interfaces or external services were accessed.',
        },
        {
            'agent': 'Credential Discovery Simulator',
            'status': 'Simulated success',
            'result': f'The mock dataset contained the planted demo value: {mock_credential}. It was not derived from the SSID.',
        },
        {
            'agent': 'Safety Auditor',
            'status': 'Complete',
            'result': 'Confirmed the displayed value is synthetic and that the workflow performed no real credential access. This illustrates how an agent chain could expose secrets if connected to real data.',
        },
    ]

    return {
        'status': 'simulated',
        'summary': 'Offline demo complete. The simulated agent chain disclosed only its planted mock value; an SSID alone does not reveal a real Wi-Fi password.',
        'agents': agents,
        'simulated_credential': mock_credential,
    }
