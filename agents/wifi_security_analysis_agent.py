from __future__ import annotations

from typing import Any


class WifiSecurityAnalysisAgent:
    """Create evidence-based findings from Wi-Fi metadata; never probes access points."""

    def analyze(self, network: dict[str, Any]) -> list[dict[str, Any]]:
        security = str(network.get('security') or 'Unknown').upper()
        ssid = str(network.get('ssid') or '(hidden SSID)')
        bssid = str(network.get('bssid') or 'unknown')
        asset = f'{ssid} ({bssid})'
        findings: list[dict[str, Any]] = []

        def finding(title: str, severity: str, description: str, evidence: str, remediation: str) -> None:
            findings.append({
                'title': title,
                'severity': severity,
                'status': 'Observed',
                'description': description,
                'affected_asset': asset,
                'evidence': evidence,
                'confidence': 'High',
                'remediation': remediation,
            })

        if security == 'OPEN':
            finding(
                'Unencrypted wireless network', 'High',
                'The network advertises no link-layer Wi-Fi encryption.',
                'Discovery metadata reports no security protocol.',
                'Enable WPA3-Personal or WPA2-AES and avoid transmitting sensitive data over an open network.',
            )
        elif security == 'WEP':
            finding(
                'Obsolete WEP encryption', 'Critical',
                'WEP is obsolete and does not provide adequate wireless confidentiality.',
                'Discovery metadata identifies WEP.',
                'Replace WEP with WPA3-Personal or WPA2-AES; do not retain WEP as a compatibility mode.',
            )
        elif security == 'WPA':
            finding(
                'Legacy WPA security', 'High',
                'The network advertises legacy WPA rather than current WPA2/WPA3 protection.',
                'Discovery metadata identifies WPA without WPA2 or WPA3.',
                'Configure WPA3-Personal or WPA2-AES and retire legacy WPA compatibility.',
            )
        elif security == 'WPA2':
            finding(
                'WPA2 configuration review', 'Informational',
                'WPA2 is supported, but passphrase strength and access-point cipher settings are not visible in beacon metadata.',
                'Discovery metadata identifies WPA2; no password or traffic was tested.',
                'Use WPA2-AES or WPA3, use a unique long passphrase, and keep access-point firmware current.',
            )
        elif security == 'WPA2/WPA3':
            finding(
                'WPA2/WPA3 transition mode', 'Low',
                'A mixed transition mode is advertised to support older clients.',
                'Discovery metadata identifies WPA2/WPA3 transition mode.',
                'Prefer WPA3-only when all clients support it; otherwise use a strong unique passphrase and review connected clients.',
            )
        elif security == 'WPA/WPA2':
            finding(
                'Legacy WPA compatibility enabled', 'Medium',
                'The network advertises both legacy WPA and WPA2 compatibility.',
                'Discovery metadata identifies legacy WPA alongside WPA2.',
                'Disable legacy WPA compatibility and use WPA2-AES or WPA3 where client support permits.',
            )
        elif security == 'WPA3':
            finding(
                'Modern Wi-Fi encryption observed', 'Informational',
                'The network advertises WPA3. Discovery metadata alone cannot verify all access-point settings.',
                'Discovery metadata identifies WPA3; no authentication attempt was made.',
                'Keep WPA3 enabled, use a unique passphrase, and maintain router firmware.',
            )
        else:
            finding(
                'Wi-Fi security could not be classified', 'Medium',
                'The available beacon metadata does not identify a supported security mode.',
                f'Reported security value: {security[:80]}.',
                'Verify the access point’s configured security mode in its authenticated administration interface.',
            )

        wps = network.get('wps_exposed')
        if wps is True:
            finding(
                'WPS advertisement observed', 'Medium',
                'Discovery metadata contains a WPS information element. No WPS registration or PIN testing was performed.',
                'A WPS information element was present in the wireless beacon information.',
                'Disable WPS in the access point’s authenticated administration interface if it is not required.',
            )
        elif wps is False:
            finding(
                'WPS not observed in discovery metadata', 'Informational',
                'The discovery source did not observe a WPS information element; this does not prove WPS is disabled.',
                'WPS was not reported by the available beacon metadata.',
                'Verify WPS is disabled through the access point’s authenticated administration interface.',
            )
        else:
            finding(
                'WPS status unavailable', 'Informational',
                'The discovery source does not expose reliable WPS status. No active WPS probe was sent.',
                'WPS status was not available from the passive metadata source.',
                'Verify WPS is disabled through the access point’s authenticated administration interface.',
            )
        return findings
