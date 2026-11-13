from __future__ import annotations

import os
import platform
import subprocess
from typing import Any

from networking.linux_wifi import LinuxWifiProvider, WifiDiscoveryError
from security.execution_policy import ExecutionPolicy


class SavedWifiRecoveryAgent:
    """Access only the current Linux user's NetworkManager Wi-Fi profiles."""

    def __init__(
        self,
        provider: LinuxWifiProvider | None = None,
        policy: ExecutionPolicy | None = None,
    ) -> None:
        self.policy = policy or ExecutionPolicy()
        self.provider = provider or LinuxWifiProvider(policy=self.policy)

    def list_connections(self) -> list[dict[str, str]]:
        return self.provider.list_saved_wireless_connections()

    def recover(self, connection_uuid: str, confirm: bool) -> dict[str, Any]:
        if confirm is not True:
            raise PermissionError('Explicit confirmation is required before requesting a saved Wi-Fi key.')
        if platform.system() != 'Linux' or not os.path.exists('/etc/os-release'):
            raise WifiDiscoveryError('Saved Wi-Fi key access is supported only for the current Linux user.')
        if hasattr(os, 'geteuid') and os.geteuid() == 0:
            raise PermissionError('Run the application as your normal logged-in user, not as root.')
        connections = self.list_connections()
        connection = next(
            (item for item in connections if item['uuid'] == connection_uuid), None
        )
        if connection is None:
            raise ValueError('Select a saved wireless connection belonging to this user account.')
        try:
            result = self.policy.run(
                'nmcli',
                [
                    '--show-secrets', '--get-values',
                    '802-11-wireless-security.psk', 'connection', 'show', connection_uuid,
                ],
            )
        except PermissionError:
            raise
        except (OSError, subprocess.SubprocessError) as exc:
            raise WifiDiscoveryError('NetworkManager could not read this user’s saved Wi-Fi key.') from exc
        if result.returncode != 0:
            if LinuxWifiProvider._permission_error(result.stderr):
                raise PermissionError(
                    'NetworkManager denied access to this saved key. No permission bypass was attempted.'
                )
            raise WifiDiscoveryError('NetworkManager could not read this user’s saved Wi-Fi key.')
        password = result.stdout.rstrip('\r\n')
        if not password:
            raise WifiDiscoveryError('No saved Wi-Fi passphrase is available for this connection.')
        return {
            'connection_uuid': connection_uuid,
            'connection_name': connection['name'],
            'password': password,
        }
