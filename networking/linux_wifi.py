from __future__ import annotations

import os
import platform
import pwd
import re
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable

from security.execution_policy import ExecutionPolicy

_INTERFACE_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
_BSSID_PATTERN = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')


class WifiDiscoveryError(RuntimeError):
    """A safe, user-facing error from local Wi-Fi discovery."""


@dataclass(frozen=True)
class WirelessInterface:
    name: str
    source: str


@dataclass(frozen=True)
class WifiNetwork:
    ssid: str
    bssid: str
    channel: int | None
    frequency_mhz: int | None
    signal_percent: int | None
    security: str
    wps_exposed: bool | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def split_nmcli_row(line: str) -> list[str]:
    """Split one nmcli terse row, respecting its backslash-escaped delimiters."""
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for character in line.rstrip('\r\n'):
        if escaped:
            current.append({'s': ' ', 'n': '\n', 't': '\t'}.get(character, character))
            escaped = False
        elif character == '\\':
            escaped = True
        elif character == ':':
            fields.append(''.join(current))
            current.clear()
        else:
            current.append(character)
    if escaped:
        current.append('\\')
    fields.append(''.join(current))
    return fields


def classify_security(value: str) -> str:
    """Normalize common nmcli and iw security labels."""
    label = value.upper().replace('_', ' ')
    has_wpa3 = 'WPA3' in label or 'SAE' in label
    has_wpa2 = 'WPA2' in label or ('RSN' in label and (not has_wpa3 or 'PSK' in label))
    has_legacy_wpa = bool(re.search(r'\bWPA(?:1)?\b', label)) and 'WPA3' not in label
    if has_wpa3 and has_wpa2:
        return 'WPA2/WPA3'
    if has_legacy_wpa and has_wpa2:
        return 'WPA/WPA2'
    if has_wpa3:
        return 'WPA3'
    if has_wpa2:
        return 'WPA2'
    if has_legacy_wpa:
        return 'WPA'
    if 'WEP' in label or ('PRIVACY' in label and 'RSN' not in label and 'WPA' not in label):
        return 'WEP'
    if not label.strip() or label.strip() in {'--', '(NONE)', 'NONE', 'OPEN'}:
        return 'Open'
    return 'Unknown'


def channel_from_frequency(frequency_mhz: int | None) -> int | None:
    if frequency_mhz is None:
        return None
    if frequency_mhz == 2484:
        return 14
    if 2412 <= frequency_mhz <= 2472:
        return (frequency_mhz - 2407) // 5
    if 5000 <= frequency_mhz < 5925:
        return (frequency_mhz - 5000) // 5
    if 5955 <= frequency_mhz <= 7115:
        return (frequency_mhz - 5950) // 5
    if frequency_mhz == 5935:
        return 2
    return None


def parse_nmcli_networks(output: str) -> list[WifiNetwork]:
    """Parse nmcli's terse SSID/BSSID/channel/frequency/signal/security listing."""
    networks: list[WifiNetwork] = []
    for line in output.splitlines():
        fields = split_nmcli_row(line)
        if len(fields) != 6:
            continue
        ssid, bssid, channel, frequency, signal, security = fields
        if not _BSSID_PATTERN.fullmatch(bssid):
            continue
        try:
            channel_value = int(channel) if channel else None
        except ValueError:
            channel_value = None
        try:
            frequency_value = int(frequency) if frequency else None
        except ValueError:
            frequency_value = None
        try:
            signal_value = max(0, min(100, int(signal))) if signal else None
        except ValueError:
            signal_value = None
        networks.append(
            WifiNetwork(
                ssid=ssid,
                bssid=bssid.upper(),
                channel=channel_value or channel_from_frequency(frequency_value),
                frequency_mhz=frequency_value,
                signal_percent=signal_value,
                security=classify_security(security),
            )
        )
    return networks


def _signal_percent_from_dbm(value: float | None) -> int | None:
    if value is None:
        return None
    return max(0, min(100, round(2 * (value + 100))))


def parse_iw_scan(output: str) -> list[WifiNetwork]:
    """Parse iw scan output without retaining raw scan text."""
    networks: list[WifiNetwork] = []
    current: dict[str, str] | None = None

    def append_current() -> None:
        if current is None:
            return
        bssid = current.get('bssid', '')
        if not _BSSID_PATTERN.fullmatch(bssid):
            return
        try:
            frequency = int(current['frequency'])
        except (KeyError, ValueError):
            frequency = None
        try:
            signal_dbm = float(current['signal'])
        except (KeyError, ValueError):
            signal_dbm = None
        security_source = current.get('security_source', '')
        networks.append(
            WifiNetwork(
                ssid=current.get('ssid', ''),
                bssid=bssid.upper(),
                channel=channel_from_frequency(frequency),
                frequency_mhz=frequency,
                signal_percent=_signal_percent_from_dbm(signal_dbm),
                security=classify_security(security_source),
                wps_exposed=True if current.get('wps') == 'true' else None,
            )
        )

    for line in output.splitlines():
        match = re.match(r'\s*BSS\s+([0-9A-Fa-f:]{17})(?:\(|\s|$)', line)
        if match:
            append_current()
            current = {'bssid': match.group(1), 'security_source': ''}
            continue
        if current is None:
            continue
        match = re.search(r'\bfreq:\s*(\d+)', line)
        if match:
            current['frequency'] = match.group(1)
        match = re.search(r'\bsignal:\s*(-?\d+(?:\.\d+)?)\s*dBm', line)
        if match:
            current['signal'] = match.group(1)
        match = re.match(r'\s*SSID:\s?(.*)$', line)
        if match:
            current['ssid'] = match.group(1)
        if re.search(r'\bWPS\b|0050f204', line, re.IGNORECASE):
            current['wps'] = 'true'
        if re.search(r'\bRSN\b|\bWPA\b|\bSAE\b|\bPSK\b|\bPrivacy\b', line, re.IGNORECASE):
            current['security_source'] += ' ' + line
    append_current()
    return networks


class LinuxWifiProvider:
    """Read nearby Wi-Fi metadata using supported local Linux utilities only."""

    def __init__(
        self,
        policy: ExecutionPolicy | None = None,
        sysfs_root: str | Path = '/sys/class/net',
        os_release_path: str | Path = '/etc/os-release',
        command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None,
    ) -> None:
        self.policy = policy or ExecutionPolicy()
        self.sysfs_root = Path(sysfs_root)
        self.os_release_path = Path(os_release_path)
        self._command_runner = command_runner or self.policy.run

    def environment(self) -> dict[str, object]:
        """Report OS, distribution, installed tools, and discovered interfaces."""
        distribution = self._distribution()
        utilities = [name for name in ('nmcli', 'iw', 'iwconfig') if shutil.which(name)]
        interfaces = self.list_wireless_interfaces()
        return {
            'platform': platform.system(),
            'distribution': distribution,
            'utilities': utilities,
            'interfaces': [asdict(interface) for interface in interfaces],
        }

    def _distribution(self) -> str:
        try:
            values = {}
            for line in self.os_release_path.read_text(encoding='utf-8').splitlines():
                key, separator, value = line.partition('=')
                if separator:
                    values[key] = value.strip().strip('"').strip("'")
            return values.get('PRETTY_NAME') or values.get('ID') or 'Linux distribution not identified'
        except OSError:
            return 'Linux distribution not identified'

    def list_wireless_interfaces(self) -> list[WirelessInterface]:
        if platform.system() != 'Linux':
            raise WifiDiscoveryError('Live Wi-Fi discovery is supported on Linux only.')

        interfaces: dict[str, str] = {}
        failures: list[str] = []
        try:
            for device in self.sysfs_root.iterdir():
                if (device / 'wireless').exists() and _INTERFACE_PATTERN.fullmatch(device.name):
                    interfaces[device.name] = 'sysfs'
        except OSError:
            failures.append('sysfs')

        if shutil.which('iw'):
            try:
                result = self._command_runner('iw', ['dev'])
                if result.returncode == 0:
                    for match in re.finditer(r'^\s*Interface\s+([A-Za-z0-9_.:-]{1,15})\s*$', result.stdout, re.M):
                        interfaces.setdefault(match.group(1), 'iw')
                else:
                    failures.append('iw')
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append('iw')

        if shutil.which('nmcli'):
            try:
                result = self._command_runner(
                    'nmcli',
                    ['--terse', '--escape', 'yes', '--fields', 'DEVICE,TYPE', 'device', 'status'],
                )
                if result.returncode == 0:
                    for line in result.stdout.splitlines():
                        fields = split_nmcli_row(line)
                        if len(fields) == 2 and fields[1] == 'wifi' and _INTERFACE_PATTERN.fullmatch(fields[0]):
                            interfaces.setdefault(fields[0], 'NetworkManager')
                else:
                    failures.append('NetworkManager')
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append('NetworkManager')

        if shutil.which('iwconfig'):
            try:
                result = self._command_runner('iwconfig', [])
                if result.returncode == 0:
                    for match in re.finditer(r'^(\S+)\s+IEEE 802\.11', result.stdout, re.M):
                        if _INTERFACE_PATTERN.fullmatch(match.group(1)):
                            interfaces.setdefault(match.group(1), 'iwconfig')
                else:
                    failures.append('iwconfig')
            except (OSError, subprocess.SubprocessError) as exc:
                failures.append('iwconfig')
        if not interfaces and failures:
            raise WifiDiscoveryError(
                f'Wireless interfaces could not be enumerated using: {", ".join(sorted(set(failures)))}.'
            )
        return [WirelessInterface(name, interfaces[name]) for name in sorted(interfaces)]

    def discover(self, interface: str) -> list[WifiNetwork]:
        """Return nearby beacon metadata; never enables monitor mode or changes interfaces."""
        if platform.system() != 'Linux':
            raise WifiDiscoveryError('Live Wi-Fi discovery is supported on Linux only.')
        if not isinstance(interface, str) or not _INTERFACE_PATTERN.fullmatch(interface):
            raise ValueError('Select a valid wireless interface.')
        if interface not in {item.name for item in self.list_wireless_interfaces()}:
            raise WifiDiscoveryError('The selected wireless interface is not available on this system.')

        failures: list[str] = []
        if shutil.which('nmcli'):
            try:
                result = self._command_runner(
                    'nmcli',
                    [
                        '--terse', '--escape', 'yes', '--fields',
                        'SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY',
                        'device', 'wifi', 'list', 'ifname', interface, '--rescan', 'yes',
                    ],
                    timeout=25,
                )
                if result.returncode == 0:
                    return parse_nmcli_networks(result.stdout)
                if self._permission_error(result.stderr):
                    raise WifiDiscoveryError(
                        'NetworkManager denied Wi-Fi discovery. Check the logged-in user’s NetworkManager permissions.'
                    )
                failures.append('NetworkManager')
            except WifiDiscoveryError:
                raise
            except subprocess.TimeoutExpired as exc:
                raise WifiDiscoveryError('NetworkManager Wi-Fi discovery timed out.') from exc
            except (OSError, subprocess.SubprocessError) as exc:
                if isinstance(exc, FileNotFoundError):
                    failures.append('NetworkManager')
                elif isinstance(exc, PermissionError):
                    raise WifiDiscoveryError('Permission was denied while requesting Wi-Fi metadata.') from exc
                else:
                    failures.append('NetworkManager')

        if shutil.which('iw'):
            try:
                result = self._command_runner('iw', ['dev', interface, 'scan'], timeout=25)
                if result.returncode == 0:
                    return parse_iw_scan(result.stdout)
                if self._permission_error(result.stderr):
                    raise WifiDiscoveryError(
                        'The kernel denied Wi-Fi scanning. Use NetworkManager or grant ordinary user-level scan permissions.'
                    )
                failures.append('iw')
            except WifiDiscoveryError:
                raise
            except subprocess.TimeoutExpired as exc:
                raise WifiDiscoveryError('iw Wi-Fi discovery timed out.') from exc
            except (OSError, subprocess.SubprocessError) as exc:
                raise WifiDiscoveryError('The iw utility could not complete Wi-Fi discovery.') from exc

        if shutil.which('iwconfig'):
            if failures:
                raise WifiDiscoveryError(
                    f'Wi-Fi discovery failed using: {", ".join(failures)}. iwconfig cannot scan nearby networks.'
                )
            raise WifiDiscoveryError(
                'iwconfig can identify legacy wireless adapters, but it does not provide a supported nearby-network scan.'
            )
        if failures:
            raise WifiDiscoveryError(f'Wi-Fi discovery failed using: {", ".join(failures)}.')
        raise WifiDiscoveryError('No supported Wi-Fi discovery utility (NetworkManager or iw) is installed.')

    def list_saved_wireless_connections(self) -> list[dict[str, str]]:
        """List profiles the current user can request through NetworkManager."""
        if platform.system() != 'Linux' or not shutil.which('nmcli'):
            raise WifiDiscoveryError('Saved Wi-Fi connections are available only through Linux NetworkManager.')
        result = self._command_runner(
            'nmcli',
            ['--terse', '--escape', 'yes', '--fields', 'UUID,NAME,TYPE', 'connection', 'show'],
        )
        if result.returncode != 0:
            if self._permission_error(result.stderr):
                raise WifiDiscoveryError('NetworkManager denied access to the current user’s connection list.')
            raise WifiDiscoveryError('NetworkManager could not list saved connection metadata.')
        connections: list[dict[str, str]] = []
        for line in result.stdout.splitlines():
            fields = split_nmcli_row(line)
            if (
                len(fields) == 3
                and fields[2] == '802-11-wireless'
                and _valid_uuid(fields[0])
            ):
                permissions_result = self._command_runner(
                    'nmcli',
                    [
                        '--get-values', 'connection.permissions',
                        'connection', 'show', fields[0],
                    ],
                )
                if permissions_result.returncode != 0:
                    if self._permission_error(permissions_result.stderr):
                        continue
                    raise WifiDiscoveryError(
                        'NetworkManager could not verify saved connection permissions.'
                    )
                access = self._connection_access(permissions_result.stdout)
                if access:
                    connections.append({
                        'uuid': fields[0],
                        'name': fields[1],
                        'access': access,
                    })
        return connections

    @staticmethod
    def _connection_access(permissions: str) -> str | None:
        """Return access only for user-owned or NetworkManager system-wide profiles."""
        normalized = permissions.strip()
        if not normalized or normalized == '--':
            return 'All users (NetworkManager controlled)'
        try:
            username = pwd.getpwuid(os.getuid()).pw_name
        except (KeyError, OSError):
            return None
        allowed = {entry for entry in normalized.split(',') if entry}
        if allowed == {f'user:{username}:'}:
            return 'Current user'
        return None

    @staticmethod
    def _permission_error(stderr: str) -> bool:
        lowered = stderr.lower()
        return any(marker in lowered for marker in ('permission denied', 'not authorized', 'access denied', 'operation not permitted'))


def _valid_uuid(value: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}', value))
