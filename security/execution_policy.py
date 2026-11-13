from __future__ import annotations

import re
import shutil
import subprocess
from typing import Iterable, Sequence

ALLOWED_EXECUTABLES = {'nmcli', 'iw', 'iwconfig'}
_INTERFACE_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
_UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


class ExecutionPolicy:
    def __init__(self, allowed_executables: Iterable[str] | None = None) -> None:
        self.allowed_executables = set(ALLOWED_EXECUTABLES if allowed_executables is None else allowed_executables)

    def is_allowed(self, executable: str) -> bool:
        return executable in self.allowed_executables and executable in ALLOWED_EXECUTABLES

    def validate_command(self, executable: str, args: Sequence[str] | None = None) -> bool:
        if not self.is_allowed(executable):
            return False
        if args is None or any(not isinstance(part, str) or len(part) >= 256 or '\x00' in part for part in args):
            return False
        parts = list(args)
        if executable == 'nmcli':
            return self._validate_nmcli(parts)
        if executable == 'iw':
            return parts == ['dev'] or (
                len(parts) == 3
                and parts[0] == 'dev'
                and _INTERFACE_PATTERN.fullmatch(parts[1]) is not None
                and parts[2] == 'scan'
            )
        if executable == 'iwconfig':
            return parts == [] or (
                len(parts) == 1 and _INTERFACE_PATTERN.fullmatch(parts[0]) is not None
            )
        return False

    @staticmethod
    def _validate_nmcli(args: list[str]) -> bool:
        if args == ['--terse', '--escape', 'yes', '--fields', 'DEVICE,TYPE', 'device', 'status']:
            return True
        if args == ['--terse', '--escape', 'yes', '--fields', 'UUID,NAME,TYPE', 'connection', 'show']:
            return True
        if (
            len(args) == 5
            and args[:4] == [
                '--get-values', 'connection.permissions', 'connection', 'show',
            ]
            and _UUID_PATTERN.fullmatch(args[4]) is not None
        ):
            return True
        if (
            len(args) == 12
            and args[:9] == [
                '--terse', '--escape', 'yes', '--fields',
                'SSID,BSSID,CHAN,FREQ,SIGNAL,SECURITY',
                'device', 'wifi', 'list', 'ifname',
            ]
            and _INTERFACE_PATTERN.fullmatch(args[9]) is not None
            and args[10:] == ['--rescan', 'yes']
        ):
            return True
        return (
            len(args) == 6
            and args[:4] == [
                '--show-secrets', '--get-values',
                '802-11-wireless-security.psk', 'connection',
            ]
            and args[4] == 'show'
            and _UUID_PATTERN.fullmatch(args[5]) is not None
        )

    def run(self, executable: str, args: Sequence[str], timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
        """Run one narrowly allowlisted, argument-vector command without a shell."""
        if not self.validate_command(executable, args):
            raise PermissionError(f'Command is not allowed by execution policy: {executable}')
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 60:
            raise ValueError('Command timeout must be between 0 and 60 seconds.')
        resolved = shutil.which(executable)
        if not resolved:
            raise FileNotFoundError(f'Required utility is not installed: {executable}')
        return subprocess.run(
            [resolved, *args],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
