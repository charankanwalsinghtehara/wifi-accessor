from __future__ import annotations

import ipaddress
import re
from typing import Any, Dict

from config import ALLOWED_CIDRS, ALLOWED_DOMAINS

_DOMAIN_PATTERN = re.compile(
    r'^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$'
)
_INTERFACE_PATTERN = re.compile(r'^[A-Za-z0-9_.:-]{1,15}$')
_BSSID_PATTERN = re.compile(r'^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$')
_UUID_PATTERN = re.compile(
    r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'
)


class ScopeValidator:
    def __init__(self) -> None:
        self.allowed_domains = ALLOWED_DOMAINS
        self.allowed_cidrs = ALLOWED_CIDRS

    def is_domain(self, value: str) -> bool:
        if not isinstance(value, str):
            return False
        normalized = value[:-1] if value.endswith('.') else value
        return bool(_DOMAIN_PATTERN.fullmatch(normalized))

    def is_cidr_target(self, value: str) -> bool:
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_network(value, strict=False)
            return True
        except ValueError:
            return False

    def is_ip_address(self, value: str) -> bool:
        if not isinstance(value, str):
            return False
        try:
            ipaddress.ip_address(value)
            return True
        except ValueError:
            return False

    def is_allowed_domain(self, domain: str) -> bool:
        normalized = domain.lower().rstrip('.')
        return normalized in {item.lower().rstrip('.') for item in self.allowed_domains}

    def is_allowed_cidr(self, target: str) -> bool:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError:
            return False
        for cidr in self.allowed_cidrs:
            try:
                allowed = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            if network.version == allowed.version and network.subnet_of(allowed):
                return True
        return False

    def validate_scope(
        self,
        category: str,
        target: str,
        details: Dict[str, Any],
        authorization: Dict[str, Any] | None = None,
    ) -> bool:
        if not isinstance(category, str) or not isinstance(target, str) or not isinstance(details, dict):
            return False
        if category.lower() == 'wifi':
            if not isinstance(authorization, dict) or authorization.get('authorized') is not True:
                return False
            operation = details.get('operation', 'review')
            if operation == 'discover':
                interface = details.get('interface', '')
                return bool(
                    isinstance(target, str)
                    and _INTERFACE_PATTERN.fullmatch(target)
                    and interface == target
                    and details.get('scope_target') == target
                )
            if operation == 'recover_saved_password':
                connection_uuid = details.get('connection_uuid', '')
                return bool(
                    isinstance(target, str)
                    and _UUID_PATTERN.fullmatch(target)
                    and connection_uuid == target
                    and details.get('scope_target') == target
                    and details.get('confirm_recovery') is True
                )
            if operation not in {'review', 'password_audit'}:
                return False
            supplied_ssid = details.get('ssid', target)
            if not isinstance(supplied_ssid, str):
                return False
            ssid = supplied_ssid or target
            scope_target = details.get('scope_target', target if details.get('lab_mode') is True else None)
            valid_wifi_target = bool(
                isinstance(ssid, str)
                and ssid.strip()
                and len(ssid.encode('utf-8', errors='replace')) <= 32
                and not any(ord(character) < 32 or ord(character) == 127 for character in ssid)
                and ssid == target
                and scope_target == target
            )
            bssid = details.get('bssid')
            valid_bssid = bssid is None or (
                isinstance(bssid, str) and _BSSID_PATTERN.fullmatch(bssid) is not None
            )
            if operation == 'review':
                security = details.get('security', details.get('security_mode', 'Unknown'))
                valid_security = isinstance(security, str) and len(security) <= 80
                numeric_limits = {
                    'channel': (1, 233),
                    'frequency_mhz': (2000, 8000),
                    'signal_percent': (0, 100),
                }
                for field, (minimum, maximum) in numeric_limits.items():
                    value = details.get(field)
                    if value is not None and (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or not minimum <= value <= maximum
                    ):
                        return False
                wps = details.get('wps_exposed')
                if wps is not None and not isinstance(wps, bool):
                    return False
                return valid_wifi_target and valid_bssid and valid_security
            return valid_wifi_target and valid_bssid
        if category.lower() in {'website', 'network', 'infrastructure'}:
            if self.is_domain(target):
                return self.is_allowed_domain(target)
            if self.is_cidr_target(target):
                return self.is_allowed_cidr(target)
            if self.is_ip_address(target):
                address = ipaddress.ip_address(target)
                for cidr in self.allowed_cidrs:
                    try:
                        network = ipaddress.ip_network(cidr, strict=False)
                    except ValueError:
                        continue
                    if address.version == network.version and address in network:
                        return True
            return False
        return False
