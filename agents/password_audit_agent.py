from __future__ import annotations

import math
import re
from typing import Any


class PasswordAuditAgent:
    """Assess an owner-supplied Wi-Fi passphrase locally without retaining it."""

    _COMMON = {
        'password', 'password1', '12345678', '123456789', 'qwerty123',
        'letmein', 'admin123', 'iloveyou', 'welcome1', 'changeme',
    }

    def evaluate(self, password: str, ssid: str = '') -> dict[str, Any]:
        if not isinstance(password, str) or not password:
            raise ValueError('Enter an owner-provided password to audit.')

        length = len(password)
        lower = password.lower()
        classes = sum(
            bool(check(password))
            for check in (
                lambda value: re.search(r'[a-z]', value),
                lambda value: re.search(r'[A-Z]', value),
                lambda value: re.search(r'\d', value),
                lambda value: re.search(r'[^A-Za-z0-9]', value),
            )
        )
        issues: list[str] = []
        score = 0

        if length < 8:
            issues.append('The passphrase is shorter than the WPA-Personal minimum of 8 characters.')
        else:
            score += min(length * 3, 45)
        if length >= 12:
            score += 10
        if length >= 16:
            score += 10
        score += classes * 6
        if lower in self._COMMON:
            issues.append('The passphrase matches a commonly used weak value.')
            score -= 45
        if ssid and len(ssid) >= 3 and ssid.casefold() in lower:
            issues.append('The passphrase contains the network name.')
            score -= 15
        if re.search(r'(.)\1{3,}', password):
            issues.append('The passphrase contains a long run of repeated characters.')
            score -= 15
        if re.search(r'(?:0123|1234|2345|3456|4567|5678|6789|abcd|qwer)', lower):
            issues.append('The passphrase contains a predictable sequence.')
            score -= 15
        if classes <= 1:
            issues.append('The passphrase uses only one character class.')
        if len(password.encode('utf-8')) > 63:
            issues.append('The passphrase exceeds the 63-byte WPA-Personal limit.')
            score -= 20

        score = max(0, min(100, score))
        if score >= 75 and not issues:
            rating = 'Strong'
        elif score >= 50:
            rating = 'Moderate'
        else:
            rating = 'Weak'

        recommendations: list[str] = []
        if length < 16:
            recommendations.append('Use a unique passphrase of at least 16 characters.')
        if classes < 3:
            recommendations.append('Prefer a randomly generated passphrase or a memorable multi-word phrase.')
        if issues:
            recommendations.append('Avoid network names, common phrases, repeated characters, and predictable sequences.')
        if not recommendations:
            recommendations.append('Keep this passphrase unique to this network and store it in a trusted password manager.')

        pool_size = (
            26 * bool(re.search(r'[a-z]', password))
            + 26 * bool(re.search(r'[A-Z]', password))
            + 10 * bool(re.search(r'\d', password))
            + 33 * bool(re.search(r'[^A-Za-z0-9]', password))
        )
        estimated_bits = round(length * math.log2(max(1, pool_size)))
        return {
            'score': score,
            'rating': rating,
            'length': length,
            'character_classes': classes,
            'estimated_strength_bits': estimated_bits,
            'issues': issues,
            'recommendations': recommendations,
        }
