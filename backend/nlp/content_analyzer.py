"""NLP Content and Sentiment Analyzer for Phishing Communications."""

import re
from typing import Any, Dict, List

URGENCY_PATTERNS = [
    r"\b(urgent|immediate|immediately|action required|suspended|suspension)\b",
    r"\b(within\s+\d+\s+(hours?|days?|minutes?))\b",
    r"\b(unauthorized\s+activity|security\s+alert|compromised)\b",
    r"\b(account\s+locked|verify\s+identity|verify\s+now)\b",
    r"\b(final\s+notice|legal\s+action|lawsuit)\b"
]

CREDENTIAL_HARVESTING_PATTERNS = [
    r"\b(enter|update|confirm|verify|reset|submit|provide)\s+(your\s+)?(password|credentials?|pin|social\s+security|ssn|credit\s+card|billing|payment|banking|account|login)\b",
    r"\b(password|credential|pin)\s+(reset|update|verification|confirmation)\b",
    r"\b(confirm\s+your\s+(identity|password|account|email))\b"
]


class PhishingNLPAnalyzer:
    """Analyzes text/emails/webpage text for social engineering cues."""

    @staticmethod
    def analyze_text(text: str) -> Dict[str, Any]:
        """Analyzes text for urgency, credential demands, and phishing patterns."""
        if not text:
            return {
                "urgency_score": 0.0,
                "credential_harvesting_detected": False,
                "phishing_text_score": 0.0,
                "matches": []
            }

        text_lower = text.lower()
        urgency_matches = []
        for pattern in URGENCY_PATTERNS:
            found = re.findall(pattern, text_lower)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    if val:
                        urgency_matches.append(val)

        cred_matches = []
        for pattern in CREDENTIAL_HARVESTING_PATTERNS:
            found = re.findall(pattern, text_lower)
            if found:
                for match in found:
                    val = match[0] if isinstance(match, tuple) else match
                    if val:
                        cred_matches.append(val)

        urgency_score = min(1.0, len(urgency_matches) * 0.25)
        cred_score = min(1.0, len(cred_matches) * 0.40)
        total_score = min(1.0, (urgency_score * 0.5) + (cred_score * 0.5))

        return {
            "urgency_score": round(urgency_score, 2),
            "credential_harvesting_detected": len(cred_matches) > 0,
            "phishing_text_score": round(total_score, 2),
            "urgency_matches": list(set(urgency_matches)),
            "credential_matches": list(set(cred_matches)),
            "is_suspicious": total_score >= 0.5
        }
