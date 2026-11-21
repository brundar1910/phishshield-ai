"""Reputation and Domain Intelligence Service."""

from typing import Dict, Any
from urllib.parse import urlparse

SAFE_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "github.com",
    "wikipedia.org", "amazon.com", "linkedin.com", "cloudflare.com",
    "stackoverflow.com", "python.org", "mozilla.org", "w3.org"
}


class ReputationService:
    """Provides high-reputation domain verification and whitelist checks."""

    @staticmethod
    def check_domain_reputation(url: str) -> Dict[str, Any]:
        """Checks if a domain is an established, verified safe entity."""
        try:
            parsed = urlparse(url if "://" in url else "http://" + url)
            hostname = (parsed.hostname or "").lower()
            if hostname.startswith("www."):
                hostname = hostname[4:]

            is_whitelisted = hostname in SAFE_DOMAINS or any(hostname.endswith("." + d) for d in SAFE_DOMAINS)

            return {
                "hostname": hostname,
                "is_whitelisted": is_whitelisted,
                "reputation_score": 100 if is_whitelisted else 50
            }
        except Exception:
            return {
                "hostname": "",
                "is_whitelisted": False,
                "reputation_score": 50
            }
