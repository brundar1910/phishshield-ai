"""
Comprehensive URL Feature Extraction Engine.
Extracts lexical, domain, structural, and entropy features from URLs for phishing detection.
"""

import math
import re
from typing import Any, Dict, List
from urllib.parse import urlparse

# Well-known URL shortening services
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "rebrand.ly", "t.co", "is.gd",
    "buff.ly", "ow.ly", "cutt.ly", "bitly.com", "tiny.cc", "clck.ru",
    "rotf.lol", "v.gd", "tr.im", "rb.gy", "shorturl.at", "bl.ink",
    "hyperurl.co", "shorte.st", "adf.ly", "bc.vc", "snipurl.com",
    "soo.gd", "q.gs", "deck.ly"
}

# Suspicious high-abuse TLDs frequently observed in phishing attacks
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "buzz", "fit", "gq", "cf", "ml", "ga", "tk",
    "icu", "loan", "cam", "bar", "rest", "monster", "quest", "click",
    "link", "country", "stream", "gdn", "mom", "party", "kim", "cricket"
}

# High-risk phishing keywords commonly used in credential harvesting & fake portals
SUSPICIOUS_KEYWORDS = [
    "login", "verify", "verification", "secure", "security", "account",
    "update", "banking", "signin", "sign-in", "log-in", "wallet",
    "confirm", "password", "credential", "authenticate", "auth",
    "support", "service", "billing", "alert", "ebayisapi", "webscr",
    "suspension", "re-login", "unlock", "recover", "validation", "token"
]

# Common top-level domains embedded inside subdomains to deceive victims
EMBEDDED_TLDS = [".com", ".net", ".org", ".gov", ".edu", ".co.uk", ".io"]

# IPv4 regex matching standard dotted-quad format
IPV4_REGEX = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)

# Hex/Octal IP address regex
HEX_OCT_IP_REGEX = re.compile(r"^(?:0x[0-9a-fA-F]+\.?|0[0-7]+\.?)+$")


def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy of a string."""
    if not text:
        return 0.0
    entropy = 0.0
    length = len(text)
    char_counts: Dict[str, int] = {}
    for char in text:
        char_counts[char] = char_counts.get(char, 0) + 1
    for count in char_counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 4)


class URLFeatureExtractor:
    """Extracts machine-learning features from a URL."""

    FEATURE_NAMES: List[str] = [
        "url_length",
        "hostname_length",
        "path_length",
        "query_length",
        "count_dots",
        "count_dots_hostname",
        "count_hyphens",
        "count_hyphens_hostname",
        "count_underscores",
        "count_slashes",
        "count_question_marks",
        "count_equals",
        "count_at",
        "count_exclamation",
        "count_percent",
        "count_ampersand",
        "count_subdomains",
        "has_ip",
        "is_https",
        "is_shortened",
        "suspicious_keyword_count",
        "shannon_entropy",
        "digit_count_hostname",
        "digit_ratio_hostname",
        "suspicious_tld",
        "hyphen_in_domain",
        "double_slash_redirect",
        "has_port",
        "tld_in_subdomain"
    ]

    @classmethod
    def get_feature_names(cls) -> List[str]:
        return list(cls.FEATURE_NAMES)

    @classmethod
    def extract_features(cls, raw_url: str) -> Dict[str, Any]:
        """
        Parses a URL and extracts numeric/boolean features for model inference.
        """
        url = (raw_url or "").strip()
        if not url:
            return {feature: 0 for feature in cls.FEATURE_NAMES}

        # Ensure scheme is present for urlparse
        has_scheme = bool(re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url))
        if not has_scheme:
            url_to_parse = "http://" + url
        else:
            url_to_parse = url

        try:
            parsed = urlparse(url_to_parse)
        except Exception:
            # Fallback for malformed URLs
            return {feature: 0 for feature in cls.FEATURE_NAMES}

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""
        query = parsed.query or ""
        url_lower = url.lower()

        # 1. Length features
        url_length = len(url)
        hostname_length = len(hostname)
        path_length = len(path)
        query_length = len(query)

        # 2. Character counts in full URL
        count_dots = url.count(".")
        count_hyphens = url.count("-")
        count_underscores = url.count("_")
        count_slashes = url.count("/")
        count_question_marks = url.count("?")
        count_equals = url.count("=")
        count_at = url.count("@")
        count_exclamation = url.count("!")
        count_percent = url.count("%")
        count_ampersand = url.count("&")

        # 3. Hostname-specific character counts
        count_dots_hostname = hostname.count(".")
        count_hyphens_hostname = hostname.count("-")

        # 4. Subdomain count
        # Typical host: sub2.sub1.domain.tld -> parts - 2
        host_parts = [p for p in hostname.split(".") if p]
        count_subdomains = max(0, len(host_parts) - 2) if len(host_parts) >= 2 else 0

        # 5. IP address detection
        clean_host = hostname.strip("[]")
        has_ip = 1 if (IPV4_REGEX.match(clean_host) or HEX_OCT_IP_REGEX.match(clean_host)) else 0

        # 6. HTTPS usage
        is_https = 1 if (parsed.scheme or "").lower() == "https" else 0

        # 7. URL shortener detection
        # Match either exact hostname or domain ending with known shortener
        is_shortened = 1 if any(hostname == s or hostname.endswith("." + s) for s in URL_SHORTENERS) else 0

        # 8. Suspicious keywords in URL path and query
        searchable_text = f"{path.lower()}?{query.lower()}#{parsed.fragment.lower()}"
        suspicious_keyword_count = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in searchable_text or kw in hostname)

        # 9. Shannon entropy of hostname
        shannon_entropy = calculate_entropy(hostname)

        # 10. Digit counts and ratios
        digit_count_hostname = sum(1 for c in hostname if c.isdigit())
        digit_ratio_hostname = round(digit_count_hostname / max(1, hostname_length), 4)

        # 11. Suspicious TLD detection
        tld = host_parts[-1] if host_parts else ""
        suspicious_tld = 1 if tld in SUSPICIOUS_TLDS else 0

        # 12. Hyphen in domain (brand spoofing indicator)
        hyphen_in_domain = 1 if "-" in hostname else 0

        # 13. Double slash redirection check in path
        double_slash_redirect = 1 if "//" in path else 0

        # 14. Non-standard port specified
        has_port = 1 if parsed.port and parsed.port not in (80, 443) else 0

        # 15. TLD embedded in subdomain (e.g. paypal.com.attacker.com)
        subdomain_part = ".".join(host_parts[:-2]) if len(host_parts) > 2 else ""
        tld_in_subdomain = 1 if any(tld_str in subdomain_part for tld_str in EMBEDDED_TLDS) else 0

        return {
            "url_length": url_length,
            "hostname_length": hostname_length,
            "path_length": path_length,
            "query_length": query_length,
            "count_dots": count_dots,
            "count_dots_hostname": count_dots_hostname,
            "count_hyphens": count_hyphens,
            "count_hyphens_hostname": count_hyphens_hostname,
            "count_underscores": count_underscores,
            "count_slashes": count_slashes,
            "count_question_marks": count_question_marks,
            "count_equals": count_equals,
            "count_at": count_at,
            "count_exclamation": count_exclamation,
            "count_percent": count_percent,
            "count_ampersand": count_ampersand,
            "count_subdomains": count_subdomains,
            "has_ip": has_ip,
            "is_https": is_https,
            "is_shortened": is_shortened,
            "suspicious_keyword_count": suspicious_keyword_count,
            "shannon_entropy": shannon_entropy,
            "digit_count_hostname": digit_count_hostname,
            "digit_ratio_hostname": digit_ratio_hostname,
            "suspicious_tld": suspicious_tld,
            "hyphen_in_domain": hyphen_in_domain,
            "double_slash_redirect": double_slash_redirect,
            "has_port": has_port,
            "tld_in_subdomain": tld_in_subdomain
        }

    @classmethod
    def extract_feature_vector(cls, raw_url: str) -> List[float]:
        """Returns ordered numerical feature vector matching FEATURE_NAMES."""
        features_dict = cls.extract_features(raw_url)
        return [float(features_dict[name]) for name in cls.FEATURE_NAMES]


def extract_url_features(url: str) -> Dict[str, Any]:
    """Helper functional wrapper for URLFeatureExtractor.extract_features."""
    return URLFeatureExtractor.extract_features(url)


def get_feature_names() -> List[str]:
    """Returns the ordered list of feature names."""
    return URLFeatureExtractor.get_feature_names()
