"""
Unit tests for the URL Feature Extraction Engine.
Validates extraction of lexical, domain, structural, and entropy features across benign,
phishing, IP-based, shortened, and malformed URLs.
"""

import pytest
from backend.feature_extraction.url_features import (
    URLFeatureExtractor,
    calculate_entropy,
    extract_url_features,
    get_feature_names,
)


class TestURLFeatureExtractor:
    """Test suite for URLFeatureExtractor methods."""

    def test_feature_names_count_and_uniqueness(self):
        """Ensures all 29 expected features are present and unique."""
        names = get_feature_names()
        assert len(names) == 29
        assert len(names) == len(set(names)), "Feature names must be unique"
        assert "has_ip" in names
        assert "is_shortened" in names
        assert "shannon_entropy" in names
        assert "suspicious_keyword_count" in names
        assert "count_subdomains" in names

    def test_benign_url_features(self):
        """Verifies feature extraction on standard benign URLs."""
        url = "https://www.google.com/search?q=machine+learning"
        features = extract_url_features(url)

        assert features["is_https"] == 1
        assert features["has_ip"] == 0
        assert features["is_shortened"] == 0
        assert features["has_port"] == 0
        assert features["double_slash_redirect"] == 0
        assert features["count_dots"] == 2
        assert features["hostname_length"] == len("www.google.com")
        assert features["url_length"] == len(url)
        assert features["suspicious_tld"] == 0

    def test_ip_address_url_detection(self):
        """Verifies accurate detection of IPv4 hostnames."""
        url_ip = "http://192.168.1.105/paypal/login.php"
        features = extract_url_features(url_ip)

        assert features["has_ip"] == 1
        assert features["is_https"] == 0
        assert features["suspicious_keyword_count"] >= 1  # 'login'

        # Obfuscated / standard IP without scheme
        url_ip_no_scheme = "10.0.0.1:8080/secure-update"
        features_no_scheme = extract_url_features(url_ip_no_scheme)
        assert features_no_scheme["has_ip"] == 1
        assert features_no_scheme["has_port"] == 1

    def test_url_shortener_detection(self):
        """Verifies detection of known URL shortening domains."""
        short_urls = [
            "https://bit.ly/3xY9Qz",
            "http://tinyurl.com/bank-alert",
            "http://t.co/xyz123",
            "https://is.gd/updateacc",
        ]
        for url in short_urls:
            features = extract_url_features(url)
            assert features["is_shortened"] == 1, f"Expected {url} to be detected as shortened"

    def test_suspicious_keywords_and_tlds(self):
        """Tests counting of phishing keywords and suspicious TLD flags."""
        url = "http://secure-account-verification.login-portal.xyz/billing/token"
        features = extract_url_features(url)

        assert features["suspicious_tld"] == 1  # .xyz
        assert features["suspicious_keyword_count"] >= 3  # secure, verification, login, billing, token
        assert features["hyphen_in_domain"] == 1
        assert features["is_https"] == 0

    def test_subdomain_abuse_and_embedded_tlds(self):
        """Tests detection of brand spoofing via embedded TLDs in subdomains."""
        url = "http://paypal.com.account-update.attacker-domain.com/login"
        features = extract_url_features(url)

        assert features["count_subdomains"] >= 2
        assert features["tld_in_subdomain"] == 1

    def test_double_slash_redirection(self):
        """Detects double slash redirect evasions in URL path."""
        url = "http://legitimate-bank.com//phishing-destination.com"
        features = extract_url_features(url)
        assert features["double_slash_redirect"] == 1

    def test_entropy_calculation(self):
        """Validates Shannon entropy properties."""
        low_entropy = calculate_entropy("aaaaaaa")
        high_entropy = calculate_entropy("a1b2c3d4e5f6g7")
        empty_entropy = calculate_entropy("")

        assert empty_entropy == 0.0
        assert low_entropy == 0.0
        assert high_entropy > 3.0

    def test_empty_and_malformed_urls(self):
        """Ensures extractor handles empty, None, and edge-case inputs gracefully."""
        features_empty = extract_url_features("")
        assert all(val == 0 for val in features_empty.values())

        features_spaces = extract_url_features("   ")
        assert all(val == 0 for val in features_spaces.values())

        vector = URLFeatureExtractor.extract_feature_vector("https://github.com")
        assert len(vector) == len(get_feature_names())
        assert isinstance(vector, list)
        assert all(isinstance(x, (float, int)) for x in vector)
