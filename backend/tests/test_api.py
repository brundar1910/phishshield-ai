"""
Integration tests for all FastAPI endpoints.
Tests /api/scan/url, /api/scan/email, /api/scan/html, /api/scan/image,
/api/history, /api/stats, /api/metrics, /api/health, and /Dashboard.html.
"""

import io
from fastapi.testclient import TestClient
from PIL import Image
import pytest

from backend.main import app

client = TestClient(app)


def test_root_endpoint():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "Phishing Detection AI Platform" in data["system"]
    assert "/api/scan" in data["api_scan"]


def test_dashboard_endpoints():
    r1 = client.get("/Dashboard.html")
    assert r1.status_code == 200
    assert "PHISHSHIELD" in r1.text
    assert "Live URL Security & ML Classifier" in r1.text
    assert "/api/scan/url" in r1.text

    r2 = client.get("/dashboard/Dashboard.html")
    assert r2.status_code == 200
    assert "PHISHSHIELD" in r2.text


def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["model_loaded"] is True
    assert "multi_modal_support" in data
    assert "url" in data["multi_modal_support"]


def test_metrics_endpoint():
    response = client.get("/api/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "models" in data
    assert "logistic_regression" in data["models"]
    assert "random_forest" in data["models"]
    assert "xgboost" in data["models"]


def test_scan_url_endpoint_benign():
    payload = {"url": "https://www.google.com/search?q=cybersecurity", "include_features": True}
    response = client.post("/api/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["url"] == payload["url"]
    assert data["verdict"] == "LOW"
    assert data["risk_score"] < 30
    assert "google.com" in data["explanation"].lower() or "benign" in data["explanation"].lower()


def test_scan_url_endpoint_phishing():
    payload = {"url": "http://192.168.1.100/paypal/login.php?verification=token", "include_features": True}
    response = client.post("/api/scan/url", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 60
    assert data["verdict"] in ["HIGH", "CRITICAL"]
    assert data["is_phishing"] is True
    assert len(data["heuristic_flags"]) > 0


def test_scan_url_empty_validation():
    response = client.post("/api/scan/url", json={"url": "   "})
    assert response.status_code == 400


def test_scan_email_endpoint():
    payload = {
        "subject": "URGENT: Suspended Account",
        "body": "Security Alert! Your account is suspended within 24 hours. Update credentials at http://192.168.1.100/paypal/login.php",
        "sender": "alert@fake-paypal.xyz"
    }
    response = client.post("/api/scan/email", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["risk_score"] >= 50
    assert data["verdict"] in ["MEDIUM", "HIGH", "CRITICAL"]
    assert len(data["embedded_urls"]) >= 1
    assert data["credential_harvesting_detected"] is True


def test_scan_html_endpoint():
    payload = {
        "base_url": "http://suspicious-site.top",
        "html_content": '<form action="http://foreign-site.com/login" method="POST"><input type="password" name="pw"/></form><iframe style="display:none;" src="http://hidden.cc"></iframe>'
    }
    response = client.post("/api/scan/html", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["hidden_iframes"] >= 1
    assert data["forms_count"] >= 1
    assert len(data["flags"]) >= 1


def test_scan_image_endpoint():
    # Create simple in-memory PNG
    img = Image.new("RGB", (300, 250), color=(240, 240, 240))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format="PNG")
    img_bytes = img_byte_arr.getvalue()

    files = {"file": ("screenshot.png", img_bytes, "image/png")}
    response = client.post("/api/scan/image", files=files)
    assert response.status_code == 200
    data = response.json()
    assert data["filename"] == "screenshot.png"
    assert data["dimensions"]["width"] == 300
    assert data["dimensions"]["height"] == 250
    assert 0 <= data["risk_score"] <= 100


def test_history_endpoint():
    response = client.get("/api/history?limit=10")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) >= 1


def test_stats_endpoint():
    response = client.get("/api/stats")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert data["total_scans"] >= 1
    assert "verdicts" in data
    assert "scan_types" in data
    assert "average_risk_score" in data
