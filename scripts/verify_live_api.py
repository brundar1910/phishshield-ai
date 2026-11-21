"""
Live Verification Script for Phishing Detection Platform.
Starts server in background, executes real HTTP requests across all endpoints,
verifies database persistence, and reports findings.
"""

import time
import requests
import subprocess
import sys

BASE_URL = "http://127.0.0.1:8000"

def test_endpoints():
    print("Testing live API endpoints...")

    # 1. Health check
    r = requests.get(f"{BASE_URL}/api/health")
    assert r.status_code == 200, f"Health check failed: {r.text}"
    health = r.json()
    print(f"  [+] /api/health -> Status: {health['status']} | Model Loaded: {health['model_loaded']}")

    # 2. URL Scan (Phishing)
    payload_phish = {
        "url": "http://192.168.1.100/paypal/login.php?verification=token",
        "include_features": True
    }
    r = requests.post(f"{BASE_URL}/api/scan/url", json=payload_phish)
    assert r.status_code == 200, f"URL scan failed: {r.text}"
    phish_data = r.json()
    print(f"  [+] /api/scan/url (Phish) -> Verdict: {phish_data['verdict']} | Score: {phish_data['risk_score']}/100")
    assert phish_data["is_phishing"] is True
    assert phish_data["verdict"] in ["HIGH", "CRITICAL"]

    # 3. URL Scan (Benign)
    payload_benign = {
        "url": "https://www.google.com/search?q=machine+learning",
        "include_features": True
    }
    r = requests.post(f"{BASE_URL}/api/scan/url", json=payload_benign)
    assert r.status_code == 200, f"Benign scan failed: {r.text}"
    benign_data = r.json()
    print(f"  [+] /api/scan/url (Benign) -> Verdict: {benign_data['verdict']} | Score: {benign_data['risk_score']}/100")
    assert benign_data["is_phishing"] is False
    assert benign_data["verdict"] == "LOW"

    # 4. Email Scan
    payload_email = {
        "subject": "Urgent Action Required",
        "body": "Your account is compromised. Please verify your password immediately at http://192.168.1.100/paypal/login.php",
        "sender": "support@alert-notice.com"
    }
    r = requests.post(f"{BASE_URL}/api/scan/email", json=payload_email)
    assert r.status_code == 200, f"Email scan failed: {r.text}"
    email_data = r.json()
    print(f"  [+] /api/scan/email -> Verdict: {email_data['verdict']} | Score: {email_data['risk_score']}/100 | Links: {len(email_data['embedded_urls'])}")

    # 5. HTML Scan
    payload_html = {
        "base_url": "http://phish-site.cc",
        "html_content": '<form action="http://stealer.xyz/post" method="POST"><input type="password" name="p"/></form><iframe style="display:none;" src="http://hidden.cc"></iframe>'
    }
    r = requests.post(f"{BASE_URL}/api/scan/html", json=payload_html)
    assert r.status_code == 200, f"HTML scan failed: {r.text}"
    html_data = r.json()
    print(f"  [+] /api/scan/html -> Verdict: {html_data['verdict']} | Score: {html_data['risk_score']}/100 | Hidden IFrames: {html_data['hidden_iframes']}")

    # 6. Database Stats
    r = requests.get(f"{BASE_URL}/api/stats")
    assert r.status_code == 200, f"Stats failed: {r.text}"
    stats_data = r.json()
    print(f"  [+] /api/stats -> Total Logged Scans: {stats_data['total_scans']} | Avg Score: {stats_data['average_risk_score']}")
    assert stats_data["total_scans"] >= 3

    # 7. Metrics
    r = requests.get(f"{BASE_URL}/api/metrics")
    assert r.status_code == 200, f"Metrics failed: {r.text}"
    metrics_data = r.json()
    print(f"  [+] /api/metrics -> Champion Model: '{metrics_data['champion_model']}' | Test Samples: {metrics_data['test_sample_count']}")

    print("\n>>> ALL LIVE ENDPOINTS VERIFIED SUCCESSFULLY WITH 100% SUCCESS RATE! <<<")

def main():
    print("Launching Uvicorn server...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    try:
        # Wait for server to start
        for _ in range(20):
            try:
                r = requests.get(f"{BASE_URL}/api/health", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                time.sleep(0.5)
        else:
            print("Server failed to respond within 10 seconds")
            proc.terminate()
            sys.exit(1)

        test_endpoints()
    finally:
        print("Shutting down test server...")
        proc.terminate()
        proc.wait(timeout=5)

if __name__ == "__main__":
    main()
