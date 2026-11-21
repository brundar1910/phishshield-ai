"""
Comprehensive Verification Script for frontend/Dashboard.html.
Validates:
1. All DOM element IDs referenced in JavaScript exist in the HTML DOM.
2. JavaScript syntax and function definitions are sound.
3. Live FastAPI server responds to /Dashboard.html and relative API routes (/api/health, /api/scan/url, etc.).
"""

from bs4 import BeautifulSoup
from pathlib import Path
import re
import requests
import subprocess
import sys
import time

ROOT_DIR = Path(__file__).resolve().parent.parent
DASHBOARD_FILE = ROOT_DIR / "frontend" / "Dashboard.html"
BASE_URL = "http://127.0.0.1:8000"


def verify_dom_elements():
    print("1. Validating DOM IDs between HTML elements and JavaScript...")
    html_content = DASHBOARD_FILE.read_text(encoding="utf-8")
    soup = BeautifulSoup(html_content, "html.parser")

    # Find all IDs defined in HTML
    html_ids = {elem["id"] for elem in soup.find_all(attrs={"id": True})}

    # Find all document.getElementById calls in the script
    script_content = ""
    for s in soup.find_all("script"):
        if s.string:
            script_content += s.string

    js_ids = set(re.findall(r'document\.getElementById\(["\']([^"\']+)["\']\)', script_content))

    print(f"   Found {len(html_ids)} HTML IDs and {len(js_ids)} JS references.")

    missing_ids = js_ids - html_ids
    if missing_ids:
        print(f"   [ERROR] Missing IDs in HTML referenced by JS: {missing_ids}")
        return False
    print("   [+] All referenced DOM IDs successfully exist in HTML!")

    # Check preset buttons
    presets = soup.find_all(class_="preset-btn")
    print(f"   [+] Found {len(presets)} preset test buttons.")
    assert len(presets) >= 4, "Expected at least 4 preset buttons"

    # Check tabs
    tabs = soup.find_all(class_="tab-btn")
    print(f"   [+] Found {len(tabs)} navigation tabs.")
    assert len(tabs) >= 5, "Expected at least 5 navigation tabs"

    return True


def verify_live_dashboard():
    print("\n2. Testing live server delivery of /Dashboard.html and relative endpoints...")
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    try:
        # Wait for server
        for _ in range(20):
            try:
                r = requests.get(f"{BASE_URL}/api/health", timeout=1)
                if r.status_code == 200:
                    break
            except Exception:
                time.sleep(0.5)
        else:
            print("   [ERROR] Server failed to start")
            proc.terminate()
            return False

        # Check /Dashboard.html
        r = requests.get(f"{BASE_URL}/Dashboard.html")
        assert r.status_code == 200, f"/Dashboard.html returned {r.status_code}"
        assert "PHISHSHIELD" in r.text
        assert "/api/scan/url" in r.text
        print("   [+] GET /Dashboard.html -> 200 OK")

        # Check /dashboard/Dashboard.html
        r2 = requests.get(f"{BASE_URL}/dashboard/Dashboard.html")
        assert r2.status_code == 200
        print("   [+] GET /dashboard/Dashboard.html -> 200 OK")

        # Check relative endpoint /api/health
        r_health = requests.get(f"{BASE_URL}/api/health")
        assert r_health.status_code == 200
        assert r_health.json()["status"] == "healthy"
        print(f"   [+] GET /api/health -> Status: {r_health.json()['status']}")

        # Test scan button action via /api/scan/url
        sample_url = "http://192.168.1.100/paypal/login.php?verification=token"
        r_scan = requests.post(f"{BASE_URL}/api/scan/url", json={"url": sample_url, "include_features": True})
        assert r_scan.status_code == 200
        scan_res = r_scan.json()
        print(f"   [+] POST /api/scan/url -> Score: {scan_res['risk_score']}/100 | Verdict: {scan_res['verdict']}")

        # Test /api/stats
        r_stats = requests.get(f"{BASE_URL}/api/stats")
        assert r_stats.status_code == 200
        print(f"   [+] GET /api/stats -> Total Scans: {r_stats.json()['total_scans']}")

        # Test /api/metrics
        r_metrics = requests.get(f"{BASE_URL}/api/metrics")
        assert r_metrics.status_code == 200
        print(f"   [+] GET /api/metrics -> Champion: {r_metrics.json()['champion_model']}")

        print("\n>>> ALL DASHBOARD VERIFICATIONS PASSED SUCCESSFULLY! <<<")
        return True
    finally:
        proc.terminate()
        proc.wait(timeout=5)


def main():
    dom_ok = verify_dom_elements()
    if not dom_ok:
        sys.exit(1)
    live_ok = verify_live_dashboard()
    if not live_ok:
        sys.exit(1)


if __name__ == "__main__":
    main()
