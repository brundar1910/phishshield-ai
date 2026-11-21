"""HTML DOM and Structural Content Analyzer for Phishing Detection."""

from typing import Any, Dict, List
from urllib.parse import urlparse
from bs4 import BeautifulSoup


class HTMLPhishingAnalyzer:
    """Analyzes web page DOM structure and forms for credential harvesting techniques."""

    @staticmethod
    def analyze_html(html_content: str, base_url: str = "") -> Dict[str, Any]:
        """Parses HTML and extracts security risk indicators."""
        soup = BeautifulSoup(html_content, "html.parser")
        flags = []
        base_domain = ""

        if base_url:
            parsed = urlparse(base_url if "://" in base_url else "http://" + base_url)
            base_domain = (parsed.hostname or "").lower()

        # 1. Form Action Analysis
        forms = soup.find_all("form")
        form_details = []
        has_external_action = False
        has_insecure_submission = False

        for form in forms:
            action = (form.get("action") or "").strip()
            inputs = form.find_all("input")
            has_password = any(i.get("type", "").lower() == "password" for i in inputs)

            if action.startswith("http://"):
                has_insecure_submission = True
                flags.append("Form submits sensitive data over unencrypted HTTP")

            if action.startswith("http://") or action.startswith("https://"):
                parsed_action = urlparse(action)
                action_domain = (parsed_action.hostname or "").lower()
                if base_domain and action_domain and base_domain != action_domain:
                    has_external_action = True
                    flags.append(f"Form action points to external foreign domain: {action_domain}")

            form_details.append({
                "action": action,
                "has_password": has_password,
                "inputs_count": len(inputs)
            })

        # 2. Hidden IFrames
        iframes = soup.find_all("iframe")
        hidden_iframes = 0
        for iframe in iframes:
            style = (iframe.get("style") or "").lower()
            width = iframe.get("width", "")
            height = iframe.get("height", "")
            if "display:none" in style or "visibility:hidden" in style or width in ["0", "1"] or height in ["0", "1"]:
                hidden_iframes += 1

        if hidden_iframes > 0:
            flags.append(f"Detected {hidden_iframes} hidden or zero-dimension iframe(s)")

        # 3. Deceptive Hyperlinks (anchor text != target URL)
        deceptive_links = 0
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            text = a.get_text(strip=True)
            if "http://" in text or "https://" in text:
                if href and text != href:
                    deceptive_links += 1

        if deceptive_links > 0:
            flags.append(f"Detected {deceptive_links} deceptive hyperlinks with mismatched anchor text")

        risk_score = min(1.0, len(flags) * 0.3)

        return {
            "risk_score": round(risk_score, 2),
            "is_suspicious": risk_score >= 0.5,
            "flags": flags,
            "forms_count": len(forms),
            "hidden_iframes": hidden_iframes,
            "deceptive_links": deceptive_links,
            "forms": form_details
        }
