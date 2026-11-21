"""
Unified Multi-Modal Phishing Detection Engine.
Combines Machine Learning inference, 29-feature URL extraction, domain reputation intelligence,
HTML/DOM inspection, NLP sentiment & urgency analysis, and visual image inspection into a
calibrated risk-scoring pipeline (0-100) with Low/Medium/High/Critical verdicts and human-readable explanations.
"""

from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import joblib

from backend.feature_extraction.url_features import URLFeatureExtractor
from backend.html_analyzer.analyzer import HTMLPhishingAnalyzer
from backend.models.schemas import (
    EmailScanResponse,
    EmbeddedURLResult,
    HTMLScanResponse,
    ImageScanResponse,
    RiskVerdict,
    URLScanResponse,
)
from backend.nlp.content_analyzer import PhishingNLPAnalyzer
from backend.ocr.image_analyzer import VisualPhishingAnalyzer
from backend.services.reputation import ReputationService

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
DEFAULT_MODELS_DIR = ROOT_DIR / "ml" / "saved_models"

URL_REGEX = re.compile(r"https?://[^\s<>\"'()]+|www\.[^\s<>\"'()]+")


def compute_verdict(risk_score: int) -> RiskVerdict:
    """Maps numerical risk score (0-100) to standard RiskVerdict."""
    if risk_score >= 85:
        return RiskVerdict.CRITICAL
    elif risk_score >= 60:
        return RiskVerdict.HIGH
    elif risk_score >= 30:
        return RiskVerdict.MEDIUM
    return RiskVerdict.LOW


class DetectionEngine:
    """Unified Detection Engine coordinating multi-modal threat analyzers."""

    def __init__(self, model_dir: Path = DEFAULT_MODELS_DIR):
        self.model_dir = Path(model_dir)
        self.scaler = None
        self.model = None
        self.load_artifacts()

    def load_artifacts(self):
        """Loads fitted scaler and champion model."""
        scaler_path = self.model_dir / "scaler.joblib"
        model_path = self.model_dir / "best_model.joblib"

        if scaler_path.exists():
            self.scaler = joblib.load(str(scaler_path))
        if model_path.exists():
            self.model = joblib.load(str(model_path))

    def evaluate_heuristics(self, features: Dict[str, Any]) -> List[str]:
        """Flags specific known attack techniques based on extracted features."""
        flags = []
        if features.get("has_ip", 0) == 1:
            flags.append("Host is an IP address instead of a domain name")
        if features.get("is_shortened", 0) == 1:
            flags.append("Uses a known URL shortening service to obscure destination")
        if features.get("suspicious_tld", 0) == 1:
            flags.append("Domain utilizes a high-abuse/suspicious Top Level Domain")
        if features.get("tld_in_subdomain", 0) == 1:
            flags.append("Subdomain embeds a deceptive top-level domain (brand spoofing)")
        if features.get("double_slash_redirect", 0) == 1:
            flags.append("URL path contains double slash (//) redirect evasion pattern")
        if features.get("suspicious_keyword_count", 0) >= 2:
            flags.append(f"Multiple high-risk credential keywords detected ({features['suspicious_keyword_count']})")
        if features.get("is_https", 0) == 0:
            flags.append("Insecure connection: HTTP protocol without SSL/TLS encryption")
        if features.get("hyphen_in_domain", 0) == 1:
            flags.append("Domain contains hyphens commonly used in lookalike typosquatting")
        if features.get("has_port", 0) == 1:
            flags.append("Specifies a non-standard port number")
        return flags

    def scan_url(self, url: str, include_features: bool = True) -> URLScanResponse:
        """Performs full ML + heuristic threat scan on a single URL."""
        clean_url = (url or "").strip()
        features = URLFeatureExtractor.extract_features(clean_url)
        heuristic_flags = self.evaluate_heuristics(features)
        reputation = ReputationService.check_domain_reputation(clean_url)

        ml_prob = 0.0
        ml_pred = 0

        if self.model and self.scaler:
            feature_vector = URLFeatureExtractor.extract_feature_vector(clean_url)
            scaled_vector = self.scaler.transform([feature_vector])
            if hasattr(self.model, "predict_proba"):
                probs = self.model.predict_proba(scaled_vector)[0]
                ml_prob = float(probs[1])
                ml_pred = int(probs[1] >= 0.5)
            else:
                ml_pred = int(self.model.predict(scaled_vector)[0])
                ml_prob = 1.0 if ml_pred == 1 else 0.0

        # Calculate calibrated 0-100 score
        base_score = ml_prob * 80.0  # Up to 80 points from ML model
        heuristic_penalty = len(heuristic_flags) * 10.0  # Up to 10 points per flag

        # Critical triggers that immediately raise threat level
        if features.get("has_ip", 0) == 1 or features.get("tld_in_subdomain", 0) == 1:
            heuristic_penalty += 20.0

        raw_score = base_score + heuristic_penalty

        # Whitelist suppression: verified trusted domains capped to safe range
        if reputation.get("is_whitelisted", False) and features.get("has_ip", 0) == 0:
            raw_score = min(raw_score * 0.15, 20.0)

        risk_score = int(max(0, min(100, round(raw_score))))
        verdict = compute_verdict(risk_score)
        is_phishing = verdict in [RiskVerdict.HIGH, RiskVerdict.CRITICAL]

        # Generate human-readable explanation
        explanation_parts = []
        if reputation.get("is_whitelisted", False):
            explanation_parts.append(f"Domain '{reputation['hostname']}' is a recognized high-reputation domain.")
        if ml_pred == 1:
            explanation_parts.append(f"AI classifier flagged lexical and structural patterns as phishing with {ml_prob * 100:.1f}% model confidence.")
        if heuristic_flags:
            explanation_parts.append(f"Identified {len(heuristic_flags)} security risk indicator(s): {'; '.join(heuristic_flags[:3])}.")
        if not explanation_parts:
            explanation_parts.append("URL exhibits standard benign characteristics with valid structure and no suspicious patterns.")

        explanation = " ".join(explanation_parts)

        return URLScanResponse(
            url=clean_url,
            is_phishing=is_phishing,
            risk_score=risk_score,
            verdict=verdict,
            threat_level=verdict,
            confidence=round(ml_prob, 4),
            explanation=explanation,
            heuristic_flags=heuristic_flags,
            features=features if include_features else None,
            model_prediction=ml_pred,
        )

    def scan_email(self, subject: str, body: str, sender: str = "") -> EmailScanResponse:
        """Analyzes email text for urgency, credential demands, and embedded malicious links."""
        full_text = f"{subject}\n{body}"
        nlp_res = PhishingNLPAnalyzer.analyze_text(full_text)

        # Extract embedded URLs
        extracted_urls = URL_REGEX.findall(full_text)
        embedded_results = []
        highest_url_score = 0

        for raw_u in extracted_urls[:5]:  # Analyze up to top 5 links
            clean_u = raw_u.strip(".,;:)>\"'")
            if clean_u:
                url_scan = self.scan_url(clean_u, include_features=False)
                embedded_results.append(EmbeddedURLResult(
                    url=clean_u,
                    risk_score=url_scan.risk_score,
                    verdict=url_scan.verdict,
                    is_phishing=url_scan.is_phishing,
                    heuristic_flags=url_scan.heuristic_flags,
                ))
                if url_scan.risk_score > highest_url_score:
                    highest_url_score = url_scan.risk_score

        # Combine NLP urgency/credential demands with embedded link scores
        nlp_risk = int(nlp_res["phishing_text_score"] * 60)
        link_risk = int(highest_url_score * 0.6)

        total_risk = max(nlp_risk, link_risk)
        if nlp_res["credential_harvesting_detected"] and highest_url_score >= 50:
            total_risk = min(100, total_risk + 25)

        total_risk = max(0, min(100, total_risk))
        verdict = compute_verdict(total_risk)

        # Human-readable explanation
        explanations = []
        if nlp_res["credential_harvesting_detected"]:
            explanations.append("Detected explicit demands for passwords, credentials, or billing details.")
        if nlp_res["urgency_matches"]:
            explanations.append(f"Identified high-pressure urgency triggers: '{', '.join(nlp_res['urgency_matches'][:3])}'.")
        if highest_url_score >= 60:
            explanations.append(f"Email contains high-risk embedded links (Peak URL risk: {highest_url_score}/100).")
        if not explanations:
            explanations.append("Email text does not contain typical phishing urgency or credential prompts.")

        return EmailScanResponse(
            subject=subject,
            sender=sender,
            urgency_score=nlp_res["urgency_score"],
            credential_harvesting_detected=nlp_res["credential_harvesting_detected"],
            risk_score=total_risk,
            verdict=verdict,
            explanation=" ".join(explanations),
            urgency_matches=nlp_res["urgency_matches"],
            credential_matches=nlp_res["credential_matches"],
            embedded_urls=embedded_results,
        )

    def scan_html(self, html_content: str, base_url: str = "") -> HTMLScanResponse:
        """Analyzes HTML markup for malicious form targets, hidden iframes, and deceptive links."""
        analysis = HTMLPhishingAnalyzer.analyze_html(html_content, base_url=base_url)

        base_url_score = 0
        if base_url:
            url_res = self.scan_url(base_url, include_features=False)
            base_url_score = url_res.risk_score

        dom_score = int(analysis["risk_score"] * 70)
        combined_score = max(dom_score, int(base_url_score * 0.5))

        if analysis["hidden_iframes"] > 0:
            combined_score += 15
        if analysis["deceptive_links"] > 0:
            combined_score += 20

        risk_score = max(0, min(100, combined_score))
        verdict = compute_verdict(risk_score)

        explanations = []
        if analysis["flags"]:
            explanations.append(f"DOM inspection flagged: {'; '.join(analysis['flags'][:3])}.")
        if base_url and base_url_score >= 60:
            explanations.append(f"Associated host URL '{base_url}' carries high threat level ({base_url_score}/100).")
        if not explanations:
            explanations.append("HTML structure contains standard forms and safe internal hyperlinks.")

        return HTMLScanResponse(
            base_url=base_url,
            forms_count=analysis["forms_count"],
            hidden_iframes=analysis["hidden_iframes"],
            deceptive_links=analysis["deceptive_links"],
            risk_score=risk_score,
            verdict=verdict,
            explanation=" ".join(explanations),
            flags=analysis["flags"],
            forms=analysis["forms"],
        )

    def scan_image(self, image_bytes: bytes, filename: str = "screenshot.png") -> ImageScanResponse:
        """Inspects webpage screenshot / logo for visual phishing form characteristics."""
        visual_res = VisualPhishingAnalyzer.analyze_image_array(image_bytes)

        risk_score = 10
        visual_flags = []

        if not visual_res.get("is_processed", False):
            return ImageScanResponse(
                filename=filename,
                dimensions={"width": 0, "height": 0},
                average_color=[0.0, 0.0, 0.0],
                color_variance=0.0,
                risk_score=0,
                verdict=RiskVerdict.LOW,
                explanation="Failed to parse image bytes as valid graphic data.",
                visual_flags=["Invalid image format"],
            )

        variance = visual_res.get("color_variance", 50.0)
        # Low color variance (< 15) indicates flat credential dialog overlay
        if variance < 15.0:
            risk_score += 40
            visual_flags.append("Low color variance indicates modal overlay dialog often used in login prompts")

        dims = visual_res.get("dimensions", {"width": 0, "height": 0})
        # Standard login modal aspect ratio check (square or 4:3 box)
        if dims["width"] > 0 and dims["height"] > 0:
            ratio = dims["width"] / dims["height"]
            if 0.8 <= ratio <= 1.5:
                risk_score += 20
                visual_flags.append("Image aspect ratio matches typical credential modal card")

        risk_score = max(0, min(100, risk_score))
        verdict = compute_verdict(risk_score)

        explanation = f"Analyzed screenshot ({dims['width']}x{dims['height']} px, variance: {variance})."
        if visual_flags:
            explanation += f" Visual alerts: {'; '.join(visual_flags)}."
        else:
            explanation += " No high-risk visual modal anomalies identified."

        return ImageScanResponse(
            filename=filename,
            dimensions=dims,
            average_color=visual_res.get("average_color", [0.0, 0.0, 0.0]),
            color_variance=variance,
            risk_score=risk_score,
            verdict=verdict,
            explanation=explanation,
            visual_flags=visual_flags,
        )
