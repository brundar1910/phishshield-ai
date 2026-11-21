"""FastAPI Route Handlers for Phishing Detection Multi-Modal Platform."""

import json
from pathlib import Path
from typing import Optional
from fastapi import APIRouter, File, HTTPException, Query, UploadFile

from backend.database.db import get_recent_scans, get_scan_stats, log_scan
from backend.detection.engine import DetectionEngine
from backend.models.schemas import (
    EmailScanRequest,
    EmailScanResponse,
    HTMLScanRequest,
    HTMLScanResponse,
    ImageScanResponse,
    StatsResponse,
    URLScanRequest,
    URLScanResponse,
)

router = APIRouter()
engine = DetectionEngine()

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
METRICS_PATH = ROOT_DIR / "ml" / "saved_models" / "metrics.json"


@router.post("/scan/url", response_model=URLScanResponse)
@router.post("/scan", response_model=URLScanResponse)
def scan_url(request: URLScanRequest):
    """Analyzes a URL for phishing using ML inference, 29 engineered features, and heuristics."""
    if not request.url or not request.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    response = engine.scan_url(request.url, include_features=request.include_features)

    try:
        log_scan(
            scan_type="url",
            target=response.url,
            risk_score=response.risk_score,
            verdict=response.verdict.value,
            confidence=response.confidence,
            explanation=response.explanation,
            heuristic_flags=response.heuristic_flags,
        )
    except Exception as e:
        print(f"[WARN] Failed to log URL scan to DB: {e}")

    return response


@router.post("/scan/email", response_model=EmailScanResponse)
def scan_email(request: EmailScanRequest):
    """Analyzes email text for urgency triggers, credential demands, and embedded links."""
    if not request.body or not request.body.strip():
        raise HTTPException(status_code=400, detail="Email body text cannot be empty")

    response = engine.scan_email(subject=request.subject, body=request.body, sender=request.sender)

    try:
        log_scan(
            scan_type="email",
            target=request.subject or (request.body[:60] + "..."),
            risk_score=response.risk_score,
            verdict=response.verdict.value,
            confidence=response.urgency_score,
            explanation=response.explanation,
            heuristic_flags=response.urgency_matches + response.credential_matches,
        )
    except Exception as e:
        print(f"[WARN] Failed to log email scan to DB: {e}")

    return response


@router.post("/scan/html", response_model=HTMLScanResponse)
def scan_html(request: HTMLScanRequest):
    """Analyzes HTML markup for deceptive forms, hidden iframes, and external targets."""
    if not request.html_content or not request.html_content.strip():
        raise HTTPException(status_code=400, detail="HTML content cannot be empty")

    response = engine.scan_html(html_content=request.html_content, base_url=request.base_url)

    try:
        log_scan(
            scan_type="html",
            target=request.base_url or f"HTML snippet ({len(request.html_content)} chars)",
            risk_score=response.risk_score,
            verdict=response.verdict.value,
            confidence=response.risk_score / 100.0,
            explanation=response.explanation,
            heuristic_flags=response.flags,
        )
    except Exception as e:
        print(f"[WARN] Failed to log HTML scan to DB: {e}")

    return response


@router.post("/scan/image", response_model=ImageScanResponse)
async def scan_image(file: UploadFile = File(...)):
    """Inspects a webpage screenshot or image for visual credential harvesting patterns."""
    if not file or not file.filename:
        raise HTTPException(status_code=400, detail="Valid image file must be uploaded")

    contents = await file.read()
    if len(contents) == 0:
        raise HTTPException(status_code=400, detail="Uploaded image is empty")

    response = engine.scan_image(image_bytes=contents, filename=file.filename)

    try:
        log_scan(
            scan_type="image",
            target=file.filename,
            risk_score=response.risk_score,
            verdict=response.verdict.value,
            confidence=response.risk_score / 100.0,
            explanation=response.explanation,
            heuristic_flags=response.visual_flags,
        )
    except Exception as e:
        print(f"[WARN] Failed to log image scan to DB: {e}")

    return response


@router.get("/history")
def get_scan_history(limit: int = 50, scan_type: Optional[str] = Query(None, description="Optional scan type filter")):
    """Returns recent scan results from the database."""
    return get_recent_scans(limit=limit, scan_type=scan_type)


@router.get("/stats", response_model=StatsResponse)
def get_system_stats():
    """Returns real-time aggregated security statistics and verdict counts."""
    return get_scan_stats()


@router.get("/metrics")
def get_model_metrics():
    """Retrieves verified ML benchmark metrics calculated on the isolated test set."""
    if not METRICS_PATH.exists():
        raise HTTPException(status_code=404, detail="Metrics file not found. Run evaluation pipeline first.")
    with open(METRICS_PATH, "r", encoding="utf-8") as f:
        metrics = json.load(f)
    return metrics


@router.get("/health")
def health_check():
    """Returns operational status, model availability, and feature extractor configuration."""
    model_loaded = engine.model is not None
    scaler_loaded = engine.scaler is not None
    return {
        "status": "healthy" if (model_loaded and scaler_loaded) else "degraded",
        "model_loaded": model_loaded,
        "scaler_loaded": scaler_loaded,
        "features_count": 29,
        "champion_model": "logistic_regression" if model_loaded else None,
        "multi_modal_support": ["url", "email", "html", "image"]
    }
