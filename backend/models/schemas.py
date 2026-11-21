"""Pydantic schemas for Phishing Detection Multi-Modal API."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RiskVerdict(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Backward compatibility
ThreatLevel = RiskVerdict


class URLScanRequest(BaseModel):
    url: str = Field(..., description="The URL to analyze for phishing threats")
    include_features: bool = Field(default=True, description="Whether to include the raw 29-feature vector")


class URLScanResponse(BaseModel):
    url: str
    is_phishing: bool
    risk_score: int = Field(..., ge=0, le=100, description="Calibrated threat score from 0 (safe) to 100 (critical)")
    verdict: RiskVerdict
    threat_level: RiskVerdict  # Alias for backward compatibility
    confidence: float
    explanation: str
    heuristic_flags: List[str] = Field(default_factory=list)
    features: Optional[Dict[str, Any]] = None
    model_prediction: Optional[int] = None
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


class EmailScanRequest(BaseModel):
    subject: str = Field(default="", description="Email subject line")
    body: str = Field(..., description="Email body text or raw content")
    sender: str = Field(default="", description="Sender email address or header")


class EmbeddedURLResult(BaseModel):
    url: str
    risk_score: int
    verdict: RiskVerdict
    is_phishing: bool
    heuristic_flags: List[str] = Field(default_factory=list)


class EmailScanResponse(BaseModel):
    subject: str
    sender: str
    urgency_score: float
    credential_harvesting_detected: bool
    risk_score: int = Field(..., ge=0, le=100)
    verdict: RiskVerdict
    explanation: str
    urgency_matches: List[str] = Field(default_factory=list)
    credential_matches: List[str] = Field(default_factory=list)
    embedded_urls: List[EmbeddedURLResult] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


class HTMLScanRequest(BaseModel):
    html_content: str = Field(..., description="Raw HTML markup to analyze")
    base_url: str = Field(default="", description="Base website URL hosting this HTML")


class HTMLScanResponse(BaseModel):
    base_url: str
    forms_count: int
    hidden_iframes: int
    deceptive_links: int
    risk_score: int = Field(..., ge=0, le=100)
    verdict: RiskVerdict
    explanation: str
    flags: List[str] = Field(default_factory=list)
    forms: List[Dict[str, Any]] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


class ImageScanResponse(BaseModel):
    filename: str
    dimensions: Dict[str, int]
    average_color: List[float]
    color_variance: float
    risk_score: int = Field(..., ge=0, le=100)
    verdict: RiskVerdict
    explanation: str
    visual_flags: List[str] = Field(default_factory=list)
    scan_timestamp: datetime = Field(default_factory=datetime.utcnow)


class StatsResponse(BaseModel):
    total_scans: int
    verdicts: Dict[str, int]
    scan_types: Dict[str, int]
    average_risk_score: float
    top_heuristic_flags: List[Dict[str, Any]]


class ModelMetricsResponse(BaseModel):
    test_sample_count: int
    test_class_distribution: Dict[str, int]
    champion_model: str
    models: Dict[str, Any]
