"""
Pydantic schemas for forensic analysis results and telemetry.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AuthResultItem(BaseModel):
    status: str = "Unknown"  # Pass, Fail, None, Unknown
    evidence: str = "No authentication header detected."
    details: Dict[str, Any] = Field(default_factory=dict)


class AuthenticationSummary(BaseModel):
    spf: AuthResultItem = Field(default_factory=AuthResultItem)
    dkim: AuthResultItem = Field(default_factory=AuthResultItem)
    dmarc: AuthResultItem = Field(default_factory=AuthResultItem)
    header_trust_score: int = 100
    evidence_notes: List[str] = Field(default_factory=list)


class SenderAnalysis(BaseModel):
    from_header: str = ""
    display_name: str = ""
    from_address: str = ""
    from_domain: str = ""
    reply_to: str = ""
    return_path: str = ""
    sender: str = ""
    from_reply_to_mismatch: bool = False
    from_return_path_mismatch: bool = False
    display_name_deception: bool = False
    is_punycode: bool = False
    is_free_provider: bool = False
    suspicious_domain_patterns: List[str] = Field(default_factory=list)
    risk_level: str = "SAFE"
    evidence: List[str] = Field(default_factory=list)


class RoutingHop(BaseModel):
    hop_number: int
    timestamp: Optional[str] = None
    from_hostname: str = ""
    from_ip: str = ""
    by_hostname: str = ""
    by_ip: str = ""
    ip_classification: str = "unknown"  # public, private, loopback, documentation, etc.
    is_public: bool = False
    country: str = "Unknown"
    city: str = "Unknown"
    region: str = "Unknown"
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: str = "Unknown"
    organization: str = "Unknown"
    asn: str = "Unknown"
    ordering_confidence: str = "High"  # High, Medium, Low
    suspicious: bool = False
    evidence: str = ""
    provider_status: str = "local_heuristic"  # active, local_heuristic, unavailable


class RouteStats(BaseModel):
    total_hops: int = 0
    public_hops: int = 0
    countries_traversed: List[str] = Field(default_factory=list)
    unique_asns: List[str] = Field(default_factory=list)
    approximate_distance_km: float = 0.0
    longest_jump_km: float = 0.0


class URLItem(BaseModel):
    full_url: str
    scheme: str = ""
    hostname: str = ""
    port: Optional[int] = None
    path: str = ""
    query: str = ""
    display_text: str = ""
    risk: int = 0  # 0 - 100
    risk_level: str = "SAFE"  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    reason: str = ""
    evidence: List[str] = Field(default_factory=list)
    is_ip_based: bool = False
    is_shortener: bool = False
    is_punycode: bool = False
    anchor_mismatch: bool = False


class AttachmentItem(BaseModel):
    filename: str
    extension: str
    mime_type: str
    size_bytes: int
    sha256: str
    sha1: Optional[str] = None
    md5: Optional[str] = None
    suspicious: bool = False
    risk_level: str = "SAFE"
    reason: str = ""
    double_extension: bool = False
    macro_enabled: bool = False
    dangerous_executable: bool = False


class NLPAnalysis(BaseModel):
    phishing_probability: float = 0.0  # 0.0 to 1.0
    intent_label: str = "Benign"  # Benign, Phishing, Credential Harvesting, Financial Fraud, Executive Impersonation
    confidence: float = 0.0
    categories: List[str] = Field(default_factory=list)
    suspicious_keywords: List[str] = Field(default_factory=list)
    evidence_sentences: List[str] = Field(default_factory=list)
    model_engine: str = "Heuristic Rule-Based & TF-IDF Fallback"
    risk_level: str = "SAFE"


class ThreatFactor(BaseModel):
    factor: str
    points: int
    category: str  # Authentication, Sender, URL, Attachment, Content, Infrastructure
    description: str
    evidence: str = ""


class TimelineEvent(BaseModel):
    timestamp: str
    event_type: str  # HOP_RECEIVED, EMAIL_DATE, ATTACHMENT_PARSED, ANALYSIS_COMPLETED
    title: str
    description: str
    source: str = "Header / Parser"


class CryptoIndicator(BaseModel):
    currency: str  # Bitcoin, Ethereum
    address: str
    context: str


class SubScores(BaseModel):
    authentication_risk: int = 0
    sender_risk: int = 0
    url_risk: int = 0
    attachment_risk: int = 0
    content_nlp_risk: int = 0
    infrastructure_risk: int = 0
    overall_threat_score: int = 0


class AnalysisSummary(BaseModel):
    investigation_id: str
    subject: str
    sender: str
    recipient: str
    date: str
    overall_threat_score: int
    threat_level: str  # Safe, Low, Medium, High, Critical
    header_trust_score: int
    verdict: str


class FullAnalysisResult(BaseModel):
    success: bool = True
    summary: AnalysisSummary
    sub_scores: SubScores
    authentication: AuthenticationSummary
    sender_analysis: SenderAnalysis
    routing_hops: List[RoutingHop] = Field(default_factory=list)
    route_stats: RouteStats = Field(default_factory=RouteStats)
    nlp_analysis: NLPAnalysis = Field(default_factory=NLPAnalysis)
    urls: List[URLItem] = Field(default_factory=list)
    attachments: List[AttachmentItem] = Field(default_factory=list)
    crypto_indicators: List[CryptoIndicator] = Field(default_factory=list)
    threat_factors: List[ThreatFactor] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    extracted_text_preview: str = ""
    sanitized_html_preview: str = ""
    raw: Dict[str, Any] = Field(default_factory=dict)
