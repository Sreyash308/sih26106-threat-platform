"""
Unit tests for ThreatScorer and explainability generation.
"""
import pytest
from backend.services.threat_scorer import ThreatScorer
from backend.schemas.analysis import (
    AuthenticationSummary, AuthResultItem, SenderAnalysis,
    URLItem, AttachmentItem, NLPAnalysis
)


def test_threat_scorer_critical():
    auth = AuthenticationSummary(
        spf=AuthResultItem(status="Fail", evidence="SPF failed"),
        dkim=AuthResultItem(status="Fail", evidence="DKIM failed"),
        dmarc=AuthResultItem(status="Fail", evidence="DMARC failed")
    )
    sender = SenderAnalysis(
        from_reply_to_mismatch=True,
        display_name_deception=True,
        from_address="evil@attacker.xyz",
        from_domain="attacker.xyz"
    )
    urls = [
        URLItem(full_url="http://evil-phish.top/login", risk=80, anchor_mismatch=True)
    ]
    attachments = [
        AttachmentItem(filename="malware.exe", extension=".exe", mime_type="application/octet-stream", size_bytes=1000, sha256="abc", dangerous_executable=True)
    ]
    nlp = NLPAnalysis(
        phishing_probability=0.92,
        categories=["Credential Harvesting", "Urgent Action"]
    )

    scorer = ThreatScorer(auth=auth, sender=sender, urls=urls, attachments=attachments, nlp=nlp, hops=[])
    score, severity, sub_scores, factors, verdict = scorer.calculate()

    assert score >= 80
    assert severity == "CRITICAL"
    assert len(factors) >= 5
    assert sub_scores.overall_threat_score == score
