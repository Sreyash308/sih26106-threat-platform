"""
Unit tests for NLP Social Engineering Analyzer.
"""
import pytest
from backend.services.nlp_analyzer import NLPAnalyzer


def test_nlp_credential_phishing():
    phish_text = "URGENT: Your account has been suspended! You must verify your password immediately or access will be terminated."
    analyzer = NLPAnalyzer(plain_text=phish_text, subject="Account Locked")
    res = analyzer.analyze()

    assert res.phishing_probability >= 0.70
    assert "Credential Harvesting" in res.categories or "Urgent Action" in res.categories
    assert len(res.suspicious_keywords) > 0


def test_nlp_benign_text():
    benign_text = "Hi team, please find attached the meeting agenda for tomorrow's engineering sync."
    analyzer = NLPAnalyzer(plain_text=benign_text, subject="Weekly Sync")
    res = analyzer.analyze()

    assert res.phishing_probability < 0.40
    assert res.intent_label == "Benign"
