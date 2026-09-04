"""
Unit tests for AuthenticationAnalyzer.
"""
import pytest
from backend.services.authentication_analyzer import AuthenticationAnalyzer


def test_auth_analyzer_pass():
    headers = {
        "authentication-results": [
            "mx.google.com; spf=pass client-ip=198.51.100.88; dkim=pass header.d=example.com; dmarc=pass header.from=example.com"
        ],
        "received-spf": [
            "Pass (mx.google.com: domain of sender@example.com designates 198.51.100.88 as permitted sender) client-ip=198.51.100.88;"
        ],
        "dkim-signature": [
            "v=1; a=rsa-sha256; d=example.com; s=s1; bh=abc=; b=xyz="
        ]
    }
    analyzer = AuthenticationAnalyzer(headers)
    summary = analyzer.analyze()

    assert summary.spf.status == "Pass"
    assert summary.dkim.status == "Pass"
    assert summary.dmarc.status == "Pass"
    assert summary.header_trust_score == 100


def test_auth_analyzer_fail():
    headers = {
        "authentication-results": [
            "mx.google.com; spf=fail client-ip=203.0.113.195; dkim=fail header.d=example.com; dmarc=fail action=quarantine header.from=example.com"
        ],
        "received-spf": [
            "Fail (mx.google.com: domain of bounce@fake.com does not designate 203.0.113.195) client-ip=203.0.113.195;"
        ]
    }
    analyzer = AuthenticationAnalyzer(headers)
    summary = analyzer.analyze()

    assert summary.spf.status == "Fail"
    assert summary.dkim.status == "Fail"
    assert summary.dmarc.status == "Fail"
    # 100 - 30 (SPF fail) - 30 (DKIM fail) - 35 (DMARC fail) = 5
    assert summary.header_trust_score <= 10
