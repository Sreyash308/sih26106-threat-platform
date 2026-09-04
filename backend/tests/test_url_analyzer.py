"""
Unit tests for URL and Cryptocurrency Analyzer.
"""
import pytest
from backend.services.url_analyzer import URLAnalyzer


def test_url_analyzer_heuristic_detection():
    html_content = """
    <p>Please login: <a href="http://secure-update-account.top/verify?redirect=portal">https://paypal.com/signin</a></p>
    <p>Direct IP: http://203.0.113.195/session/re-activate</p>
    """
    text_content = "Please remit BTC payment to 1BoatSLRHtKNngkdXEeobR76b53LETtpyT immediately."

    analyzer = URLAnalyzer(plain_text=text_content, raw_html=html_content, headers_dict={})
    urls, cryptos = analyzer.analyze()

    assert len(urls) >= 2
    # Verify Anchor Mismatch detection
    mismatched = [u for u in urls if u.anchor_mismatch]
    assert len(mismatched) == 1
    assert mismatched[0].risk >= 50

    # Verify IP-based URL detection
    ip_urls = [u for u in urls if u.is_ip_based]
    assert len(ip_urls) == 1

    # Verify Bitcoin Address detection
    assert len(cryptos) == 1
    assert cryptos[0].currency == "Bitcoin (BTC)"
    assert cryptos[0].address == "1BoatSLRHtKNngkdXEeobR76b53LETtpyT"
