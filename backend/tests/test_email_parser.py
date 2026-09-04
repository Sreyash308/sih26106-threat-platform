"""
Unit tests for EmailParser service.
"""
import pytest
from backend.services.email_parser import EmailParser


SAMPLE_RAW_EMAIL = b"""From: =?UTF-8?B?U2VjdXJpdHkgQWxlcnQ=?= <alert@example.com>
To: target@example.com
Subject: =?UTF-8?Q?Urgent_=E2=9A=A0_Action_Required?=
Date: Fri, 04 Sep 2026 10:00:00 +0000
Message-ID: <msg-12345@example.com>
Content-Type: text/html; charset=UTF-8

<html><body><p>Please review your account immediately.</p><script>alert('malicious')</script></body></html>
"""


def test_email_parser_metadata_and_headers():
    parser = EmailParser(SAMPLE_RAW_EMAIL)
    res = parser.parse()

    meta = res["metadata"]
    assert "Security Alert" in meta["from"]
    assert "Urgent" in meta["subject"]
    assert meta["message_id"] == "<msg-12345@example.com>"
    assert len(res["raw_headers_list"]) > 0
    assert "alert@example.com" in res["raw_headers_str"]


def test_html_sanitization_in_parser():
    parser = EmailParser(SAMPLE_RAW_EMAIL)
    res = parser.parse()

    sanitized = res["sanitized_html"]
    # Verify malicious script tag was completely stripped
    assert "<script>" not in sanitized
    assert "alert('malicious')" not in sanitized
    assert "Please review your account immediately." in sanitized


def test_plain_text_fallback():
    parser = EmailParser(SAMPLE_RAW_EMAIL)
    res = parser.parse()

    plain = res["plain_text"]
    assert "Please review your account immediately." in plain
