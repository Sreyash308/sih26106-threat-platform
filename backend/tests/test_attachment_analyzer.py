"""
Unit tests for Attachment Analyzer and cryptographic hashing.
"""
import pytest
from backend.services.attachment_analyzer import AttachmentAnalyzer


def test_attachment_hashing_and_double_extension():
    fake_exe_bytes = b"MZ\x90\x00\x03\x00\x00\x00FakePEBinaryPayload"
    attachments_raw = [
        {
            "filename": "Quarterly_Report.pdf.exe",
            "content_type": "application/octet-stream",
            "data": fake_exe_bytes
        },
        {
            "filename": "SafeDocument.pdf",
            "content_type": "application/pdf",
            "data": b"%PDF-1.4 Fake PDF Content"
        }
    ]

    analyzer = AttachmentAnalyzer(attachments_raw)
    results = analyzer.analyze()

    assert len(results) == 2

    # Verify Double Extension detection
    bad_att = results[0]
    assert bad_att.double_extension is True
    assert bad_att.dangerous_executable is True
    assert bad_att.risk_level == "CRITICAL"
    assert len(bad_att.sha256) == 64

    # Verify Safe Attachment
    safe_att = results[1]
    assert safe_att.suspicious is False
    assert safe_att.risk_level == "SAFE"
