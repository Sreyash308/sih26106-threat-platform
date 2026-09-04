"""
Unit tests for Received header forensics and IP classification.
"""
import pytest
from backend.utils.helpers import classify_ip
from backend.services.geo_tracer import GeoTracer


def test_ip_classification():
    # Public
    pub = classify_ip("8.8.8.8")
    assert pub["type"] == "public"
    assert pub["is_public"] is True

    # RFC 1918 Private
    priv = classify_ip("192.168.1.1")
    assert priv["type"] == "private"
    assert priv["is_public"] is False

    # Loopback
    loop = classify_ip("127.0.0.1")
    assert loop["type"] == "loopback"
    assert loop["is_public"] is False

    # Documentation
    doc = classify_ip("203.0.113.195")
    assert doc["type"] == "documentation"
    assert doc["is_public"] is False


def test_received_headers_chronological_reconstruction():
    headers = {
        "received": [
            "from mx.dest.org ([198.51.100.88]) by gateway.dest.org; Fri, 04 Sep 2026 10:02:00 +0000",
            "from relay.intermediate.com ([198.51.100.25]) by mx.dest.org; Fri, 04 Sep 2026 10:01:00 +0000",
            "from client.origin.net ([203.0.113.195]) by relay.intermediate.com; Fri, 04 Sep 2026 10:00:00 +0000"
        ]
    }
    tracer = GeoTracer(headers)
    hops, stats = tracer.trace()

    assert len(hops) == 3
    # Hop 1 must be the earliest sending relay (from origin 203.0.113.195)
    assert hops[0].hop_number == 1
    assert "203.0.113.195" in (hops[0].from_ip or hops[0].by_ip)

    # Hop 3 must be the final receiving relay
    assert hops[2].hop_number == 3
    assert stats.total_hops == 3
