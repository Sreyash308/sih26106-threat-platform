"""
Unit tests for GeoTracer and Haversine distance calculation.
"""
import pytest
from backend.utils.helpers import calculate_haversine_distance
from backend.services.geo_tracer import GeoTracer


def test_haversine_distance_calculation():
    # Distance between London (51.5074, -0.1278) and Paris (48.8566, 2.3522) ~ 343 km
    dist = calculate_haversine_distance(51.5074, -0.1278, 48.8566, 2.3522)
    assert 340.0 < dist < 350.0


def test_geo_tracer_demo_dataset():
    headers = {
        "received": [
            "from mail.example.com ([192.0.2.1]) by mx.dest.org; Fri, 04 Sep 2026 10:00:00 +0000"
        ]
    }
    tracer = GeoTracer(headers)
    hops, stats = tracer.trace()

    assert len(hops) == 1
    assert hops[0].country == "United States"
    assert hops[0].city == "Ashburn"
    assert hops[0].provider_status == "demo_intelligence"
