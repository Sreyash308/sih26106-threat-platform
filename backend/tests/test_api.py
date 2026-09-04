"""
Integration tests for FastAPI endpoints.
"""
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend.database.database import init_db

init_db()
client = TestClient(app)


def test_api_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ACTIVE"
    assert "components" in data


def test_api_dashboard_stats():
    response = client.get("/api/v1/dashboard/stats")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert "total_investigations" in data["data"]


def test_api_analyze_raw_text():
    sample_raw = """From: Security <alert@fake-login.xyz>
To: victim@example.com
Subject: URGENT: Verify your credentials now
Authentication-Results: mx.example.com; spf=fail; dmarc=fail

Please verify your password immediately at http://fake-login.xyz/login
"""
    response = client.post("/api/v1/analyze", data={"raw_text": sample_raw})
    assert response.status_code == 200
    res = response.json()
    assert res["success"] is True
    assert "summary" in res
    assert res["summary"]["overall_threat_score"] > 0
    inv_id = res["summary"]["investigation_id"]

    # Verify retrieval
    inv_resp = client.get(f"/api/v1/investigations/{inv_id}")
    assert inv_resp.status_code == 200
    inv_data = inv_resp.json()["data"]
    assert inv_data["id"] == inv_id

    # Verify status update
    status_resp = client.patch(f"/api/v1/investigations/{inv_id}/status", json={"status": "IN_PROGRESS"})
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "IN_PROGRESS"

    # Verify analyst note addition
    note_resp = client.post(f"/api/v1/investigations/{inv_id}/notes", json={"author": "SOC Lead", "note": "Escalating incident."})
    assert note_resp.status_code == 200
    assert len(note_resp.json()["notes"]) >= 1

    # Verify PDF export
    pdf_resp = client.get(f"/api/v1/investigations/{inv_id}/report/pdf")
    assert pdf_resp.status_code == 200
    assert pdf_resp.headers["content-type"] == "application/pdf"
    assert len(pdf_resp.content) > 500

    # Verify JSON export
    json_resp = client.get(f"/api/v1/investigations/{inv_id}/export/json")
    assert json_resp.status_code == 200
    assert "Forensic_Data_" in json_resp.headers["content-disposition"]


def test_threat_intelligence_lookups():
    # Demo IP
    ip_resp = client.get("/api/v1/threat-intelligence/ip/203.0.113.195")
    assert ip_resp.status_code == 200
    assert ip_resp.json()["data"]["provider_status"] == "demo_intelligence"

    # Unconfigured IP
    unconf_resp = client.get("/api/v1/threat-intelligence/ip/8.8.4.4")
    assert unconf_resp.status_code == 200
    assert unconf_resp.json()["status"] == "not_configured"
