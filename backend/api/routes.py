"""
FastAPI REST API routes for SIH26106 Threat Platform.
Provides endpoints for email ingestion, SOC telemetry, investigation management,
threat intelligence lookups, and PDF/JSON forensic report exports.
"""
import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Response
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from ..database.database import get_db
from ..database import crud
from ..services.pipeline import EmailAnalysisPipeline
from ..services.report_generator import ReportGenerator
from ..services.threat_intelligence import ThreatIntelligenceService
from ..schemas.investigation import (
    InvestigationListResponse,
    InvestigationListItem,
    InvestigationDetail,
    AnalystNote,
    StatusUpdateRequest,
    AddNoteRequest,
    APIResponse,
    StandardError,
)

router = APIRouter()
intel_service = ThreatIntelligenceService()


# ---------------------------------------------------------
# Health Check Endpoint
# ---------------------------------------------------------
@router.get("/health")
def health_check(db: Session = Depends(get_db)):
    """System health inspection for backend, SQLite, NLP engine, and threat providers."""
    db_status = "ACTIVE"
    try:
        crud.get_dashboard_stats(db)
    except Exception:
        db_status = "UNAVAILABLE"

    return {
        "status": "ACTIVE",
        "version": "1.0.0",
        "service": "SIH26106 Email Threat Intelligence Platform",
        "components": {
            "backend": "ACTIVE",
            "database": db_status,
            "nlp_engine": "ACTIVE (Rule-Based & TF-IDF Fallback)",
            "geolocation": "AVAILABLE (ip-api.com & Synthetic Documentation Fallback)",
            "threat_intelligence": "ACTIVE (Provider Abstraction: VirusTotal & AbuseIPDB)"
        }
    }


# ---------------------------------------------------------
# Dashboard Statistics
# ---------------------------------------------------------
@router.get("/v1/dashboard/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """Aggregated SOC statistics for the command dashboard."""
    stats = crud.get_dashboard_stats(db)
    return {"success": True, "data": stats, "error": None}


# ---------------------------------------------------------
# Email Analysis (Ingestion)
# ---------------------------------------------------------
@router.post("/v1/analyze")
async def analyze_email(
    file: Optional[UploadFile] = File(None),
    raw_text: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Primary ingestion endpoint for email threat forensics.
    Accepts .eml file upload or raw RFC 2822 / header / body text.
    Executes the 20-stage forensic pipeline and returns FullAnalysisResult.
    """
    if not file and (not raw_text or not raw_text.strip()):
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_PAYLOAD", "message": "Provide an .eml file or paste raw email text."}
        )

    filename = "pasted_email.eml"
    raw_content = b""

    if file:
        filename = file.filename or "uploaded_email.eml"
        raw_content = await file.read()
    elif raw_text:
        raw_content = raw_text.encode("utf-8", errors="replace")

    if not raw_content:
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_PAYLOAD", "message": "Email payload is empty."}
        )

    # Execute 20-stage pipeline with DB persistence
    pipeline = EmailAnalysisPipeline(raw_input=raw_content, filename=filename, db=db)
    result = pipeline.execute()

    return result.model_dump()


# ---------------------------------------------------------
# Investigation Case Management
# ---------------------------------------------------------
@router.get("/v1/investigations")
def list_investigations(
    skip: int = Query(0, ge=0),
    limit: int = Query(25, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    """Lists investigations with optional filtering, search, and pagination."""
    items, total = crud.list_investigations(
        db=db,
        skip=skip,
        limit=limit,
        severity=severity,
        status=status,
        search=search
    )

    formatted_items = [
        InvestigationListItem(
            id=i.id,
            subject=i.subject,
            sender=i.sender,
            recipient=i.recipient,
            email_date=i.email_date,
            filename=i.filename,
            threat_score=i.threat_score,
            severity=i.severity,
            header_trust_score=i.header_trust_score,
            source_ip=i.source_ip,
            source_country=i.source_country,
            spf_status=i.spf_status,
            dkim_status=i.dkim_status,
            dmarc_status=i.dmarc_status,
            status=i.status,
            created_at=i.created_at.isoformat() if i.created_at else "",
            updated_at=i.updated_at.isoformat() if i.updated_at else "",
        )
        for i in items
    ]

    return {
        "success": True,
        "total": total,
        "page": (skip // limit) + 1,
        "limit": limit,
        "items": [item.model_dump() for item in formatted_items]
    }


@router.get("/v1/investigations/{inv_id}")
def get_investigation_detail(inv_id: str, db: Session = Depends(get_db)):
    """Retrieves full investigation detail including parsed analysis and analyst notes."""
    inv = crud.get_investigation(db, inv_id)
    if not inv:
        raise HTTPException(
            status_code=404,
            detail={"code": "INVESTIGATION_NOT_FOUND", "message": f"Case {inv_id} not found."}
        )

    try:
        analysis_data = json.loads(inv.analysis_json or "{}")
    except Exception:
        analysis_data = {}

    try:
        notes_data = json.loads(inv.notes or "[]")
    except Exception:
        notes_data = []

    detail = InvestigationDetail(
        id=inv.id,
        created_at=inv.created_at.isoformat() if inv.created_at else "",
        updated_at=inv.updated_at.isoformat() if inv.updated_at else "",
        subject=inv.subject,
        sender=inv.sender,
        recipient=inv.recipient,
        email_date=inv.email_date,
        filename=inv.filename,
        threat_score=inv.threat_score,
        severity=inv.severity,
        header_trust_score=inv.header_trust_score,
        summary=inv.summary,
        source_ip=inv.source_ip,
        source_country=inv.source_country,
        spf_status=inv.spf_status,
        dkim_status=inv.dkim_status,
        dmarc_status=inv.dmarc_status,
        status=inv.status,
        raw_headers=inv.raw_headers,
        analysis=analysis_data,
        notes=[AnalystNote(**n) for n in notes_data]
    )

    return {"success": True, "data": detail.model_dump(), "error": None}


@router.patch("/v1/investigations/{inv_id}/status")
def update_status(
    inv_id: str,
    req: StatusUpdateRequest,
    db: Session = Depends(get_db)
):
    """Updates case status (NEW, IN_PROGRESS, REVIEWED, ESCALATED, CLOSED)."""
    valid_statuses = {"NEW", "IN_PROGRESS", "REVIEWED", "ESCALATED", "CLOSED"}
    new_status = req.status.upper()
    if new_status not in valid_statuses:
        raise HTTPException(
            status_code=400,
            detail={"code": "INVALID_STATUS", "message": f"Status must be one of {valid_statuses}"}
        )

    inv = crud.update_investigation_status(db, inv_id, new_status)
    if not inv:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"Investigation {inv_id} not found"}
        )

    return {"success": True, "message": f"Status updated to {new_status}", "status": new_status}


@router.post("/v1/investigations/{inv_id}/notes")
def add_note(
    inv_id: str,
    req: AddNoteRequest,
    db: Session = Depends(get_db)
):
    """Appends an analyst note to the case history."""
    if not req.note.strip():
        raise HTTPException(
            status_code=400,
            detail={"code": "EMPTY_NOTE", "message": "Note text cannot be empty."}
        )

    inv = crud.add_investigation_note(db, inv_id, req.author, req.note)
    if not inv:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"Investigation {inv_id} not found"}
        )

    try:
        notes_data = json.loads(inv.notes or "[]")
    except Exception:
        notes_data = []

    return {"success": True, "message": "Note added successfully", "notes": notes_data}


@router.delete("/v1/investigations/{inv_id}")
def delete_investigation(inv_id: str, db: Session = Depends(get_db)):
    """Deletes an investigation case."""
    success = crud.delete_investigation(db, inv_id)
    if not success:
        raise HTTPException(
            status_code=404,
            detail={"code": "NOT_FOUND", "message": f"Investigation {inv_id} not found"}
        )
    return {"success": True, "message": f"Investigation {inv_id} deleted"}


# ---------------------------------------------------------
# Forensic Reporting: PDF & JSON Exports
# ---------------------------------------------------------
@router.get("/v1/investigations/{inv_id}/report/pdf")
def export_pdf_report(inv_id: str, db: Session = Depends(get_db)):
    """Generates and serves a formatted PDF forensic report."""
    inv = crud.get_investigation(db, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        analysis_data = json.loads(inv.analysis_json or "{}")
    except Exception:
        analysis_data = {}

    pdf_bytes = ReportGenerator.generate_pdf(analysis_data)

    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f"attachment; filename=Forensic_Report_{inv_id}.pdf"
        }
    )


@router.get("/v1/investigations/{inv_id}/export/json")
def export_json_report(inv_id: str, db: Session = Depends(get_db)):
    """Exports full machine-readable JSON forensic package."""
    inv = crud.get_investigation(db, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        analysis_data = json.loads(inv.analysis_json or "{}")
    except Exception:
        analysis_data = {}

    try:
        notes_data = json.loads(inv.notes or "[]")
    except Exception:
        notes_data = []

    export_obj = {
        "investigation_id": inv.id,
        "created_at": inv.created_at.isoformat() if inv.created_at else "",
        "subject": inv.subject,
        "sender": inv.sender,
        "recipient": inv.recipient,
        "threat_score": inv.threat_score,
        "severity": inv.severity,
        "header_trust_score": inv.header_trust_score,
        "forensic_analysis": analysis_data,
        "analyst_notes": notes_data
    }

    return Response(
        content=json.dumps(export_obj, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=Forensic_Data_{inv_id}.json"
        }
    )


@router.get("/v1/investigations/{inv_id}/report")
def get_report_summary(inv_id: str, db: Session = Depends(get_db)):
    """Quick summary of the investigation report."""
    inv = crud.get_investigation(db, inv_id)
    if not inv:
        raise HTTPException(status_code=404, detail="Investigation not found")

    try:
        analysis_data = json.loads(inv.analysis_json or "{}")
    except Exception:
        analysis_data = {}

    return {
        "success": True,
        "investigation_id": inv.id,
        "summary": analysis_data.get("summary", {}),
        "threat_factors": analysis_data.get("threat_factors", []),
        "sub_scores": analysis_data.get("sub_scores", {})
    }


# ---------------------------------------------------------
# Threat Intelligence Lookups
# ---------------------------------------------------------
@router.get("/v1/threat-intelligence/ip/{ip}")
def lookup_ip_threat(ip: str):
    """Queries reputation for a specific IP address."""
    return intel_service.lookup_ip(ip)


@router.get("/v1/threat-intelligence/domain/{domain}")
def lookup_domain_threat(domain: str):
    """Queries reputation for a specific domain name."""
    return intel_service.lookup_domain(domain)


@router.get("/v1/threat-intelligence/hash/{file_hash}")
def lookup_hash_threat(file_hash: str):
    """Queries reputation for a specific cryptographic file hash."""
    return intel_service.lookup_hash(file_hash)


# ---------------------------------------------------------
# Geo Intelligence Telemetry
# ---------------------------------------------------------
@router.get("/v1/geo/intelligence")
def get_geo_intelligence(db: Session = Depends(get_db)):
    """Aggregates geographic route intelligence across past investigations."""
    investigations = db.query(crud.Investigation.analysis_json).limit(50).all()
    all_hops = []
    country_freq = {}

    for row in investigations:
        try:
            data = json.loads(row[0])
            for hop in data.get("routing_hops", []):
                if hop.get("latitude") and hop.get("longitude"):
                    all_hops.append({
                        "ip": hop.get("from_ip") or hop.get("by_ip"),
                        "city": hop.get("city"),
                        "country": hop.get("country"),
                        "lat": hop.get("latitude"),
                        "lon": hop.get("longitude"),
                        "isp": hop.get("isp"),
                        "suspicious": hop.get("suspicious", False)
                    })
                    c = hop.get("country")
                    if c and c not in ("Unknown", "Private Network"):
                        country_freq[c] = country_freq.get(c, 0) + 1
        except Exception:
            continue

    return {
        "success": True,
        "active_relays_count": len(all_hops),
        "geo_points": all_hops[:100],
        "top_relay_countries": sorted([{"country": k, "count": v} for k, v in country_freq.items()], key=lambda x: x["count"], reverse=True)[:10]
    }
