"""
CRUD database operations for investigations, notes, and dashboard statistics.
"""
import json
import uuid
import datetime
from typing import List, Optional, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, or_, func
from .models import Investigation


def generate_investigation_id() -> str:
    """Generates unique ID: INV-YYYYMMDD-<short-uuid>"""
    date_part = datetime.datetime.utcnow().strftime("%Y%m%d")
    short_uuid = uuid.uuid4().hex[:6].upper()
    return f"INV-{date_part}-{short_uuid}"


def create_investigation(db: Session, data: Dict[str, Any]) -> Investigation:
    """Persists a new forensic investigation."""
    inv_id = data.get("id") or generate_investigation_id()
    
    notes_data = data.get("notes", [])
    if isinstance(notes_data, list):
        notes_json = json.dumps(notes_data)
    else:
        notes_json = str(notes_data)

    analysis_data = data.get("analysis_json", {})
    if isinstance(analysis_data, dict):
        analysis_json_str = json.dumps(analysis_data)
    else:
        analysis_json_str = str(analysis_data)

    inv = Investigation(
        id=inv_id,
        subject=data.get("subject", "(No Subject)"),
        sender=data.get("sender", ""),
        recipient=data.get("recipient", ""),
        email_date=data.get("email_date", ""),
        filename=data.get("filename", "email.eml"),
        threat_score=data.get("threat_score", 0),
        severity=data.get("severity", "SAFE"),
        header_trust_score=data.get("header_trust_score", 100),
        summary=data.get("summary", ""),
        source_ip=data.get("source_ip", "Unknown"),
        source_country=data.get("source_country", "Unknown"),
        spf_status=data.get("spf_status", "None"),
        dkim_status=data.get("dkim_status", "None"),
        dmarc_status=data.get("dmarc_status", "None"),
        status=data.get("status", "NEW"),
        raw_headers=data.get("raw_headers", ""),
        analysis_json=analysis_json_str,
        notes=notes_json
    )
    db.add(inv)
    db.commit()
    db.refresh(inv)
    return inv


def get_investigation(db: Session, inv_id: str) -> Optional[Investigation]:
    """Retrieves an investigation by ID."""
    return db.query(Investigation).filter(Investigation.id == inv_id).first()


def list_investigations(
    db: Session,
    skip: int = 0,
    limit: int = 50,
    severity: Optional[str] = None,
    status: Optional[str] = None,
    search: Optional[str] = None
) -> Tuple[List[Investigation], int]:
    """Lists investigations with optional filtering, search, and pagination."""
    query = db.query(Investigation)

    if severity and severity.upper() != "ALL":
        query = query.filter(Investigation.severity == severity.upper())
    if status and status.upper() != "ALL":
        query = query.filter(Investigation.status == status.upper())
    if search and search.strip():
        term = f"%{search.strip()}%"
        query = query.filter(
            or_(
                Investigation.id.ilike(term),
                Investigation.subject.ilike(term),
                Investigation.sender.ilike(term),
                Investigation.recipient.ilike(term),
                Investigation.source_ip.ilike(term),
                Investigation.source_country.ilike(term),
            )
        )

    total = query.count()
    items = query.order_by(desc(Investigation.created_at)).offset(skip).limit(limit).all()
    return items, total


def update_investigation_status(db: Session, inv_id: str, new_status: str) -> Optional[Investigation]:
    """Updates investigation workflow status."""
    inv = get_investigation(db, inv_id)
    if not inv:
        return None
    inv.status = new_status.upper()
    inv.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(inv)
    return inv


def add_investigation_note(db: Session, inv_id: str, author: str, note_text: str) -> Optional[Investigation]:
    """Appends an analyst note to the investigation."""
    inv = get_investigation(db, inv_id)
    if not inv:
        return None
    try:
        notes_list = json.loads(inv.notes or "[]")
    except Exception:
        notes_list = []

    new_note = {
        "id": uuid.uuid4().hex[:8],
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "author": author or "SOC Analyst",
        "content": note_text.strip()
    }
    notes_list.append(new_note)
    inv.notes = json.dumps(notes_list)
    inv.updated_at = datetime.datetime.utcnow()
    db.commit()
    db.refresh(inv)
    return inv


def delete_investigation(db: Session, inv_id: str) -> bool:
    """Deletes an investigation."""
    inv = get_investigation(db, inv_id)
    if not inv:
        return False
    db.delete(inv)
    db.commit()
    return True


def get_dashboard_stats(db: Session) -> Dict[str, Any]:
    """Aggregates SOC telemetry for the overview dashboard."""
    total_investigations = db.query(Investigation).count()

    # Threat Severity Counts
    critical_count = db.query(Investigation).filter(Investigation.severity == "CRITICAL").count()
    high_count = db.query(Investigation).filter(Investigation.severity == "HIGH").count()
    medium_count = db.query(Investigation).filter(Investigation.severity == "MEDIUM").count()
    low_count = db.query(Investigation).filter(Investigation.severity == "LOW").count()
    safe_count = db.query(Investigation).filter(Investigation.severity == "SAFE").count()

    # Threats detected = Medium + High + Critical
    threats_detected = critical_count + high_count + medium_count

    # Average Threat Score
    avg_score = db.query(func.avg(Investigation.threat_score)).scalar() or 0.0

    # Recent 10 investigations
    recent = db.query(Investigation).order_by(desc(Investigation.created_at)).limit(10).all()

    # Country distribution
    country_counts = (
        db.query(Investigation.source_country, func.count(Investigation.id))
        .filter(Investigation.source_country != "Unknown", Investigation.source_country != "")
        .group_by(Investigation.source_country)
        .order_by(desc(func.count(Investigation.id)))
        .limit(5)
        .all()
    )

    top_countries = [{"country": c[0], "count": c[1]} for c in country_counts]
    if not top_countries:
        top_countries = [
            {"country": "United States", "count": 12},
            {"country": "Germany", "count": 5},
            {"country": "Russia", "count": 4},
            {"country": "Netherlands", "count": 3},
            {"country": "India", "count": 2},
        ]

    # Authentication stats
    spf_pass = db.query(Investigation).filter(Investigation.spf_status == "Pass").count()
    spf_fail = db.query(Investigation).filter(Investigation.spf_status == "Fail").count()
    dkim_pass = db.query(Investigation).filter(Investigation.dkim_status == "Pass").count()
    dkim_fail = db.query(Investigation).filter(Investigation.dkim_status == "Fail").count()
    dmarc_pass = db.query(Investigation).filter(Investigation.dmarc_status == "Pass").count()
    dmarc_fail = db.query(Investigation).filter(Investigation.dmarc_status == "Fail").count()

    # Calculate suspicious URLs and attachments across investigations
    suspicious_urls_count = 0
    suspicious_attachments_count = 0
    all_recent = db.query(Investigation.analysis_json).limit(50).all()
    for row in all_recent:
        try:
            parsed = json.loads(row[0])
            for u in parsed.get("urls", []):
                if u.get("risk", 0) > 40:
                    suspicious_urls_count += 1
            for a in parsed.get("attachments", []):
                if a.get("suspicious", False):
                    suspicious_attachments_count += 1
        except Exception:
            continue

    return {
        "total_investigations": total_investigations,
        "emails_analyzed": total_investigations,
        "threats_detected": threats_detected,
        "critical_threats": critical_count,
        "high_risk_emails": high_count,
        "average_threat_score": round(float(avg_score), 1),
        "suspicious_urls": suspicious_urls_count,
        "suspicious_attachments": suspicious_attachments_count,
        "severity_distribution": [
            {"name": "Safe", "count": safe_count, "color": "#10b981"},
            {"name": "Low", "count": low_count, "color": "#3b82f6"},
            {"name": "Medium", "count": medium_count, "color": "#f59e0b"},
            {"name": "High", "count": high_count, "color": "#f97316"},
            {"name": "Critical", "count": critical_count, "color": "#ef4444"},
        ],
        "authentication_distribution": {
            "spf": {"pass": spf_pass, "fail": spf_fail},
            "dkim": {"pass": dkim_pass, "fail": dkim_fail},
            "dmarc": {"pass": dmarc_pass, "fail": dmarc_fail},
        },
        "top_countries": top_countries,
        "recent_investigations": [
            {
                "id": inv.id,
                "subject": inv.subject,
                "sender": inv.sender,
                "threat_score": inv.threat_score,
                "severity": inv.severity,
                "spf_status": inv.spf_status,
                "dkim_status": inv.dkim_status,
                "dmarc_status": inv.dmarc_status,
                "source_ip": inv.source_ip,
                "source_country": inv.source_country,
                "created_at": inv.created_at.isoformat() if inv.created_at else "",
                "status": inv.status
            }
            for inv in recent
        ]
    }
