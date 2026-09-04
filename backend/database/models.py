"""
SQLAlchemy ORM models for forensic investigations.
"""
import datetime
from sqlalchemy import Column, String, Integer, DateTime, Text
from .database import Base


class Investigation(Base):
    __tablename__ = "investigations"

    id = Column(String(64), primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

    # Core Email Identifiers
    subject = Column(String(512), default="(No Subject)")
    sender = Column(String(256), default="")
    recipient = Column(String(256), default="")
    email_date = Column(String(128), default="")
    filename = Column(String(256), default="manual_input.eml")

    # Threat Intelligence & Scoring
    threat_score = Column(Integer, default=0, index=True)
    severity = Column(String(32), default="SAFE", index=True)  # SAFE, LOW, MEDIUM, HIGH, CRITICAL
    header_trust_score = Column(Integer, default=100)
    summary = Column(Text, default="")

    # Forensic Quick Lookups
    source_ip = Column(String(64), default="Unknown")
    source_country = Column(String(64), default="Unknown")
    spf_status = Column(String(32), default="None")
    dkim_status = Column(String(32), default="None")
    dmarc_status = Column(String(32), default="None")

    # Workflow & SOC Management
    status = Column(String(32), default="NEW", index=True)  # NEW, IN_PROGRESS, REVIEWED, ESCALATED, CLOSED

    # Raw and Structured Data
    raw_headers = Column(Text, default="")
    analysis_json = Column(Text, default="{}")  # Full JSON string of pipeline analysis
    notes = Column(Text, default="[]")  # JSON string of analyst notes array
