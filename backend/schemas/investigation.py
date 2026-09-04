"""
Pydantic schemas for investigation management, notes, and API responses.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AnalystNote(BaseModel):
    id: str
    timestamp: str
    author: str
    content: str


class AddNoteRequest(BaseModel):
    author: str = "SOC Analyst"
    note: str


class StatusUpdateRequest(BaseModel):
    status: str = Field(..., description="NEW, IN_PROGRESS, REVIEWED, ESCALATED, CLOSED")


class InvestigationListItem(BaseModel):
    id: str
    subject: str
    sender: str
    recipient: str
    email_date: str
    filename: str
    threat_score: int
    severity: str
    header_trust_score: int
    source_ip: str
    source_country: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    status: str
    created_at: str
    updated_at: str


class InvestigationListResponse(BaseModel):
    success: bool = True
    total: int
    page: int
    limit: int
    items: List[InvestigationListItem]


class InvestigationDetail(BaseModel):
    id: str
    created_at: str
    updated_at: str
    subject: str
    sender: str
    recipient: str
    email_date: str
    filename: str
    threat_score: int
    severity: str
    header_trust_score: int
    summary: str
    source_ip: str
    source_country: str
    spf_status: str
    dkim_status: str
    dmarc_status: str
    status: str
    raw_headers: str
    analysis: Dict[str, Any]
    notes: List[AnalystNote]


class StandardError(BaseModel):
    code: str
    message: str


class APIResponse(BaseModel):
    success: bool = True
    data: Optional[Any] = None
    error: Optional[StandardError] = None
