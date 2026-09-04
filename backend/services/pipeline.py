"""
EmailAnalysisPipeline: Central 20-stage forensic analysis pipeline.
Coordinates MIME parsing, authentication, sender inspection, routing forensics,
URL/crypto heuristics, attachment hashing, NLP intent analysis, and explainable threat scoring.
Fault-tolerant: a failure in any individual subsystem never crashes the entire analysis.
"""
import re
import datetime
from email.utils import parseaddr
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session

from .email_parser import EmailParser
from .authentication_analyzer import AuthenticationAnalyzer
from .geo_tracer import GeoTracer
from .url_analyzer import URLAnalyzer
from .attachment_analyzer import AttachmentAnalyzer
from .nlp_analyzer import NLPAnalyzer
from .threat_scorer import ThreatScorer
from ..database.crud import create_investigation, generate_investigation_id
from ..schemas.analysis import (
    FullAnalysisResult,
    AnalysisSummary,
    SenderAnalysis,
    TimelineEvent,
)

FREE_EMAIL_PROVIDERS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com",
    "protonmail.com", "mail.com", "zoho.com", "yandex.com", "icloud.com"
}

BRAND_TARGETS = [
    "microsoft", "google", "apple", "amazon", "paypal", "netflix", "chase",
    "bank of america", "wellsfargo", "dhl", "fedex", "irs", "support", "security team"
]


class EmailAnalysisPipeline:
    """Master orchestrator for forensic email analysis."""

    def __init__(self, raw_input: bytes | str, filename: str = "email.eml", db: Optional[Session] = None):
        self.raw_input = raw_input
        self.filename = filename
        self.db = db

    def execute(self) -> FullAnalysisResult:
        """Executes all 20 stages of forensic inspection with defensive error boundaries."""
        timeline: list[TimelineEvent] = []
        investigation_id = generate_investigation_id()
        now_iso = datetime.datetime.utcnow().isoformat() + "Z"

        # 1-4. Input Validation & MIME Parsing
        parser = EmailParser(self.raw_input)
        parsed_email = parser.parse()

        metadata = parsed_email["metadata"]
        headers_dict = parsed_email["headers_dict"]
        plain_text = parsed_email["plain_text"]
        raw_html = parsed_email["raw_html"]
        sanitized_html = parsed_email["sanitized_html"]
        raw_attachments = parsed_email["raw_attachments"]

        # Timeline: Email Date Event
        if metadata.get("date"):
            timeline.append(TimelineEvent(
                timestamp=metadata["date"],
                event_type="EMAIL_DATE",
                title="Message Dispatched",
                description=f"Email Date header asserted by sender: {metadata['date']}",
                source="Header: Date"
            ))

        # 5. Authentication Analysis (SPF, DKIM, DMARC)
        try:
            auth_analyzer = AuthenticationAnalyzer(headers_dict)
            auth_summary = auth_analyzer.analyze()
        except Exception as e:
            from ..schemas.analysis import AuthenticationSummary, AuthResultItem
            auth_summary = AuthenticationSummary(
                spf=AuthResultItem(status="Unknown", evidence=f"SPF parser error: {str(e)}"),
                dkim=AuthResultItem(status="Unknown", evidence=f"DKIM parser error: {str(e)}"),
                dmarc=AuthResultItem(status="Unknown", evidence=f"DMARC parser error: {str(e)}"),
                header_trust_score=50,
                evidence_notes=[f"Auth analyzer degraded: {str(e)}"]
            )

        # 6. Sender Forensics & Impersonation Analysis
        sender_analysis = self._analyze_sender(metadata)

        # 7-10. Received-Header Parsing, Hop Reconstruction & Geolocation
        try:
            tracer = GeoTracer(headers_dict)
            hops, route_stats = tracer.trace()
            for h in hops:
                timeline.append(TimelineEvent(
                    timestamp=h.timestamp or "Unspecified Timestamp",
                    event_type="HOP_RECEIVED",
                    title=f"Hop #{h.hop_number} Observed",
                    description=f"Relayed by {h.by_hostname or h.by_ip or 'Relay'} from {h.from_hostname or h.from_ip or 'Host'} ({h.city}, {h.country})",
                    source=f"Hop #{h.hop_number}"
                ))
        except Exception:
            hops = []
            from ..schemas.analysis import RouteStats
            route_stats = RouteStats()

        # 11-12. URL & Cryptocurrency Analysis
        try:
            url_analyzer = URLAnalyzer(plain_text, raw_html, headers_dict)
            urls, crypto_indicators = url_analyzer.analyze()
        except Exception:
            urls = []
            crypto_indicators = []

        # 13-14. Attachment Extraction & Hashing
        try:
            att_analyzer = AttachmentAnalyzer(raw_attachments)
            attachments = att_analyzer.analyze()
            for a in attachments:
                timeline.append(TimelineEvent(
                    timestamp=now_iso,
                    event_type="ATTACHMENT_PARSED",
                    title=f"Attachment Extracted: {a.filename}",
                    description=f"Computed SHA-256: {a.sha256[:16]}... ({a.size_bytes} bytes). Risk: {a.risk_level}",
                    source="MIME Attachment Parser"
                ))
        except Exception:
            attachments = []

        # 15. NLP Social Engineering & Intent Analysis
        try:
            nlp_analyzer = NLPAnalyzer(plain_text, metadata.get("subject", ""))
            nlp_analysis = nlp_analyzer.analyze()
        except Exception:
            from ..schemas.analysis import NLPAnalysis
            nlp_analysis = NLPAnalysis()

        # 16-17. Explainable Threat Scoring
        threat_scorer = ThreatScorer(
            auth=auth_summary,
            sender=sender_analysis,
            urls=urls,
            attachments=attachments,
            nlp=nlp_analysis,
            hops=hops
        )
        overall_score, severity, sub_scores, threat_factors, verdict = threat_scorer.calculate()

        # Final Timeline Event: Analysis Finished
        timeline.append(TimelineEvent(
            timestamp=now_iso,
            event_type="ANALYSIS_COMPLETED",
            title="Forensic Pipeline Complete",
            description=f"Calculated Threat Score: {overall_score} ({severity}). Generated {len(threat_factors)} threat factor indicators.",
            source="Pipeline Engine"
        ))

        # Origin IP and Country
        origin_ip = "Unknown"
        origin_country = "Unknown"
        if hops:
            origin_hop = hops[0]
            origin_ip = origin_hop.from_ip or origin_hop.by_ip or "Unknown"
            origin_country = origin_hop.country or "Unknown"

        summary = AnalysisSummary(
            investigation_id=investigation_id,
            subject=metadata.get("subject", "(No Subject)"),
            sender=metadata.get("from", ""),
            recipient=metadata.get("to", ""),
            date=metadata.get("date", now_iso),
            overall_threat_score=overall_score,
            threat_level=severity,
            header_trust_score=auth_summary.header_trust_score,
            verdict=verdict
        )

        full_result = FullAnalysisResult(
            success=True,
            summary=summary,
            sub_scores=sub_scores,
            authentication=auth_summary,
            sender_analysis=sender_analysis,
            routing_hops=hops,
            route_stats=route_stats,
            nlp_analysis=nlp_analysis,
            urls=urls,
            attachments=attachments,
            crypto_indicators=crypto_indicators,
            threat_factors=threat_factors,
            timeline=timeline,
            extracted_text_preview=plain_text[:1500] if plain_text else "",
            sanitized_html_preview=sanitized_html[:2500] if sanitized_html else "",
            raw={"headers": parsed_email["raw_headers_str"]}
        )

        # 19. Persist Investigation to Database if DB Session Provided
        if self.db is not None:
            try:
                db_data = {
                    "id": investigation_id,
                    "subject": summary.subject,
                    "sender": summary.sender,
                    "recipient": summary.recipient,
                    "email_date": summary.date,
                    "filename": self.filename,
                    "threat_score": overall_score,
                    "severity": severity,
                    "header_trust_score": auth_summary.header_trust_score,
                    "summary": verdict,
                    "source_ip": origin_ip,
                    "source_country": origin_country,
                    "spf_status": auth_summary.spf.status,
                    "dkim_status": auth_summary.dkim.status,
                    "dmarc_status": auth_summary.dmarc.status,
                    "status": "NEW",
                    "raw_headers": parsed_email["raw_headers_str"],
                    "analysis_json": full_result.model_dump(),
                    "notes": []
                }
                create_investigation(self.db, db_data)
            except Exception:
                pass  # Do not block response on database commit issue

        return full_result

    def _analyze_sender(self, metadata: Dict[str, Any]) -> SenderAnalysis:
        """Compares From, Reply-To, Return-Path, and Sender for deceptive patterns."""
        from_raw = metadata.get("from", "")
        reply_to_raw = metadata.get("reply_to", "")
        return_path_raw = metadata.get("return_path", "")
        sender_raw = metadata.get("sender", "")

        from_display, from_addr = parseaddr(from_raw)
        _, reply_to_addr = parseaddr(reply_to_raw)
        _, return_path_addr = parseaddr(return_path_raw)
        _, sender_addr = parseaddr(sender_raw)

        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""
        reply_to_domain = reply_to_addr.split("@")[-1].lower() if "@" in reply_to_addr else ""
        return_path_domain = return_path_addr.split("@")[-1].lower() if "@" in return_path_addr else ""

        # Mismatches
        from_reply_to_mismatch = bool(reply_to_domain and from_domain and (reply_to_domain != from_domain))
        from_return_path_mismatch = bool(return_path_domain and from_domain and (return_path_domain != from_domain))

        # Brand impersonation check in display name
        display_lower = from_display.lower()
        display_impersonation = False
        evidence_list = []

        for brand in BRAND_TARGETS:
            if brand in display_lower and brand not in from_domain:
                display_impersonation = True
                evidence_list.append(f"Display name references '{brand}' but domain is '{from_domain}'")
                break

        # Punycode check
        is_punycode = "xn--" in from_domain
        if is_punycode:
            evidence_list.append(f"Punycode encoded domain ({from_domain})")

        # Free provider check
        is_free = from_domain in FREE_EMAIL_PROVIDERS

        # Suspicious patterns
        suspicious_patterns = []
        if len(from_domain.split(".")) > 3:
            suspicious_patterns.append("Excessive subdomain hierarchy")
        if re.search(r"[0-9]{4,}", from_domain):
            suspicious_patterns.append("Heavy numeric sequences in domain name")

        if from_reply_to_mismatch:
            evidence_list.append(f"Reply-To domain '{reply_to_domain}' mismatches From domain '{from_domain}'")
        if from_return_path_mismatch:
            evidence_list.append(f"Return-Path domain '{return_path_domain}' mismatches From domain '{from_domain}'")

        risk_level = "SAFE"
        if display_impersonation or is_punycode or from_reply_to_mismatch:
            risk_level = "HIGH" if (display_impersonation and from_reply_to_mismatch) else "MEDIUM"

        return SenderAnalysis(
            from_header=from_raw,
            display_name=from_display,
            from_address=from_addr,
            from_domain=from_domain,
            reply_to=reply_to_addr,
            return_path=return_path_addr,
            sender=sender_addr,
            from_reply_to_mismatch=from_reply_to_mismatch,
            from_return_path_mismatch=from_return_path_mismatch,
            display_name_deception=display_impersonation,
            is_punycode=is_punycode,
            is_free_provider=is_free,
            suspicious_domain_patterns=suspicious_patterns,
            risk_level=risk_level,
            evidence=evidence_list
        )
