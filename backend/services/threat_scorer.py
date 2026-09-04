"""
Transparent Explainable Threat Scoring Engine.
Calculates an overall threat score (0-100), severity tier (SAFE, LOW, MEDIUM, HIGH, CRITICAL),
sub-scores across 6 forensic categories, and itemized explainable threat factors.
"""
import re
from typing import List, Dict, Any, Tuple
from ..schemas.analysis import (
    ThreatFactor,
    SubScores,
    AuthenticationSummary,
    SenderAnalysis,
    URLItem,
    AttachmentItem,
    NLPAnalysis,
    RoutingHop,
)


class ThreatScorer:
    """Computes transparent, evidence-based cybersecurity threat scores."""

    def __init__(
        self,
        auth: AuthenticationSummary,
        sender: SenderAnalysis,
        urls: List[URLItem],
        attachments: List[AttachmentItem],
        nlp: NLPAnalysis,
        hops: List[RoutingHop]
    ):
        self.auth = auth
        self.sender = sender
        self.urls = urls
        self.attachments = attachments
        self.nlp = nlp
        self.hops = hops

    def calculate(self) -> Tuple[int, str, SubScores, List[ThreatFactor], str]:
        """Calculates overall score, severity, sub-scores, and factor list."""
        factors: List[ThreatFactor] = []

        # 1. Authentication Signals
        auth_points = 0
        if self.auth.spf.status == "Fail":
            points = 15
            auth_points += points
            factors.append(ThreatFactor(
                factor="SPF Authentication Failure",
                points=points,
                category="Authentication",
                description="Sending IP address is not authorized in sender domain's SPF record.",
                evidence=self.auth.spf.evidence
            ))

        if self.auth.dkim.status == "Fail":
            points = 15
            auth_points += points
            factors.append(ThreatFactor(
                factor="DKIM Signature Verification Failed",
                points=points,
                category="Authentication",
                description="Cryptographic signature invalid or email body tampered in transit.",
                evidence=self.auth.dkim.evidence
            ))

        if self.auth.dmarc.status == "Fail":
            points = 20
            auth_points += points
            factors.append(ThreatFactor(
                factor="DMARC Policy Alignment Failure",
                points=points,
                category="Authentication",
                description="Email failed domain alignment with published DMARC policy.",
                evidence=self.auth.dmarc.evidence
            ))

        # 2. Sender Analysis Signals
        sender_points = 0
        if self.sender.from_reply_to_mismatch:
            points = 10
            sender_points += points
            factors.append(ThreatFactor(
                factor="Reply-To Header Mismatch",
                points=points,
                category="Sender",
                description="Replies routed to a different domain than sender.",
                evidence=f"From: {self.sender.from_address} vs Reply-To: {self.sender.reply_to}"
            ))

        if self.sender.from_return_path_mismatch:
            points = 8
            sender_points += points
            factors.append(ThreatFactor(
                factor="Return-Path Domain Mismatch",
                points=points,
                category="Sender",
                description="Envelope return address differs from display From address.",
                evidence=f"From: {self.sender.from_address} vs Return-Path: {self.sender.return_path}"
            ))

        if self.sender.display_name_deception:
            points = 12
            sender_points += points
            factors.append(ThreatFactor(
                factor="Display Name Impersonation",
                points=points,
                category="Sender",
                description="Display name mimics recognized brand while address uses unrelated domain.",
                evidence=f"'{self.sender.display_name}' sent from <{self.sender.from_address}>"
            ))

        if self.sender.is_punycode:
            points = 10
            sender_points += points
            factors.append(ThreatFactor(
                factor="Punycode / Homograph Domain",
                points=points,
                category="Sender",
                description="Domain uses ASCII-compatible encoding (xn--) to mimic authentic characters.",
                evidence=self.sender.from_domain
            ))

        # 3. URL Signals
        url_points = 0
        suspicious_urls = [u for u in self.urls if u.risk >= 40]
        ip_urls = [u for u in self.urls if u.is_ip_based]
        anchor_mismatches = [u for u in self.urls if u.anchor_mismatch]

        if suspicious_urls:
            points = 15
            url_points += points
            factors.append(ThreatFactor(
                factor=f"Suspicious URLs Detected ({len(suspicious_urls)})",
                points=points,
                category="URL",
                description="Links exhibit credential-harvesting parameters or malicious TLDs.",
                evidence=f"Highest risk link: {suspicious_urls[0].full_url[:60]}... ({suspicious_urls[0].reason})"
            ))

        if anchor_mismatches:
            points = 15
            url_points += points
            factors.append(ThreatFactor(
                factor="Deceptive Hyperlink Anchor Mismatch",
                points=points,
                category="URL",
                description="Visible link text displays legitimate brand URL while link routes elsewhere.",
                evidence=anchor_mismatches[0].reason
            ))

        if ip_urls:
            points = 10
            url_points += points
            factors.append(ThreatFactor(
                factor="Direct IP Address Link",
                points=points,
                category="URL",
                description="URL points directly to raw IP address instead of domain hostname.",
                evidence=ip_urls[0].full_url[:60]
            ))

        # 4. Attachment Signals
        attachment_points = 0
        for att in self.attachments:
            if att.dangerous_executable:
                points = 25
                attachment_points += points
                factors.append(ThreatFactor(
                    factor=f"Dangerous Executable Attachment ({att.extension})",
                    points=points,
                    category="Attachment",
                    description="Email contains executable binary or script capable of host compromise.",
                    evidence=f"{att.filename} (SHA-256: {att.sha256[:16]}...)"
                ))
            if att.double_extension:
                points = 20
                attachment_points += points
                factors.append(ThreatFactor(
                    factor="Deceptive Double Extension",
                    points=points,
                    category="Attachment",
                    description="Attachment disguises executable payload behind common document extension.",
                    evidence=att.filename
                ))
            if att.macro_enabled:
                points = 20
                attachment_points += points
                factors.append(ThreatFactor(
                    factor="Macro-Enabled Document Attached",
                    points=points,
                    category="Attachment",
                    description="Office document contains embedded macros/VBA code.",
                    evidence=att.filename
                ))

        # 5. NLP & Content Signals
        nlp_points = 0
        if "Credential Harvesting" in self.nlp.categories:
            points = 20
            nlp_points += points
            factors.append(ThreatFactor(
                factor="Credential Harvesting Content Detected",
                points=points,
                category="Content",
                description="Text prompts victim to re-authenticate, verify password, or unlock account.",
                evidence="; ".join(self.nlp.evidence_sentences[:2]) if self.nlp.evidence_sentences else "Credential keywords detected"
            ))

        if "Financial Fraud" in self.nlp.categories:
            points = 20
            nlp_points += points
            factors.append(ThreatFactor(
                factor="Financial / Invoice Fraud Indicators",
                points=points,
                category="Content",
                description="Language requests wire transfers, altered banking coordinates, or urgent invoice payments.",
                evidence="; ".join(self.nlp.evidence_sentences[:2]) if self.nlp.evidence_sentences else "Financial fraud language"
            ))

        if "Executive Impersonation" in self.nlp.categories:
            points = 15
            nlp_points += points
            factors.append(ThreatFactor(
                factor="Executive Impersonation / BEC Language",
                points=points,
                category="Content",
                description="Simulates internal confidential request from executive/CEO requiring discrete action.",
                evidence="; ".join(self.nlp.evidence_sentences[:2]) if self.nlp.evidence_sentences else "Impersonation patterns"
            ))

        if "Urgent Action" in self.nlp.categories and ("Credential Harvesting" not in self.nlp.categories):
            points = 8
            nlp_points += points
            factors.append(ThreatFactor(
                factor="Artificial Urgency & Coercion",
                points=points,
                category="Content",
                description="High-pressure time limit designed to bypass victim's scrutiny.",
                evidence=", ".join(self.nlp.suspicious_keywords[:4])
            ))

        # 6. Infrastructure Signals
        infra_points = 0
        suspicious_hops = [h for h in self.hops if h.suspicious]
        if suspicious_hops:
            points = 15
            infra_points += points
            factors.append(ThreatFactor(
                factor="Suspicious Infrastructure Relay Observed",
                points=points,
                category="Infrastructure",
                description="Email passed through dynamic client or untrusted relay host.",
                evidence=f"Hop #{suspicious_hops[0].hop_number}: {suspicious_hops[0].from_hostname or suspicious_hops[0].from_ip}"
            ))

        # Calculate Total Overall Threat Score (Capped at 100)
        total_raw_points = sum(f.points for f in factors)
        overall_score = min(100, max(0, total_raw_points))

        # Sub-scores (0-100 each)
        sub_scores = SubScores(
            authentication_risk=min(100, auth_points * 2),
            sender_risk=min(100, sender_points * 3),
            url_risk=min(100, url_points * 2),
            attachment_risk=min(100, attachment_points * 2),
            content_nlp_risk=min(100, int(self.nlp.phishing_probability * 100)),
            infrastructure_risk=min(100, infra_points * 4),
            overall_threat_score=overall_score
        )

        # Map Severity
        if overall_score >= 80:
            severity = "CRITICAL"
            verdict = "Critical Threat: Immediate quarantine and analyst response required."
        elif overall_score >= 60:
            severity = "HIGH"
            verdict = "High Risk: Probable targeted social engineering or malware campaign."
        elif overall_score >= 40:
            severity = "MEDIUM"
            verdict = "Medium Risk: Suspicious indicators present — manual analyst triage recommended."
        elif overall_score >= 20:
            severity = "LOW"
            verdict = "Low Risk: Minor authentication or formatting anomalies observed."
        else:
            severity = "SAFE"
            verdict = "Safe: Authentication passed and no malicious indicators detected."

        return overall_score, severity, sub_scores, factors, verdict
