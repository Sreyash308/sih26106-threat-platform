"""
Authentication Analyzer: Forensically parses SPF, DKIM, and DMARC evidence
from Authentication-Results, Received-SPF, and DKIM-Signature headers.
Calculates a transparent Header Trust Score (0-100) strictly separate from Threat Score.
"""
import re
from typing import Dict, Any, List, Optional
from ..schemas.analysis import AuthenticationSummary, AuthResultItem


class AuthenticationAnalyzer:
    """Analyzes email authentication headers and calculates header trust metrics."""

    def __init__(self, headers_dict: Dict[str, List[str]]):
        self.headers = headers_dict

    def analyze(self) -> AuthenticationSummary:
        """Performs multi-header forensic parsing for SPF, DKIM, and DMARC."""
        auth_results_headers = self.headers.get("authentication-results", [])
        received_spf_headers = self.headers.get("received-spf", [])
        dkim_sig_headers = self.headers.get("dkim-signature", [])
        arc_auth_headers = self.headers.get("arc-authentication-results", [])

        # 1. SPF Analysis
        spf_item = self._parse_spf(auth_results_headers, received_spf_headers)

        # 2. DKIM Analysis
        dkim_item = self._parse_dkim(auth_results_headers, dkim_sig_headers)

        # 3. DMARC Analysis
        dmarc_item = self._parse_dmarc(auth_results_headers, arc_auth_headers)

        # 4. Header Trust Score Calculation
        trust_score, notes = self._calculate_header_trust(spf_item, dkim_item, dmarc_item)

        return AuthenticationSummary(
            spf=spf_item,
            dkim=dkim_item,
            dmarc=dmarc_item,
            header_trust_score=trust_score,
            evidence_notes=notes
        )

    def _parse_spf(self, auth_results: List[str], received_spf: List[str]) -> AuthResultItem:
        """Parses SPF authentication from Received-SPF and Authentication-Results."""
        combined_text = " ".join(auth_results + received_spf)

        if not combined_text.strip():
            return AuthResultItem(
                status="None",
                evidence="No SPF evaluation headers (Received-SPF or Authentication-Results) observed.",
                details={"raw_spf": None}
            )

        # Priority 1: Check Received-SPF headers
        for r_spf in received_spf:
            r_lower = r_spf.lower()
            match_client_ip = re.search(r"client-ip=([0-9a-fA-F\.:]+)", r_spf)
            match_mailfrom = re.search(r"envelope-from=<?([^\s>;]+)>?", r_spf) or re.search(r"identity=mailfrom;\s*domain=([^\s;]+)", r_spf)
            client_ip = match_client_ip.group(1) if match_client_ip else ""
            mailfrom = match_mailfrom.group(1) if match_mailfrom else ""

            if r_lower.startswith("pass") or " spf=pass " in f" {r_lower} " or r_lower.startswith("pass "):
                return AuthResultItem(
                    status="Pass",
                    evidence=f"SPF passed: Valid mail relay for envelope sender {mailfrom or 'domain'}.",
                    details={"client_ip": client_ip, "mailfrom": mailfrom, "header": r_spf}
                )
            elif "fail" in r_lower or "softfail" in r_lower or "permerror" in r_lower:
                status_type = "Softfail" if "softfail" in r_lower else ("Permerror" if "permerror" in r_lower else "Fail")
                return AuthResultItem(
                    status="Fail",
                    evidence=f"SPF {status_type}: Unauthorized sending IP {client_ip or 'unknown'} for sender {mailfrom or 'domain'}.",
                    details={"client_ip": client_ip, "mailfrom": mailfrom, "type": status_type, "header": r_spf}
                )
            elif "neutral" in r_lower:
                return AuthResultItem(
                    status="None",
                    evidence="SPF Neutral: Domain owner does not explicitly assert whether sending IP is authorized.",
                    details={"client_ip": client_ip, "header": r_spf}
                )
            elif "none" in r_lower:
                return AuthResultItem(
                    status="None",
                    evidence="SPF None: No SPF record published by sender domain.",
                    details={"client_ip": client_ip, "header": r_spf}
                )

        # Priority 2: Check Authentication-Results
        for ar in auth_results:
            ar_lower = ar.lower()
            spf_match = re.search(r"spf=([a-z]+)", ar_lower)
            if spf_match:
                res = spf_match.group(1)
                reason_match = re.search(r"reason=[\"\']?([^;\"\'\n]+)", ar)
                reason = reason_match.group(1).strip() if reason_match else ""
                
                if res == "pass":
                    return AuthResultItem(
                        status="Pass",
                        evidence="SPF pass reported in Authentication-Results header.",
                        details={"result": res, "reason": reason, "header": ar}
                    )
                elif res in ("fail", "softfail", "permerror"):
                    return AuthResultItem(
                        status="Fail",
                        evidence=f"SPF {res.upper()} reported in Authentication-Results: {reason or 'IP not in authorized SPF list'}.",
                        details={"result": res, "reason": reason, "header": ar}
                    )
                elif res in ("none", "neutral"):
                    return AuthResultItem(
                        status="None",
                        evidence=f"SPF {res} recorded: Sender domain has no definitive authorization policy.",
                        details={"result": res, "header": ar}
                    )

        return AuthResultItem(
            status="Unknown",
            evidence="SPF header information ambiguous or incomplete.",
            details={"raw": combined_text[:200]}
        )

    def _parse_dkim(self, auth_results: List[str], dkim_signatures: List[str]) -> AuthResultItem:
        """Parses DKIM signatures and verification headers."""
        has_signature = len(dkim_signatures) > 0
        sig_info = {}

        if has_signature:
            first_sig = dkim_signatures[0]
            d_match = re.search(r"\bd=([a-zA-Z0-9\.\-_]+)", first_sig)
            s_match = re.search(r"\bs=([a-zA-Z0-9\.\-_]+)", first_sig)
            a_match = re.search(r"\ba=([a-zA-Z0-9\-_]+)", first_sig)
            c_match = re.search(r"\bc=([a-zA-Z0-9\-_/]+)", first_sig)

            sig_info = {
                "domain": d_match.group(1) if d_match else "unknown",
                "selector": s_match.group(1) if s_match else "unknown",
                "algorithm": a_match.group(1) if a_match else "unknown",
                "canonicalization": c_match.group(1) if c_match else "unknown",
            }

        # Check Authentication-Results for receiving server's verdict
        for ar in auth_results:
            ar_lower = ar.lower()
            dkim_match = re.search(r"dkim=([a-z]+)", ar_lower)
            if dkim_match:
                res = dkim_match.group(1)
                header_domain_match = re.search(r"header\.d=([a-zA-Z0-9\.\-_]+)", ar_lower)
                hdr_domain = header_domain_match.group(1) if header_domain_match else sig_info.get("domain", "")

                if res == "pass":
                    return AuthResultItem(
                        status="Pass",
                        evidence=f"DKIM Signature Observed & Evaluated as PASS for domain '{hdr_domain}'.",
                        details={**sig_info, "evaluated_domain": hdr_domain, "verification_note": "Signature Observed"}
                    )
                elif res in ("fail", "permerror", "temperror"):
                    return AuthResultItem(
                        status="Fail",
                        evidence=f"DKIM Signature evaluated as {res.upper()} for domain '{hdr_domain}'. Signature verification failed or body was altered.",
                        details={**sig_info, "evaluated_domain": hdr_domain, "verification_note": "Signature Failed"}
                    )
                elif res == "none":
                    return AuthResultItem(
                        status="None",
                        evidence="DKIM evaluation reported as None (No valid signature).",
                        details=sig_info
                    )

        if has_signature:
            return AuthResultItem(
                status="Unknown",
                evidence=f"DKIM-Signature observed (d={sig_info.get('domain')}, s={sig_info.get('selector')}), but no receiving mail gateway verification result recorded in headers.",
                details={**sig_info, "verification_note": "Signature Observed — Verification Not Performed"}
            )

        return AuthResultItem(
            status="None",
            evidence="No DKIM-Signature header present in the email.",
            details={"verification_note": "Verification Not Performed"}
        )

    def _parse_dmarc(self, auth_results: List[str], arc_results: List[str]) -> AuthResultItem:
        """Parses DMARC alignment and policy results."""
        combined = " ".join(auth_results + arc_results)

        if not combined.strip():
            return AuthResultItem(
                status="None",
                evidence="No DMARC evaluation headers detected.",
                details={}
            )

        for ar in auth_results + arc_results:
            ar_lower = ar.lower()
            dmarc_match = re.search(r"dmarc=([a-z]+)", ar_lower)
            if dmarc_match:
                res = dmarc_match.group(1)
                from_domain_match = re.search(r"header\.from=([a-zA-Z0-9\.\-_]+)", ar_lower)
                action_match = re.search(r"action=([a-zA-Z0-9\.\-_]+)", ar_lower)
                policy_match = re.search(r"p=([a-z]+)", ar_lower)

                details = {
                    "header_from": from_domain_match.group(1) if from_domain_match else "",
                    "action": action_match.group(1) if action_match else "none",
                    "policy": policy_match.group(1) if policy_match else "unspecified"
                }

                if res == "pass":
                    return AuthResultItem(
                        status="Pass",
                        evidence=f"DMARC evaluation: PASS for header.from '{details['header_from']}'. Alignment verified with SPF/DKIM.",
                        details=details
                    )
                elif res in ("fail", "reject", "quarantine"):
                    return AuthResultItem(
                        status="Fail",
                        evidence=f"DMARC evaluation: FAIL for header.from '{details['header_from']}'. Alignment failed with both SPF and DKIM.",
                        details=details
                    )
                elif res == "none":
                    return AuthResultItem(
                        status="None",
                        evidence=f"DMARC evaluation: None for domain '{details['header_from']}'. No DMARC policy published.",
                        details=details
                    )

        return AuthResultItem(
            status="Unknown",
            evidence="No explicit DMARC evaluation entry found in Authentication-Results.",
            details={}
        )

    def _calculate_header_trust(
        self, spf: AuthResultItem, dkim: AuthResultItem, dmarc: AuthResultItem
    ) -> (int, List[str]):
        """
        Calculates Header Trust Score from 0 to 100.
        Higher score = high authenticity / trustworthy headers.
        Lower score = severe authentication failures / spoofing signals.
        """
        score = 100
        notes = []

        # SPF penalties
        if spf.status == "Fail":
            score -= 30
            notes.append("SPF failed (-30 trust)")
        elif spf.status == "None":
            score -= 10
            notes.append("No SPF policy (-10 trust)")
        elif spf.status == "Unknown":
            score -= 5

        # DKIM penalties
        if dkim.status == "Fail":
            score -= 30
            notes.append("DKIM verification failed (-30 trust)")
        elif dkim.status == "None":
            score -= 15
            notes.append("No DKIM signature (-15 trust)")
        elif dkim.status == "Unknown":
            score -= 5

        # DMARC penalties
        if dmarc.status == "Fail":
            score -= 35
            notes.append("DMARC alignment failed (-35 trust)")
        elif dmarc.status == "None":
            score -= 10
            notes.append("No DMARC policy (-10 trust)")

        # Cap boundaries
        trust_score = max(0, min(100, score))
        return trust_score, notes
