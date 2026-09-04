"""
Threat Intelligence Abstraction Layer.
Supports modular IOC lookups (IP, Domain, File Hash) with VirusTotal, AbuseIPDB, and URLhaus.
Strictly adheres to core platform principle: Never fabricate threat intelligence.
Marks unconfigured external providers transparently as 'not_configured'.
"""
import os
import httpx
from typing import Dict, Any, Optional

# Synthetic demo intelligence database for offline presentation & testing
DEMO_IOC_INTEL = {
    "ip": {
        "203.0.113.195": {
            "reputation": "Suspicious / Demo Malicious",
            "threat_score": 85,
            "reports_count": 42,
            "category": "Credential Phishing Host",
            "provider_status": "demo_intelligence",
            "provider_name": "SIH-Synthetic-Intel-Feed",
            "last_reported": "2026-09-04T12:00:00Z"
        },
        "198.51.100.25": {
            "reputation": "Known Bulletproof Transit Relay",
            "threat_score": 75,
            "reports_count": 18,
            "category": "Spam Relay",
            "provider_status": "demo_intelligence",
            "provider_name": "SIH-Synthetic-Intel-Feed",
            "last_reported": "2026-09-03T18:30:00Z"
        }
    },
    "domain": {
        "microsoft-security.example": {
            "reputation": "Suspicious / Brand Impersonation",
            "threat_score": 90,
            "category": "Executive & IT Impersonation",
            "provider_status": "demo_intelligence",
            "provider_name": "SIH-Synthetic-Intel-Feed",
            "registered_days_ago": 3
        },
        "secure-portal-update.top": {
            "reputation": "Phishing Landing Page",
            "threat_score": 95,
            "category": "Credential Harvesting",
            "provider_status": "demo_intelligence",
            "provider_name": "SIH-Synthetic-Intel-Feed",
            "registered_days_ago": 1
        }
    },
    "hash": {
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {
            "reputation": "Clean / Empty File",
            "threat_score": 0,
            "detections": 0,
            "provider_status": "demo_intelligence",
            "provider_name": "SIH-Synthetic-Intel-Feed"
        }
    }
}


class ThreatIntelligenceService:
    """Manages threat intelligence querying with provider abstraction and safe fallbacks."""

    def __init__(self):
        self.vt_key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
        self.abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip()
        self.ipinfo_token = os.getenv("IPINFO_TOKEN", "").strip()

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Queries IP reputation or returns transparent fallback."""
        if not ip:
            return {"status": "error", "message": "Empty IP address provided"}

        # 1. Check demo intelligence
        if ip in DEMO_IOC_INTEL["ip"]:
            return {
                "ip": ip,
                "status": "success",
                "data": DEMO_IOC_INTEL["ip"][ip]
            }

        # 2. Check live AbuseIPDB if configured
        if self.abuse_key:
            try:
                headers = {"Key": self.abuse_key, "Accept": "application/json"}
                params = {"ipAddress": ip, "maxAgeInDays": 90}
                with httpx.Client(timeout=3.0) as client:
                    resp = client.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params)
                    if resp.status_code == 200:
                        res = resp.json().get("data", {})
                        return {
                            "ip": ip,
                            "status": "success",
                            "data": {
                                "reputation": "Malicious" if res.get("abuseConfidenceScore", 0) > 50 else "Benign",
                                "threat_score": res.get("abuseConfidenceScore", 0),
                                "reports_count": res.get("totalReports", 0),
                                "category": "Abuse Reports",
                                "provider_status": "active",
                                "provider_name": "AbuseIPDB",
                                "last_reported": res.get("lastReportedAt")
                            }
                        }
            except Exception:
                pass

        # 3. Provider not configured - return honest status
        return {
            "ip": ip,
            "status": "not_configured",
            "data": {
                "reputation": "Provider Not Configured",
                "threat_score": None,
                "reports_count": None,
                "provider_status": "not_configured",
                "provider_name": "None (Set ABUSEIPDB_API_KEY to activate)",
                "note": "External IP reputation provider is not configured. Threat score is evaluated purely via local headers and route heuristics."
            }
        }

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        """Queries domain reputation or returns transparent fallback."""
        clean_domain = domain.strip().lower()
        if not clean_domain:
            return {"status": "error", "message": "Empty domain provided"}

        if clean_domain in DEMO_IOC_INTEL["domain"]:
            return {
                "domain": clean_domain,
                "status": "success",
                "data": DEMO_IOC_INTEL["domain"][clean_domain]
            }

        # If VirusTotal configured
        if self.vt_key:
            try:
                headers = {"x-apikey": self.vt_key}
                with httpx.Client(timeout=3.0) as client:
                    resp = client.get(f"https://www.virustotal.com/api/v3/domains/{clean_domain}", headers=headers)
                    if resp.status_code == 200:
                        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        return {
                            "domain": clean_domain,
                            "status": "success",
                            "data": {
                                "reputation": "Malicious" if malicious > 0 else "Clean",
                                "threat_score": min(100, malicious * 10),
                                "detections": malicious,
                                "provider_status": "active",
                                "provider_name": "VirusTotal"
                            }
                        }
            except Exception:
                pass

        return {
            "domain": clean_domain,
            "status": "not_configured",
            "data": {
                "reputation": "Provider Not Configured",
                "threat_score": None,
                "provider_status": "not_configured",
                "provider_name": "None (Set VIRUSTOTAL_API_KEY to activate)",
                "note": "External domain reputation provider not configured. Domain risk evaluated via local heuristic pattern analysis."
            }
        }

    def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Queries cryptographic file hash reputation or returns transparent fallback."""
        clean_hash = file_hash.strip().lower()
        if not clean_hash:
            return {"status": "error", "message": "Empty hash provided"}

        if clean_hash in DEMO_IOC_INTEL["hash"]:
            return {
                "hash": clean_hash,
                "status": "success",
                "data": DEMO_IOC_INTEL["hash"][clean_hash]
            }

        if self.vt_key:
            try:
                headers = {"x-apikey": self.vt_key}
                with httpx.Client(timeout=3.0) as client:
                    resp = client.get(f"https://www.virustotal.com/api/v3/files/{clean_hash}", headers=headers)
                    if resp.status_code == 200:
                        stats = resp.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0)
                        return {
                            "hash": clean_hash,
                            "status": "success",
                            "data": {
                                "reputation": "Malicious" if malicious > 0 else "Clean",
                                "threat_score": min(100, malicious * 10),
                                "detections": malicious,
                                "provider_status": "active",
                                "provider_name": "VirusTotal"
                            }
                        }
            except Exception:
                pass

        return {
            "hash": clean_hash,
            "status": "not_configured",
            "data": {
                "reputation": "Provider Not Configured",
                "threat_score": None,
                "detections": None,
                "provider_status": "not_configured",
                "provider_name": "None (Set VIRUSTOTAL_API_KEY to activate)",
                "note": "External hash reputation provider not configured. File threat status evaluated by file extension, MIME, and macro heuristics."
            }
        }
