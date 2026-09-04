"""
Forensic URL and Cryptocurrency Analyzer.
Extracts URLs from plain text, HTML, and headers without visiting remote endpoints (SSRF prevention).
Applies cybersecurity heuristics for credential phishing, deceptive anchors, IP-hosts, and crypto indicators.
"""
import re
from urllib.parse import urlparse, parse_qs, unquote
from typing import List, Dict, Any, Tuple
from bs4 import BeautifulSoup

from ..schemas.analysis import URLItem, CryptoIndicator

# Suspicious TLDs frequently abused in rapid-fire phishing campaigns
SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "click", "country", "gq", "cf", "ml", "tk",
    "ga", "club", "vip", "icu", "cam", "fit", "buzz", "rest", "stream", "download"
}

# Known public URL shortening domains
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", "goo.gl",
    "cutt.ly", "shorturl.at", "rb.gy", "rebrand.ly", "v.gd", "qr.ae"
}

# High-risk phishing and social engineering keyword triggers in URLs
CREDENTIAL_KEYWORDS = [
    "login", "signin", "sign-in", "log-in", "verify", "verification", "secure",
    "security", "account", "suspended", "password", "credential", "update",
    "banking", "wallet", "invoice", "payment", "confirm", "recovery", "auth",
    "session", "token", "unlock", "validation", "support", "billing", "re-activate"
]

# Regex for IPv4 in hostname
IPV4_REGEX = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

# Cryptocurrency regex patterns
BTC_REGEX = re.compile(r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{25,90})\b")
ETH_REGEX = re.compile(r"\b(0x[a-fA-F0-9]{40})\b")


class URLAnalyzer:
    """Performs deep forensic inspection of URLs and crypto indicators."""

    def __init__(self, plain_text: str, raw_html: str, headers_dict: Dict[str, List[str]]):
        self.plain_text = plain_text or ""
        self.raw_html = raw_html or ""
        self.headers = headers_dict

    def analyze(self) -> Tuple[List[URLItem], List[CryptoIndicator]]:
        """Extracts and analyzes all URLs and cryptocurrency addresses."""
        raw_urls_with_context: List[Dict[str, str]] = []

        # 1. Extract from HTML <a> tags (preserving anchor text for deception analysis)
        if self.raw_html:
            try:
                soup = BeautifulSoup(self.raw_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    display_text = a_tag.get_text().strip()
                    if href.startswith(("http://", "https://", "ftp://", "www.")):
                        raw_urls_with_context.append({
                            "url": href if not href.startswith("www.") else f"http://{href}",
                            "display_text": display_text,
                            "source": "HTML Link"
                        })
            except Exception:
                pass

        # 2. Extract URLs from plain text and raw HTML using robust regex
        url_pattern = re.compile(r"https?://[^\s<>\"'{}|\\^`\[\]]+", re.IGNORECASE)
        combined_text = f"{self.plain_text}\n{self.raw_html}"
        for match in url_pattern.finditer(combined_text):
            found_url = match.group(0).rstrip(".,;:!?)>")
            raw_urls_with_context.append({
                "url": found_url,
                "display_text": found_url,
                "source": "Text/Body Stream"
            })

        # Deduplicate URLs while preserving anchor text
        seen = set()
        unique_urls: List[Dict[str, str]] = []
        for item in raw_urls_with_context:
            norm = item["url"].lower()
            if norm not in seen:
                seen.add(norm)
                unique_urls.append(item)

        # 3. Analyze each extracted URL
        analyzed_urls: List[URLItem] = []
        for u in unique_urls:
            analyzed_urls.append(self._inspect_url(u["url"], u["display_text"]))

        # 4. Detect Cryptocurrency indicators in text & HTML
        crypto_indicators = self._detect_cryptocurrency(self.plain_text + " " + self.raw_html)

        return analyzed_urls, crypto_indicators

    def _inspect_url(self, full_url: str, display_text: str) -> URLItem:
        """Heuristically inspects a single URL without making network requests."""
        try:
            parsed = urlparse(full_url)
        except Exception:
            return URLItem(
                full_url=full_url,
                risk=50,
                risk_level="MEDIUM",
                reason="Malformed or unparseable URL structure",
                evidence=["Failed standard URI parsing"]
            )

        scheme = parsed.scheme.lower()
        hostname = (parsed.hostname or "").lower()
        port = parsed.port
        path = parsed.path
        query = parsed.query

        risk_score = 0
        evidence_list: List[str] = []

        # Check Scheme
        if scheme == "http":
            risk_score += 15
            evidence_list.append("Unencrypted HTTP protocol in link destination")

        # Check IP-based Hostname
        is_ip_based = bool(IPV4_REGEX.match(hostname))
        if is_ip_based:
            risk_score += 35
            evidence_list.append(f"Direct IP-based URL detected ({hostname}) — typical malware/phishing evasion")

        # Check URL Shortener
        is_shortener = hostname in URL_SHORTENERS
        if is_shortener:
            risk_score += 20
            evidence_list.append(f"URL shortener service ({hostname}) disguises true destination")

        # Check Punycode / Internationalized Domain Name (IDN)
        is_punycode = "xn--" in hostname
        if is_punycode:
            risk_score += 30
            evidence_list.append("Punycode (xn--) domain detected — potential homograph/lookalike attack")

        # Check Suspicious TLD
        tld = hostname.split(".")[-1] if "." in hostname else ""
        if tld in SUSPICIOUS_TLDS:
            risk_score += 20
            evidence_list.append(f"Domain registered under high-abuse TLD (.{tld})")

        # Check Excessive Subdomains
        subdomain_parts = hostname.split(".")
        if len(subdomain_parts) >= 4:
            risk_score += 15
            evidence_list.append(f"Excessive subdomains ({len(subdomain_parts) - 2} levels) detected")

        # Check Credential & Phishing Keywords in Hostname or Path
        full_lower = full_url.lower()
        matched_keywords = [kw for kw in CREDENTIAL_KEYWORDS if kw in full_lower]
        if matched_keywords:
            risk_score += min(30, len(matched_keywords) * 10)
            evidence_list.append(f"Phishing/credential keywords found in URL: {', '.join(matched_keywords[:4])}")

        # Check Anchor Text Mismatch (Deceptive Hyperlink)
        anchor_mismatch = False
        if display_text and ("http://" in display_text.lower() or "https://" in display_text.lower() or "www." in display_text.lower()):
            clean_display = display_text.lower().replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
            if clean_display and clean_display not in hostname and hostname not in clean_display:
                anchor_mismatch = True
                risk_score += 40
                evidence_list.append(f"Anchor text deception: Display text references '{display_text[:35]}' but points to '{hostname}'")

        # Check Redirect Parameters in Query
        if query:
            qs = parse_qs(query)
            for param in ["redirect", "url", "next", "goto", "target", "link"]:
                if param in qs:
                    risk_score += 15
                    evidence_list.append(f"Open redirect parameter '{param}' detected in query string")
                    break

        # Calculate final risk level
        final_risk = min(100, risk_score)
        if final_risk >= 80:
            level = "CRITICAL"
        elif final_risk >= 60:
            level = "HIGH"
        elif final_risk >= 40:
            level = "MEDIUM"
        elif final_risk >= 20:
            level = "LOW"
        else:
            level = "SAFE"

        reason = "; ".join(evidence_list) if evidence_list else "No suspicious indicators detected"

        return URLItem(
            full_url=full_url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            path=path,
            query=query,
            display_text=display_text or full_url,
            risk=final_risk,
            risk_level=level,
            reason=reason,
            evidence=evidence_list,
            is_ip_based=is_ip_based,
            is_shortener=is_shortener,
            is_punycode=is_punycode,
            anchor_mismatch=anchor_mismatch
        )

    def _detect_cryptocurrency(self, content: str) -> List[CryptoIndicator]:
        """Scans email content for Bitcoin and Ethereum payment addresses."""
        indicators: List[CryptoIndicator] = []

        # Bitcoin matches
        for btc in set(BTC_REGEX.findall(content)):
            # Context snippet
            pos = content.find(btc)
            start = max(0, pos - 40)
            end = min(len(content), pos + len(btc) + 40)
            context = "..." + content[start:end].replace("\n", " ").strip() + "..."
            indicators.append(CryptoIndicator(
                currency="Bitcoin (BTC)",
                address=btc,
                context=context
            ))

        # Ethereum matches
        for eth in set(ETH_REGEX.findall(content)):
            pos = content.find(eth)
            start = max(0, pos - 40)
            end = min(len(content), pos + len(eth) + 40)
            context = "..." + content[start:end].replace("\n", " ").strip() + "..."
            indicators.append(CryptoIndicator(
                currency="Ethereum (ETH)",
                address=eth,
                context=context
            ))

        return indicators
