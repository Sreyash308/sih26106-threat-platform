"""
Received Header Forensics and Geographic Route Tracer.
Extracts network hops from Received headers, reconstructs chronological transmission path,
classifies IP addresses, looks up geolocation with caching & fallback,
and calculates route statistics.
"""
import re
import httpx
from typing import List, Dict, Any, Optional, Tuple
from dateutil import parser as date_parser

from ..utils.helpers import classify_ip, calculate_haversine_distance, normalize_date
from ..schemas.analysis import RoutingHop, RouteStats

# In-memory session cache for geolocated IPs
_GEO_CACHE: Dict[str, Dict[str, Any]] = {}

# Demo coordinates for documentation / test IPs so the map can render demo cases gracefully
# with transparent labeling "Demo Intelligence / Synthetic Documentation Net"
DEMO_IP_GEO = {
    "192.0.2.1": {"country": "United States", "city": "Ashburn", "region": "Virginia", "lat": 39.0438, "lon": -77.4874, "isp": "Demo Relay Corp", "org": "AS16509 Amazon Demo", "asn": "AS16509"},
    "198.51.100.25": {"country": "Germany", "city": "Frankfurt", "region": "Hesse", "lat": 50.1109, "lon": 8.6821, "isp": "Demo Transit AG", "org": "AS24940 Hetzner Demo", "asn": "AS24940"},
    "203.0.113.195": {"country": "Russia", "city": "Moscow", "region": "Moscow", "lat": 55.7558, "lon": 37.6173, "isp": "Demo Cyber Relay", "org": "AS12345 Suspicious Host", "asn": "AS12345"},
    "203.0.113.50": {"country": "Netherlands", "city": "Amsterdam", "region": "North Holland", "lat": 52.3676, "lon": 4.9041, "isp": "Demo Bulletproof B.V.", "org": "AS99999 Demo Org", "asn": "AS99999"},
    "198.51.100.88": {"country": "United Kingdom", "city": "London", "region": "England", "lat": 51.5074, "lon": -0.1278, "isp": "Demo Corporate Exchange", "org": "AS2856 BT Demo", "asn": "AS2856"},
}


class GeoTracer:
    """Parses Received headers, reconstructs mail routing, and enriches with geolocation."""

    def __init__(self, headers_dict: Dict[str, List[str]]):
        self.received_headers = headers_dict.get("received", [])

    def trace(self) -> Tuple[List[RoutingHop], RouteStats]:
        """Performs full hop extraction, chronological reconstruction, and geo lookup."""
        if not self.received_headers:
            return [], RouteStats()

        raw_hops: List[Dict[str, Any]] = []

        # Parse every Received header
        for idx, header_text in enumerate(self.received_headers):
            hop_data = self._parse_single_received_header(header_text, idx)
            raw_hops.append(hop_data)

        # In email semantics, headers are appended to the top as the email traverses hops.
        # Earliest sending hop is at the bottom of the Received headers stack.
        # Reconstruct hop sequence from origin (first hop) to final recipient relay.
        reconstructed = list(reversed(raw_hops))

        # Assign hop numbers (Hop 1 = Origin relay, Hop N = Destination)
        final_hops: List[RoutingHop] = []
        for i, hop in enumerate(reconstructed):
            hop_num = i + 1
            ip_to_geo = hop["from_ip"] or hop["by_ip"]
            ip_info = classify_ip(ip_to_geo) if ip_to_geo else classify_ip("")

            geo_data = self._resolve_geolocation(ip_to_geo, ip_info)

            suspicious = False
            evidence_parts = []
            if ip_info["type"] == "documentation":
                evidence_parts.append("Synthetic documentation IP range (RFC 5737)")
            if hop["from_hostname"] and ("unknown" in hop["from_hostname"].lower() or "dynamic" in hop["from_hostname"].lower()):
                suspicious = True
                evidence_parts.append("Unverified or dynamic client hostname")

            evidence = "; ".join(evidence_parts) if evidence_parts else "Standard transmission relay"

            final_hops.append(RoutingHop(
                hop_number=hop_num,
                timestamp=hop["timestamp"],
                from_hostname=hop["from_hostname"],
                from_ip=hop["from_ip"],
                by_hostname=hop["by_hostname"],
                by_ip=hop["by_ip"],
                ip_classification=ip_info["type"],
                is_public=ip_info["is_public"],
                country=geo_data.get("country", "Unknown"),
                city=geo_data.get("city", "Unknown"),
                region=geo_data.get("region", "Unknown"),
                latitude=geo_data.get("lat"),
                longitude=geo_data.get("lon"),
                isp=geo_data.get("isp", "Unknown"),
                organization=geo_data.get("org", "Unknown"),
                asn=geo_data.get("asn", "Unknown"),
                ordering_confidence="High" if hop["timestamp"] else "Medium",
                suspicious=suspicious,
                evidence=evidence,
                provider_status=geo_data.get("provider_status", "local_heuristic")
            ))

        # Calculate Route Statistics
        route_stats = self._calculate_route_stats(final_hops)

        return final_hops, route_stats

    def _parse_single_received_header(self, text: str, index: int) -> Dict[str, Any]:
        """Extracts from, by, with, id, and timestamp using robust regex patterns."""
        clean_text = " ".join(text.split())

        # Timestamp is typically after the semicolon ';'
        timestamp_str = None
        if ";" in clean_text:
            parts = clean_text.rsplit(";", 1)
            time_candidate = parts[1].strip()
            timestamp_str = normalize_date(time_candidate)

        # Extract 'from' clause
        from_host = ""
        from_ip = ""
        from_match = re.search(r"\bfrom\s+([^\s\(\)]+)(?:\s+\((?:[^\)]*?\[)?([0-9a-fA-F\.:]+)(?:\])?[^\)]*?\))?", clean_text, re.IGNORECASE)
        if from_match:
            from_host = from_match.group(1).strip()
            from_ip = from_match.group(2).strip() if from_match.group(2) else ""

        # If from_ip was not captured by regex, search for standalone IP inside parens
        if not from_ip:
            ip_in_parens = re.search(r"\bfrom\s+[^;]*?\[([0-9a-fA-F\.:]+)\]", clean_text, re.IGNORECASE)
            if ip_in_parens:
                from_ip = ip_in_parens.group(1).strip()

        # Extract 'by' clause
        by_host = ""
        by_ip = ""
        by_match = re.search(r"\bby\s+([^\s\(\)]+)(?:\s+\((?:[^\)]*?\[)?([0-9a-fA-F\.:]+)(?:\])?[^\)]*?\))?", clean_text, re.IGNORECASE)
        if by_match:
            by_host = by_match.group(1).strip()
            by_ip = by_match.group(2).strip() if by_match.group(2) else ""

        return {
            "index": index,
            "raw": clean_text,
            "from_hostname": from_host,
            "from_ip": from_ip,
            "by_hostname": by_host,
            "by_ip": by_ip,
            "timestamp": timestamp_str
        }

    def _resolve_geolocation(self, ip: str, ip_info: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves IP geolocation via in-memory cache, demo synthetic database, or live provider."""
        if not ip or ip_info["type"] == "invalid":
            return {
                "country": "Unknown", "city": "Unknown", "region": "Unknown",
                "lat": None, "lon": None, "isp": "Unknown", "org": "Unknown",
                "asn": "Unknown", "provider_status": "unavailable"
            }

        # Check Cache
        if ip in _GEO_CACHE:
            return _GEO_CACHE[ip]

        # Check Demo synthetic documentation network addresses
        if ip in DEMO_IP_GEO:
            demo_res = {
                **DEMO_IP_GEO[ip],
                "provider_status": "demo_intelligence"
            }
            _GEO_CACHE[ip] = demo_res
            return demo_res

        # Private / Internal RFC 1918 or Loopback addresses
        if not ip_info["is_public"]:
            return {
                "country": "Private Network",
                "city": "Internal Relay",
                "region": "Localhost/LAN",
                "lat": None,
                "lon": None,
                "isp": "Local Infrastructure",
                "org": ip_info["description"],
                "asn": "Private RFC 1918",
                "provider_status": "local_classification"
            }

        # Public routable IP - Try lightweight HTTP geolocation provider (ip-api.com with 2s timeout)
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,as")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        result = {
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "region": data.get("regionName", "Unknown"),
                            "lat": data.get("lat"),
                            "lon": data.get("lon"),
                            "isp": data.get("isp", "Unknown"),
                            "org": data.get("org", "Unknown"),
                            "asn": data.get("as", "Unknown"),
                            "provider_status": "active"
                        }
                        _GEO_CACHE[ip] = result
                        return result
        except Exception:
            pass

        # Fallback if external provider is offline or rate-limited
        fallback_res = {
            "country": "Unknown",
            "city": "Unknown",
            "region": "Unknown",
            "lat": None,
            "lon": None,
            "isp": "Provider Unavailable",
            "org": "Provider Unavailable",
            "asn": "Unknown",
            "provider_status": "unavailable"
        }
        _GEO_CACHE[ip] = fallback_res
        return fallback_res

    def _calculate_route_stats(self, hops: List[RoutingHop]) -> RouteStats:
        """Computes transmission statistics across reconstructed hops."""
        total_hops = len(hops)
        public_hops = sum(1 for h in hops if h.is_public)
        countries = list(dict.fromkeys(h.country for h in hops if h.country and h.country not in ("Unknown", "Private Network")))
        asns = list(dict.fromkeys(h.asn for h in hops if h.asn and h.asn not in ("Unknown", "Private RFC 1918")))

        # Distance calculation
        coords = [(h.latitude, h.longitude) for h in hops if h.latitude is not None and h.longitude is not None]
        total_distance = 0.0
        longest_jump = 0.0

        for i in range(len(coords) - 1):
            lat1, lon1 = coords[i]
            lat2, lon2 = coords[i + 1]
            dist = calculate_haversine_distance(lat1, lon1, lat2, lon2)
            total_distance += dist
            if dist > longest_jump:
                longest_jump = dist

        return RouteStats(
            total_hops=total_hops,
            public_hops=public_hops,
            countries_traversed=countries,
            unique_asns=asns,
            approximate_distance_km=round(total_distance, 1),
            longest_jump_km=round(longest_jump, 1)
        )
